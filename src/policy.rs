use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{ProxyError, ProxyResult};

/// Upper bound the Integration API itself enforces on `timeLimitMinutes`.
const UNIFI_MAX_TIME_LIMIT_MINUTES: u64 = 1_000_000;

/// The voucher-creation body, as a closed set of fields.
///
/// Client JSON is parsed into this struct and re-serialised before it goes
/// upstream — the proxy never forwards bytes it did not understand. Combined
/// with `deny_unknown_fields`, that means a client cannot smuggle an extra
/// property past the proxy in the hope that the controller honours it.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateVoucherRequest {
    pub name: String,
    #[serde(default = "one")]
    pub count: u32,
    pub time_limit_minutes: u64,
    #[serde(default = "one")]
    pub authorized_guest_limit: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_usage_limit_m_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_rate_limit_kbps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_rate_limit_kbps: Option<u64>,
}

fn one() -> u32 {
    1
}

/// The ceilings that apply to one particular caller.
#[derive(Debug, Clone, Copy)]
pub struct Ceilings {
    pub max_vouchers: u32,
    pub max_validity_minutes: u64,
}

impl CreateVoucherRequest {
    pub fn parse(body: &Value) -> ProxyResult<Self> {
        serde_json::from_value(body.clone())
            .map_err(|e| ProxyError::BadRequest(format!("voucher request is not acceptable: {e}")))
    }

    /// Rejects anything past the caller's ceilings.
    ///
    /// Over-limit requests are refused rather than silently clamped: a client
    /// that asked for 50 vouchers and got 10 without being told would be a
    /// worse experience than a clear error, and quietly changing what a caller
    /// asked for is a bad habit for a security component.
    pub fn enforce(&self, c: Ceilings) -> ProxyResult<()> {
        if self.name.trim().is_empty() {
            return Err(ProxyError::BadRequest(
                "voucher name must not be empty".into(),
            ));
        }
        if self.name.chars().count() > 128 {
            return Err(ProxyError::BadRequest("voucher name is too long".into()));
        }
        if self.count == 0 {
            return Err(ProxyError::BadRequest("count must be at least 1".into()));
        }
        if self.count > c.max_vouchers {
            return Err(ProxyError::Forbidden(format!(
                "this token may create at most {} voucher(s) per request (asked for {})",
                c.max_vouchers, self.count
            )));
        }
        if self.time_limit_minutes == 0 {
            return Err(ProxyError::BadRequest(
                "timeLimitMinutes must be at least 1".into(),
            ));
        }
        let ceiling = c.max_validity_minutes.min(UNIFI_MAX_TIME_LIMIT_MINUTES);
        if self.time_limit_minutes > ceiling {
            return Err(ProxyError::Forbidden(format!(
                "this token may issue vouchers valid for at most {} minute(s) (asked for {})",
                ceiling, self.time_limit_minutes
            )));
        }
        if self.authorized_guest_limit == 0 || self.authorized_guest_limit > 10_000 {
            return Err(ProxyError::BadRequest(
                "authorizedGuestLimit is out of range".into(),
            ));
        }
        Ok(())
    }

    pub fn to_upstream_body(&self) -> ProxyResult<Value> {
        serde_json::to_value(self)
            .map_err(|e| ProxyError::Internal(anyhow::anyhow!("failed to re-encode body: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ceilings() -> Ceilings {
        Ceilings {
            max_vouchers: 10,
            max_validity_minutes: 1440,
        }
    }

    fn valid() -> Value {
        json!({"name": "Guest", "count": 2, "timeLimitMinutes": 480, "authorizedGuestLimit": 1})
    }

    #[test]
    fn accepts_a_normal_request() {
        let req = CreateVoucherRequest::parse(&valid()).unwrap();
        req.enforce(ceilings()).unwrap();
        let body = req.to_upstream_body().unwrap();
        assert_eq!(body["name"], "Guest");
        assert_eq!(body["count"], 2);
        assert_eq!(body["timeLimitMinutes"], 480);
        // Absent optionals stay absent rather than becoming null.
        assert!(body.get("rxRateLimitKbps").is_none());
    }

    #[test]
    fn rejects_unknown_fields() {
        let mut body = valid();
        body["somethingElse"] = json!("nope");
        assert!(CreateVoucherRequest::parse(&body).is_err());
    }

    #[test]
    fn enforces_the_count_ceiling() {
        let mut body = valid();
        body["count"] = json!(50);
        let err = CreateVoucherRequest::parse(&body)
            .unwrap()
            .enforce(ceilings())
            .unwrap_err();
        assert_eq!(err.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn enforces_the_validity_ceiling() {
        let mut body = valid();
        body["timeLimitMinutes"] = json!(100_000);
        assert!(CreateVoucherRequest::parse(&body)
            .unwrap()
            .enforce(ceilings())
            .is_err());
    }

    #[test]
    fn rejects_an_overlong_name() {
        let mut body = valid();
        body["name"] = json!("x".repeat(200));
        assert!(CreateVoucherRequest::parse(&body)
            .unwrap()
            .enforce(ceilings())
            .is_err());
    }

    #[test]
    fn caps_validity_at_the_api_maximum_even_when_configured_higher() {
        // A generous config must not let a client ask for something the
        // controller will reject with an opaque 400.
        let generous = Ceilings {
            max_vouchers: 10,
            max_validity_minutes: u64::MAX,
        };
        let mut body = valid();
        body["timeLimitMinutes"] = json!(2_000_000u64);
        let err = CreateVoucherRequest::parse(&body)
            .unwrap()
            .enforce(generous)
            .unwrap_err();
        assert!(err.to_string().contains("1000000"), "{err}");
    }

    #[test]
    fn carries_optional_rate_limits_through() {
        let body = json!({
            "name": "Guest", "count": 1, "timeLimitMinutes": 60,
            "dataUsageLimitMBytes": 500, "rxRateLimitKbps": 1000, "txRateLimitKbps": 2000
        });
        let req = CreateVoucherRequest::parse(&body).unwrap();
        req.enforce(ceilings()).unwrap();
        let out = req.to_upstream_body().unwrap();
        assert_eq!(out["dataUsageLimitMBytes"], 500);
        assert_eq!(out["rxRateLimitKbps"], 1000);
        assert_eq!(out["txRateLimitKbps"], 2000);
    }

    #[test]
    fn rejects_an_absurd_guest_limit() {
        let mut body = valid();
        body["authorizedGuestLimit"] = json!(999_999);
        assert!(CreateVoucherRequest::parse(&body)
            .unwrap()
            .enforce(ceilings())
            .is_err());
    }

    #[test]
    fn rejects_degenerate_values() {
        for (field, value) in [
            ("count", json!(0)),
            ("timeLimitMinutes", json!(0)),
            ("authorizedGuestLimit", json!(0)),
            ("name", json!("   ")),
        ] {
            let mut body = valid();
            body[field] = value;
            assert!(
                CreateVoucherRequest::parse(&body)
                    .unwrap()
                    .enforce(ceilings())
                    .is_err(),
                "{field} should have been rejected"
            );
        }
    }
}
