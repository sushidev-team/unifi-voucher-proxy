//! Typed views over the controller's JSON.
//!
//! The Integration API is not consistent across firmware revisions — ids arrive
//! as `id` or `_id`, names as `name`, `desc` or `internalReference`, and usage
//! counters are absent entirely on some tiers. Parsing is therefore forgiving:
//! every optional field stays optional rather than failing a whole response.
//!
//! Timestamps are carried as the strings the controller sent (ISO-8601). They
//! are deliberately not parsed into a date type: the formats vary by firmware
//! and re-encoding them would risk changing what a client sees.

use async_graphql::SimpleObject;
use serde_json::Value;

/// A UniFi site.
#[derive(Debug, Clone, SimpleObject)]
pub struct Site {
    /// Site id, as used in every other call.
    pub id: String,
    /// Human-readable name.
    pub name: String,
}

/// A hotspot voucher.
#[derive(Debug, Clone, SimpleObject)]
pub struct Voucher {
    pub id: String,
    /// The 10-digit code a guest types in.
    pub code: String,
    pub name: Option<String>,
    /// How long the voucher is valid once redeemed.
    pub time_limit_minutes: Option<i64>,
    /// How many devices may share it.
    pub authorized_guest_limit: Option<i64>,
    /// How many have used it so far. Absent when the controller does not report it.
    pub authorized_guest_count: Option<i64>,
    pub expired: bool,
    /// ISO-8601, as sent by the controller.
    pub expires_at: Option<String>,
    /// ISO-8601, as sent by the controller.
    pub created_at: Option<String>,
    pub data_usage_limit_m_bytes: Option<i64>,
    pub rx_rate_limit_kbps: Option<i64>,
    pub tx_rate_limit_kbps: Option<i64>,
}

fn as_str(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

fn as_int(v: Option<&Value>) -> Option<i64> {
    match v {
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::String(s)) => s.parse().ok(),
        _ => None,
    }
}

/// Pulls the list out of an upstream envelope. Paged reads use `data`, but
/// `POST /hotspot/vouchers` answers `{"vouchers": [...]}`, so both are accepted
/// before falling back to the first list-valued field.
pub fn list_field(body: &Value) -> Vec<Value> {
    if let Value::Array(items) = body {
        return items.clone();
    }
    let Value::Object(map) = body else {
        return Vec::new();
    };
    for key in ["data", "vouchers"] {
        if let Some(Value::Array(items)) = map.get(key) {
            return items.clone();
        }
    }
    map.values()
        .find_map(|v| v.as_array().cloned())
        .unwrap_or_default()
}

impl Site {
    pub fn from_json(v: &Value) -> Option<Self> {
        let id = as_str(v.get("id")).or_else(|| as_str(v.get("_id")))?;
        let name = as_str(v.get("name"))
            .or_else(|| as_str(v.get("internalReference")))
            .or_else(|| as_str(v.get("desc")))
            .unwrap_or_else(|| id.clone());
        Some(Self { id, name })
    }

    pub fn list(body: &Value) -> Vec<Self> {
        list_field(body)
            .iter()
            .filter_map(Self::from_json)
            .collect()
    }
}

impl Voucher {
    pub fn from_json(v: &Value) -> Option<Self> {
        let id = as_str(v.get("id")).or_else(|| as_str(v.get("_id")))?;
        Some(Self {
            id,
            code: as_str(v.get("code")).unwrap_or_default(),
            name: as_str(v.get("name")),
            time_limit_minutes: as_int(v.get("timeLimitMinutes")),
            authorized_guest_limit: as_int(v.get("authorizedGuestLimit")),
            authorized_guest_count: as_int(v.get("authorizedGuestCount")),
            expired: v.get("expired").and_then(Value::as_bool).unwrap_or(false),
            expires_at: as_str(v.get("expiresAt")),
            created_at: as_str(v.get("createdAt")),
            data_usage_limit_m_bytes: as_int(v.get("dataUsageLimitMBytes")),
            rx_rate_limit_kbps: as_int(v.get("rxRateLimitKbps")),
            tx_rate_limit_kbps: as_int(v.get("txRateLimitKbps")),
        })
    }

    pub fn list(body: &Value) -> Vec<Self> {
        list_field(body)
            .iter()
            .filter_map(Self::from_json)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_sites_in_every_shape_the_api_uses() {
        let body = json!({"data": [
            {"id": "a", "name": "Default"},
            {"_id": "b", "desc": "Branch"},
            {"id": "c"}
        ]});
        let sites = Site::list(&body);
        assert_eq!(sites.len(), 3);
        assert_eq!(sites[1].id, "b");
        assert_eq!(sites[1].name, "Branch");
        // Nameless sites fall back to their id rather than vanishing.
        assert_eq!(sites[2].name, "c");
    }

    #[test]
    fn reads_vouchers_from_both_envelopes() {
        let paged = json!({"data": [{"id": "v1", "code": "1234567890"}]});
        let created = json!({"vouchers": [{"id": "v2", "code": "0987654321"}]});
        assert_eq!(Voucher::list(&paged)[0].id, "v1");
        assert_eq!(Voucher::list(&created)[0].id, "v2");
    }

    #[test]
    fn tolerates_missing_usage_fields() {
        let v = Voucher::from_json(&json!({"id": "v1", "code": "1"})).unwrap();
        assert_eq!(v.authorized_guest_count, None);
        assert!(!v.expired);
    }

    #[test]
    fn skips_entries_without_an_id_instead_of_failing_the_response() {
        let body = json!({"data": [{"code": "orphan"}, {"id": "ok", "code": "1"}]});
        let vouchers = Voucher::list(&body);
        assert_eq!(vouchers.len(), 1);
        assert_eq!(vouchers[0].id, "ok");
    }

    #[test]
    fn accepts_a_bare_array_as_well_as_an_envelope() {
        let bare = json!([{"id": "v1", "code": "1"}]);
        assert_eq!(Voucher::list(&bare).len(), 1);
    }

    #[test]
    fn falls_back_to_the_first_list_valued_field() {
        // Some firmwares wrap the list under a key we have not seen before;
        // taking the first array is better than returning nothing.
        let odd = json!({"meta": {"rc": "ok"}, "someOtherKey": [{"id": "v1"}]});
        assert_eq!(Voucher::list(&odd).len(), 1);
    }

    #[test]
    fn returns_nothing_for_shapes_that_hold_no_list() {
        assert!(Voucher::list(&json!("just a string")).is_empty());
        assert!(Voucher::list(&json!({"meta": {"rc": "ok"}})).is_empty());
        assert!(Voucher::list(&json!(null)).is_empty());
    }

    #[test]
    fn reads_numeric_ids() {
        // Ids arrive as numbers on some endpoints.
        let v = Voucher::from_json(&json!({"id": 42, "code": 12345})).unwrap();
        assert_eq!(v.id, "42");
        assert_eq!(v.code, "12345");
    }

    #[test]
    fn treats_an_empty_string_as_absent() {
        let v = Voucher::from_json(&json!({"id": "v", "name": ""})).unwrap();
        assert_eq!(v.name, None);
    }

    #[test]
    fn skips_sites_without_an_id() {
        assert!(Site::from_json(&json!({"name": "nameless"})).is_none());
    }

    #[test]
    fn accepts_numeric_strings_for_int_fields() {
        let v = Voucher::from_json(&json!({"id": "v", "timeLimitMinutes": "480"})).unwrap();
        assert_eq!(v.time_limit_minutes, Some(480));
    }
}
