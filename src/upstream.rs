use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::{Method, StatusCode};
use serde_json::Value;

use crate::config::ControllerConfig;
use crate::error::{ProxyError, ProxyResult};
use crate::secret::Secret;
use crate::tls;

/// The client that holds the real UniFi API key.
///
/// There is deliberately no generic "forward this path" method. Every reachable
/// upstream call is a named function on this type, so the set of things the
/// proxy can possibly do to your controller is the list below — enforced by the
/// compiler, not by a runtime allowlist someone can misconfigure.
#[derive(Debug, Clone)]
pub struct Upstream {
    client: reqwest::Client,
    /// `https://host/proxy/network/integration/v1`
    base: String,
    api_key: Secret,
}

/// The Integration API pages voucher reads at 100 by default and caps at 1000.
const VOUCHER_PAGE_LIMIT: u32 = 1000;

impl Upstream {
    pub fn new(cfg: &ControllerConfig, timeout: Duration) -> Result<Self> {
        let tls = tls::client_config(&cfg.tls)?;
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(10))
            // Redirects would let a compromised controller bounce the API key
            // to an arbitrary host.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("failed to build the upstream HTTP client")?;

        Ok(Self {
            client,
            base: format!("{}/proxy/network/integration/v1", normalize_host(&cfg.host)),
            api_key: cfg.api_key.clone(),
        })
    }

    pub async fn list_sites(&self) -> ProxyResult<Value> {
        self.send(Method::GET, "/sites".to_string(), None).await
    }

    pub async fn list_vouchers(&self, site: &str) -> ProxyResult<Value> {
        let site = validate_id(site, "site id")?;
        self.send(
            Method::GET,
            format!("/sites/{site}/hotspot/vouchers?limit={VOUCHER_PAGE_LIMIT}"),
            None,
        )
        .await
    }

    pub async fn create_vouchers(&self, site: &str, body: &Value) -> ProxyResult<Value> {
        let site = validate_id(site, "site id")?;
        self.send(
            Method::POST,
            format!("/sites/{site}/hotspot/vouchers"),
            Some(body),
        )
        .await
    }

    pub async fn delete_voucher(&self, site: &str, voucher: &str) -> ProxyResult<Value> {
        let site = validate_id(site, "site id")?;
        let voucher = validate_id(voucher, "voucher id")?;
        self.send(
            Method::DELETE,
            format!("/sites/{site}/hotspot/vouchers/{voucher}"),
            None,
        )
        .await
    }

    async fn send(&self, method: Method, path: String, body: Option<&Value>) -> ProxyResult<Value> {
        let url = format!("{}{}", self.base, path);
        let mut req = self
            .client
            .request(method, &url)
            .header("X-API-KEY", self.api_key.expose())
            .header("Accept", "application/json");
        if let Some(b) = body {
            req = req.json(b);
        }

        let res = req.send().await.map_err(|e| {
            // `e` can render the URL but never the header, so this is safe to
            // surface. Keep it short — it reaches the client.
            ProxyError::UpstreamUnreachable(short_reqwest_error(&e))
        })?;

        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        let json: Value = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or(Value::Null)
        };

        if status.is_success() {
            return Ok(json);
        }

        // A 5xx body is where a controller would put internals — a stack trace,
        // a path, a component name. That is the operator's to read in the log,
        // not the client's to receive, so only the status crosses back.
        let message = if status.is_server_error() {
            // Resolved before the macro, as in `audit`: `tracing` only evaluates
            // field expressions when a subscriber is listening, which makes them
            // invisible to coverage.
            let code = status.as_u16();
            let body = clamp(&text);
            tracing::warn!(
                status = code,
                body = %body,
                "the controller returned a server error"
            );
            format!(
                "the controller reported an error (HTTP {})",
                status.as_u16()
            )
        } else if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
            // Checked before the controller's own message, never after. A 401
            // here is not about the caller's request at all — it says the
            // *proxy's* key was refused. The caller can do nothing with that,
            // and the controller's wording can describe the very secret this
            // proxy exists to hold, so it goes to the operator's log instead.
            let code = status.as_u16();
            let body = clamp(&text);
            tracing::warn!(
                status = code,
                body = %body,
                "the controller rejected the proxy's API key"
            );
            "the controller rejected the proxy's API key".to_string()
        } else {
            json.get("message")
                .and_then(Value::as_str)
                .map(clamp)
                .unwrap_or_else(|| format!("controller request failed (HTTP {})", status.as_u16()))
        };

        Err(ProxyError::Upstream {
            status: axum::http::StatusCode::from_u16(status.as_u16())
                .unwrap_or(axum::http::StatusCode::BAD_GATEWAY),
            message,
        })
    }
}

/// Trims a reqwest error down to something safe and useful for a client.
///
/// A pinning failure is checked first and by walking the whole source chain:
/// rustls reports it several levels down, and reqwest classifies it as a
/// connect error, so the generic buckets would otherwise swallow the one
/// diagnostic that actually matters — either the console was re-provisioned or
/// something is impersonating it.
fn short_reqwest_error(e: &reqwest::Error) -> String {
    let mut chain = vec![e.to_string()];
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
    while let Some(s) = source {
        chain.push(s.to_string());
        source = s.source();
    }
    let full = chain.join(": ");

    if full.contains("fingerprint mismatch") {
        return "certificate fingerprint mismatch — the controller is not the one this proxy is pinned to".to_string();
    }
    if e.is_timeout() {
        return "timed out".to_string();
    }
    if full.contains("invalid peer certificate") || full.contains("UnknownIssuer") {
        return "the controller's certificate is not trusted — pin its fingerprint with `fetch-fingerprint`".to_string();
    }
    if e.is_connect() {
        return "connection refused or host unreachable".to_string();
    }
    "request failed".to_string()
}

/// Bounds a message coming from the controller before it is echoed anywhere.
///
/// Upstream text is not ours and is not trusted to be short or well-behaved:
/// control characters are dropped so a log line cannot be forged, and the
/// length is capped so a large body cannot become a large response or a large
/// log entry.
fn clamp(raw: &str) -> String {
    const MAX: usize = 200;
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = cleaned.trim();
    match trimmed.char_indices().nth(MAX) {
        Some((cut, _)) => format!("{}…", &trimmed[..cut]),
        None => trimmed.to_string(),
    }
}

/// Turns a user-entered host into `https://host[:port]`.
fn normalize_host(host: &str) -> String {
    let h = host.trim().trim_end_matches('/');
    if h.starts_with("http://") || h.starts_with("https://") {
        h.to_string()
    } else {
        format!("https://{h}")
    }
}

/// Path segments come from the client, so they are whitelisted rather than
/// escaped: anything outside this alphabet cannot be a UniFi id and could
/// otherwise walk out of the voucher namespace with `..` or a query string.
fn validate_id<'a>(value: &'a str, what: &str) -> ProxyResult<&'a str> {
    if value.is_empty() || value.len() > 128 {
        return Err(ProxyError::BadRequest(format!(
            "{what} has an implausible length"
        )));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        return Err(ProxyError::BadRequest(format!(
            "{what} contains characters that are not allowed"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_hosts() {
        assert_eq!(normalize_host("192.168.1.1"), "https://192.168.1.1");
        assert_eq!(normalize_host("https://10.0.0.1/"), "https://10.0.0.1");
        assert_eq!(
            normalize_host("  unifi.lan:8443 "),
            "https://unifi.lan:8443"
        );
        assert_eq!(normalize_host("http://10.0.0.1"), "http://10.0.0.1");
    }

    #[test]
    fn rejects_path_traversal_in_ids() {
        assert!(validate_id("../../../api/self", "site id").is_err());
        assert!(validate_id("abc/def", "site id").is_err());
        assert!(validate_id("abc?limit=1", "site id").is_err());
        assert!(validate_id("", "site id").is_err());
        assert!(validate_id(&"a".repeat(200), "site id").is_err());
        assert!(validate_id("default", "site id").is_ok());
        assert!(validate_id("66c2f1e9-4b3a-4f21-9d0e-1a2b3c4d5e6f", "site id").is_ok());
    }
}
