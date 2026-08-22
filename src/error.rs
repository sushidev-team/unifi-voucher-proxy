use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// Everything the proxy can refuse or fail with.
///
/// The wire shape is `{"message": "..."}` — the same envelope the UniFi
/// Integration API uses for errors, so drop-in clients surface proxy errors
/// through their existing error handling without changes.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("missing or invalid API key")]
    Unauthorized,

    /// The token was recognised but has lapsed. Told apart from
    /// [`Unauthorized`] on purpose: "your token expired" is actionable, while
    /// "invalid key" sends the operator looking for a typo.
    #[error("this token expired on {0}")]
    TokenExpired(String),

    #[error("{0}")]
    Forbidden(String),

    #[error("{0}")]
    BadRequest(String),

    #[error("rate limit exceeded — slow down")]
    RateLimited,

    #[error("this proxy only forwards hotspot voucher operations")]
    NotAllowed,

    /// The controller answered, but not with success. Its status and message
    /// are passed through so clients keep seeing meaningful errors.
    #[error("{message}")]
    Upstream { status: StatusCode, message: String },

    #[error("cannot reach the UniFi controller: {0}")]
    UpstreamUnreachable(String),

    #[error("internal proxy error")]
    Internal(#[from] anyhow::Error),
}

impl ProxyError {
    pub fn status(&self) -> StatusCode {
        match self {
            ProxyError::Unauthorized => StatusCode::UNAUTHORIZED,
            ProxyError::TokenExpired(_) => StatusCode::UNAUTHORIZED,
            ProxyError::Forbidden(_) => StatusCode::FORBIDDEN,
            ProxyError::NotAllowed => StatusCode::FORBIDDEN,
            ProxyError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ProxyError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ProxyError::Upstream { status, .. } => *status,
            ProxyError::UpstreamUnreachable(_) => StatusCode::BAD_GATEWAY,
            ProxyError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Short machine-readable tag, used in audit records.
    pub fn kind(&self) -> &'static str {
        match self {
            ProxyError::Unauthorized => "unauthorized",
            ProxyError::TokenExpired(_) => "token_expired",
            ProxyError::Forbidden(_) => "forbidden",
            ProxyError::NotAllowed => "not_allowed",
            ProxyError::BadRequest(_) => "bad_request",
            ProxyError::RateLimited => "rate_limited",
            ProxyError::Upstream { .. } => "upstream_error",
            ProxyError::UpstreamUnreachable(_) => "upstream_unreachable",
            ProxyError::Internal(_) => "internal",
        }
    }
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        // Internal errors are logged in full but reported opaquely: their text
        // can carry configuration detail that clients have no business seeing.
        if let ProxyError::Internal(err) = &self {
            tracing::error!(error = ?err, "internal error");
        }
        let status = self.status();
        let message = match &self {
            ProxyError::Internal(_) => "internal proxy error".to_string(),
            other => other.to_string(),
        };
        (status, Json(json!({ "message": message }))).into_response()
    }
}

pub type ProxyResult<T> = Result<T, ProxyError>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    fn all_variants() -> Vec<ProxyError> {
        vec![
            ProxyError::Unauthorized,
            ProxyError::TokenExpired("2026-01-01T00:00:00Z".into()),
            ProxyError::Forbidden("nope".into()),
            ProxyError::NotAllowed,
            ProxyError::BadRequest("bad".into()),
            ProxyError::RateLimited,
            ProxyError::Upstream {
                status: StatusCode::CONFLICT,
                message: "conflict".into(),
            },
            ProxyError::UpstreamUnreachable("timed out".into()),
            ProxyError::Internal(anyhow::anyhow!("config path /etc/secrets")),
        ]
    }

    #[test]
    fn every_variant_maps_to_a_status_and_a_kind() {
        let expected = [
            (StatusCode::UNAUTHORIZED, "unauthorized"),
            (StatusCode::UNAUTHORIZED, "token_expired"),
            (StatusCode::FORBIDDEN, "forbidden"),
            (StatusCode::FORBIDDEN, "not_allowed"),
            (StatusCode::BAD_REQUEST, "bad_request"),
            (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            (StatusCode::CONFLICT, "upstream_error"),
            (StatusCode::BAD_GATEWAY, "upstream_unreachable"),
            (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        ];
        for (err, (status, kind)) in all_variants().into_iter().zip(expected) {
            assert_eq!(err.status(), status, "{err}");
            assert_eq!(err.kind(), kind, "{err}");
        }
    }

    #[tokio::test]
    async fn errors_render_in_the_envelope_unifi_clients_already_parse() {
        let res = ProxyError::Forbidden("token may not do that".into()).into_response();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(res.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "token may not do that");
    }

    #[tokio::test]
    async fn internal_errors_do_not_tell_the_client_what_went_wrong() {
        let res = ProxyError::Internal(anyhow::anyhow!("api_key=hunter2 at /etc/secrets"))
            .into_response();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(res.into_body(), 4096).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("internal proxy error"));
        assert!(!text.contains("hunter2") && !text.contains("/etc/secrets"));
    }

    #[test]
    fn an_anyhow_error_converts_into_the_internal_variant() {
        let err: ProxyError = anyhow::anyhow!("boom").into();
        assert_eq!(err.kind(), "internal");
    }
}
