use std::sync::Arc;

use anyhow::Result;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::audit;
use crate::auth::{token_from_headers, Authenticator};
use crate::config::{Config, Limits, Scope, TokenConfig};
use crate::error::ProxyError;
use crate::graphql::{self, ProxySchema};
use crate::policy::Ceilings;
use crate::ratelimit::RateLimits;
use crate::upstream::Upstream;

pub struct AppState {
    pub auth: Authenticator,
    pub upstream: Upstream,
    pub limits: Limits,
    pub rate: RateLimits,
    pub schema: ProxySchema,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    pub fn new(cfg: &Config) -> Result<SharedState> {
        Ok(Arc::new(Self {
            auth: Authenticator::new(&cfg.tokens)?,
            upstream: Upstream::new(&cfg.controller, cfg.server.upstream_timeout)?,
            limits: cfg.limits.clone(),
            rate: RateLimits::from_config(cfg),
            schema: graphql::schema(),
        }))
    }
}

/// An authenticated client, resolved from the request's token.
///
/// Extracting this type is what enforces authentication and the per-token rate
/// limit; a handler that takes a `Caller` cannot be reached anonymously.
#[derive(Clone)]
pub struct Caller {
    pub token: Arc<TokenConfig>,
    pub ceilings: Ceilings,
}

impl Caller {
    pub fn name(&self) -> &str {
        &self.token.name
    }

    pub fn require_scope(&self, scope: Scope) -> Result<(), ProxyError> {
        if self.token.has_scope(scope) {
            Ok(())
        } else {
            Err(ProxyError::Forbidden(format!(
                "token '{}' does not carry the {} scope",
                self.token.name,
                scope.as_str()
            )))
        }
    }

    /// Spends one unit of the caller's quota.
    ///
    /// Charged per *upstream call* rather than per HTTP request, because a
    /// single GraphQL document can ask for several. Refusals that never reach
    /// the controller cost nothing, which is the honest accounting: the quota
    /// exists to bound load on the console.
    pub fn charge(&self, rate: &RateLimits, action: &str) -> Result<(), ProxyError> {
        if rate.check(&self.token) {
            Ok(())
        } else {
            audit::rejected(action, "rate_limited", 429);
            Err(ProxyError::RateLimited)
        }
    }

    pub fn require_site(&self, site: &str) -> Result<(), ProxyError> {
        if self.token.allows_site(site) {
            Ok(())
        } else {
            Err(ProxyError::Forbidden(format!(
                "token '{}' is not allowed to use site '{}'",
                self.token.name, site
            )))
        }
    }
}

impl FromRequestParts<SharedState> for Caller {
    type Rejection = ProxyError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let Some(presented) = token_from_headers(&parts.headers) else {
            audit::rejected(parts.uri.path(), "missing_token", 401);
            return Err(ProxyError::Unauthorized);
        };

        let Some(token) = state.auth.authenticate(presented) else {
            audit::rejected(parts.uri.path(), "unknown_token", 401);
            return Err(ProxyError::Unauthorized);
        };

        let ceilings = Ceilings {
            max_vouchers: token.effective_max_vouchers(&state.limits),
            max_validity_minutes: token.effective_max_validity(&state.limits),
        };
        Ok(Caller { token, ceilings })
    }
}
