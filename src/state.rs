use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use time::OffsetDateTime;

use crate::audit;
use crate::auth::{token_from_headers, Authenticator};
use crate::config::{Config, Limits, Scope, TokenConfig};
use crate::error::ProxyError;
use crate::graphql::{self, ProxySchema};
use crate::metrics::Metrics;
use crate::policy::Ceilings;
use crate::ratelimit::RateLimits;
use crate::upstream::Upstream;

/// Everything a SIGHUP can replace.
///
/// Grouped into one struct so a reload swaps a single pointer: a request either
/// sees the whole old configuration or the whole new one, never a token list
/// from one and limits from the other.
pub struct Live {
    pub auth: Authenticator,
    pub upstream: Upstream,
    pub limits: Limits,
    pub rate: RateLimits,
    pub token_count: usize,
}

impl Live {
    pub fn build(cfg: &Config) -> Result<Self> {
        Ok(Self {
            auth: Authenticator::new(&cfg.tokens)?,
            upstream: Upstream::new(&cfg.controller, cfg.server.upstream_timeout)?,
            limits: cfg.limits.clone(),
            rate: RateLimits::from_config(cfg),
            token_count: cfg.tokens.len(),
        })
    }
}

pub struct AppState {
    /// Read on every request; swapped wholesale on reload. `ArcSwap` keeps the
    /// read path lock-free, which matters because it is on every request while
    /// writes happen only on SIGHUP.
    live: ArcSwap<Live>,
    pub schema: ProxySchema,
    pub metrics: Metrics,
    /// Where to re-read on SIGHUP. `None` when the config came from the
    /// environment alone, in which case there is nothing to re-read.
    pub config_path: Option<PathBuf>,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    pub fn new(cfg: &Config) -> Result<SharedState> {
        Self::with_path(cfg, None)
    }

    pub fn with_path(cfg: &Config, config_path: Option<PathBuf>) -> Result<SharedState> {
        Ok(Arc::new(Self {
            live: ArcSwap::from_pointee(Live::build(cfg)?),
            schema: graphql::schema(),
            metrics: Metrics::default(),
            config_path,
        }))
    }

    pub fn live(&self) -> arc_swap::Guard<Arc<Live>> {
        self.live.load()
    }

    /// Re-reads the config file and swaps in the result.
    ///
    /// A bad config leaves the running configuration untouched: a typo in a
    /// token entry must not be able to take a working proxy down, so the error
    /// is reported and the old `Live` keeps serving.
    pub fn reload(&self) -> Result<usize> {
        let path = self
            .config_path
            .as_deref()
            .context("no config file to reload — this proxy was configured from the environment")?;
        let cfg =
            Config::load(Some(path)).context("reload rejected, keeping the previous config")?;
        let live = Live::build(&cfg).context("reload rejected, keeping the previous config")?;
        let count = live.token_count;
        self.live.store(Arc::new(live));
        Ok(count)
    }
}

/// An authenticated client, resolved from the request's token.
///
/// Extracting this type is what enforces authentication; a handler that takes a
/// `Caller` cannot be reached anonymously.
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
    /// single GraphQL document can ask for several.
    ///
    /// Spent once the caller is known to be allowed to attempt the operation,
    /// which is deliberately *before* anything parses client-supplied data: the
    /// quota bounds load on the console, but it also has to bound the work a
    /// caller can make the proxy itself do. Scope and site refusals stay free —
    /// they are constant-time lookups, and charging for them would punish a
    /// client for a misconfiguration it cannot see.
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
        let live = state.live();

        // Charged before the token is even read. Verifying a wrong token runs
        // Argon2 against every configured hash and is deliberately never
        // cached, so without this an unauthenticated caller decides how much
        // CPU this machine spends.
        //
        // The peer address only reaches here when the server was started with
        // `into_make_service_with_connect_info`; absent it, there is no key to
        // count against and the limit is skipped rather than guessed at.
        if let Some(ConnectInfo(peer)) = parts.extensions.get::<ConnectInfo<std::net::SocketAddr>>()
        {
            if !live.rate.check_ip(peer.ip()) {
                audit::rejected(parts.uri.path(), "ip_rate_limited", 429);
                state
                    .metrics
                    .record_request("-", parts.uri.path(), "ip_rate_limited");
                return Err(ProxyError::RateLimited);
            }
        }

        let Some(presented) = token_from_headers(&parts.headers) else {
            audit::rejected(parts.uri.path(), "missing_token", 401);
            state
                .metrics
                .record_request("-", parts.uri.path(), "missing_token");
            return Err(ProxyError::Unauthorized);
        };

        let Some(token) = live.auth.authenticate(presented) else {
            audit::rejected(parts.uri.path(), "unknown_token", 401);
            state
                .metrics
                .record_request("-", parts.uri.path(), "unknown_token");
            return Err(ProxyError::Unauthorized);
        };

        // Checked per request, so a token stops working the moment it lapses
        // rather than at the next restart.
        if let Some(expiry) = token.expires_at {
            let now = OffsetDateTime::now_utc();
            if token.is_expired_at(now) {
                audit::rejected(parts.uri.path(), "token_expired", 401);
                state
                    .metrics
                    .record_request(&token.name, parts.uri.path(), "token_expired");
                return Err(ProxyError::TokenExpired(
                    expiry
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_else(|_| "an earlier date".to_string()),
                ));
            }
        }

        let ceilings = Ceilings {
            max_vouchers: token.effective_max_vouchers(&live.limits),
            max_validity_minutes: token.effective_max_validity(&live.limits),
        };
        Ok(Caller { token, ceilings })
    }
}
