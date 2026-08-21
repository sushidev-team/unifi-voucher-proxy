use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;

use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};

use crate::config::{Config, TokenConfig};

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Per-token request budgets.
///
/// Each token gets its own limiter built from its effective quota, so one noisy
/// device cannot spend another's allowance. A token configured with `0` is
/// unlimited and simply has no entry.
#[derive(Debug, Default)]
pub struct RateLimits {
    limiters: HashMap<String, Arc<DirectLimiter>>,
}

impl RateLimits {
    pub fn from_config(cfg: &Config) -> Self {
        let mut limiters = HashMap::new();
        for token in &cfg.tokens {
            let per_minute = token.effective_rate_limit(&cfg.limits);
            if let Some(n) = NonZeroU32::new(per_minute) {
                limiters.insert(
                    token.name.clone(),
                    Arc::new(RateLimiter::direct(Quota::per_minute(n))),
                );
            }
        }
        Self { limiters }
    }

    /// Consumes one unit of the token's budget. `false` means "over quota".
    pub fn check(&self, token: &TokenConfig) -> bool {
        match self.limiters.get(&token.name) {
            Some(limiter) => limiter.check().is_ok(),
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ControllerConfig, Limits, Scope, ServerConfig, TlsConfig};
    use crate::secret::Secret;

    fn config(global: u32, per_token: Option<u32>) -> Config {
        Config {
            server: ServerConfig::default(),
            controller: ControllerConfig {
                host: "https://10.0.0.1".into(),
                api_key: Secret::new("k"),
                tls: TlsConfig::default(),
            },
            limits: Limits {
                rate_limit_per_minute: global,
                ..Limits::default()
            },
            tokens: vec![TokenConfig {
                name: "phone".into(),
                hash: "$argon2id$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA".into(),
                sites: vec!["*".into()],
                scopes: vec![Scope::VouchersRead],
                max_vouchers_per_request: None,
                max_validity_minutes: None,
                rate_limit_per_minute: per_token,
            }],
        }
    }

    #[test]
    fn stops_a_caller_that_burns_its_quota() {
        let cfg = config(2, None);
        let limits = RateLimits::from_config(&cfg);
        let token = &cfg.tokens[0];
        assert!(limits.check(token));
        assert!(limits.check(token));
        assert!(!limits.check(token), "third call in the same minute");
    }

    #[test]
    fn a_token_may_tighten_but_not_widen_the_global_quota() {
        let cfg = config(10, Some(1));
        let limits = RateLimits::from_config(&cfg);
        let token = &cfg.tokens[0];
        assert!(limits.check(token));
        assert!(!limits.check(token));
    }

    #[test]
    fn zero_means_unlimited() {
        let cfg = config(0, None);
        let limits = RateLimits::from_config(&cfg);
        let token = &cfg.tokens[0];
        for _ in 0..1000 {
            assert!(limits.check(token));
        }
    }
}
