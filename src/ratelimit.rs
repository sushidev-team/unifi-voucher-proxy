use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};

use crate::config::{Config, TokenConfig};

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;
type PerIpLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

/// How many pre-auth checks pass before expired per-IP entries are swept.
///
/// The keyed store holds one entry per source address, so without this a long
/// run of distinct addresses is itself a slow memory leak. Sweeping on a
/// counter rather than a timer keeps the work proportional to traffic.
const SWEEP_EVERY: u32 = 1024;

/// Per-token request budgets.
///
/// Each token gets its own limiter built from its effective quota, so one noisy
/// device cannot spend another's allowance. A token configured with `0` is
/// unlimited and simply has no entry.
#[derive(Debug, Default)]
pub struct RateLimits {
    limiters: HashMap<String, Arc<DirectLimiter>>,
    /// Charged before a token is even looked at — see [`RateLimits::check_ip`].
    per_ip: Option<Arc<PerIpLimiter>>,
    sweep: AtomicU32,
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
        let per_ip = NonZeroU32::new(cfg.limits.rate_limit_per_ip_per_minute)
            .map(|n| Arc::new(RateLimiter::keyed(Quota::per_minute(n))));
        Self {
            limiters,
            per_ip,
            sweep: AtomicU32::new(0),
        }
    }

    /// Spends one unit of a source address's pre-authentication budget.
    ///
    /// This runs before the Argon2 verification, which is the expensive part
    /// and the part an unauthenticated caller can otherwise trigger at will.
    /// `true` when the address may proceed; `None` configured means unlimited.
    pub fn check_ip(&self, ip: IpAddr) -> bool {
        let Some(limiter) = &self.per_ip else {
            return true;
        };
        if self.sweep.fetch_add(1, Ordering::Relaxed) % SWEEP_EVERY == SWEEP_EVERY - 1 {
            limiter.retain_recent();
        }
        limiter.check_key(&ip).is_ok()
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
                rate_limit_per_ip_per_minute: 0,
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
                expires_at: None,
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

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([127, 0, 0, last])
    }

    #[test]
    fn a_source_address_gets_its_own_pre_auth_budget() {
        let mut cfg = config(0, None);
        cfg.limits.rate_limit_per_ip_per_minute = 2;
        let limits = RateLimits::from_config(&cfg);

        assert!(limits.check_ip(ip(1)));
        assert!(limits.check_ip(ip(1)));
        assert!(!limits.check_ip(ip(1)), "third call in the same minute");

        // A different address is unaffected — one noisy client must not lock
        // everyone else out of authenticating.
        assert!(limits.check_ip(ip(2)));
    }

    #[test]
    fn a_pre_auth_budget_of_zero_is_unlimited() {
        let cfg = config(0, None);
        assert_eq!(cfg.limits.rate_limit_per_ip_per_minute, 0);
        let limits = RateLimits::from_config(&cfg);
        for _ in 0..2000 {
            assert!(limits.check_ip(ip(1)));
        }
    }

    #[test]
    fn the_keyed_store_is_swept_so_it_cannot_grow_without_bound() {
        let mut cfg = config(0, None);
        cfg.limits.rate_limit_per_ip_per_minute = 60;
        let limits = RateLimits::from_config(&cfg);
        // Enough calls to cross the sweep threshold at least once.
        for i in 0..(SWEEP_EVERY + 8) {
            limits.check_ip(IpAddr::from([10, 0, (i / 256) as u8, (i % 256) as u8]));
        }
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
