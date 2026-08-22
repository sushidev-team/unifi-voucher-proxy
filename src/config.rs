use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use figment::providers::{Env, Format, Toml};
use figment::Figment;
use serde::{Deserialize, Deserializer, Serialize};
use time::OffsetDateTime;

use crate::secret::Secret;

/// The proxy's whole configuration. Loaded from a TOML file, then overlaid with
/// `UVP_*` environment variables so secrets can stay out of the file entirely
/// (`UVP_CONTROLLER__API_KEY=...` is the common deployment shape).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    pub controller: ControllerConfig,
    #[serde(default)]
    pub limits: Limits,
    /// Callers allowed through. An empty list is refused at startup — a proxy
    /// that trusts everyone is worse than no proxy.
    #[serde(default)]
    pub tokens: Vec<TokenConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    /// How long an upstream call may take before the proxy gives up.
    #[serde(default = "default_timeout", with = "humantime_serde")]
    pub upstream_timeout: Duration,
    /// Largest request body accepted from a client, in bytes.
    #[serde(default = "default_body_limit")]
    pub max_body_bytes: usize,
    /// Serve the GraphiQL explorer at `GET /graphql`.
    ///
    /// Off by default. The page is inert client-side HTML and carries no
    /// credentials of its own, but a security component should not put an
    /// unrequested interactive console on the network.
    #[serde(default)]
    pub graphql_playground: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerConfig {
    /// Controller root, e.g. `https://192.168.1.1`. Scheme optional.
    pub host: String,
    /// The full-control UniFi Integration API key. This is the value the whole
    /// project exists to keep off end-user devices.
    pub api_key: Secret,
    #[serde(default)]
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// SHA-256 fingerprint(s) of the controller's leaf certificate, hex encoded
    /// (colons and `sha256:` prefix are tolerated). When set, the presented
    /// certificate must match one of them — this is how you get a trustworthy
    /// channel to a box that ships a self-signed cert.
    ///
    /// Accepts a single string or a list. A list is for the cases where one
    /// console legitimately answers with more than one certificate — UniFi OS
    /// serves a different leaf depending on the name it is reached by, and a
    /// planned rotation means both the old and the new one are valid for a
    /// while. Every entry is still an exact pin; a list widens *which* certs
    /// are accepted, never *whether* they are checked.
    #[serde(default, deserialize_with = "one_or_many")]
    pub fingerprint_sha256: Option<Vec<String>>,
    /// Accept any certificate. Requires no fingerprint to be set and is loudly
    /// warned about on every startup; provided only so first-run setup can
    /// discover the fingerprint.
    #[serde(default)]
    pub insecure_skip_verify: bool,
    /// Suppress the per-start warning that `insecure_skip_verify` prints.
    ///
    /// The check stays off either way — this only silences the reminder, for an
    /// operator who has weighed the risk and does not want it in the log on
    /// every restart. It does nothing unless `insecure_skip_verify` is on.
    #[serde(default)]
    pub silence_insecure_warning: bool,
    /// Permit an `http://` controller URL, i.e. no TLS at all.
    ///
    /// A UniFi console always speaks HTTPS, so this exists for one shape only:
    /// a TLS-terminating sidecar on the loopback interface. Without it a
    /// plaintext host is refused at startup, because the whole point of the
    /// proxy is that the full-control API key never travels in the clear.
    #[serde(default)]
    pub allow_plaintext: bool,
}

/// Accepts either `fingerprint_sha256 = "abc…"` or `fingerprint_sha256 = ["abc…", "def…"]`.
///
/// The single-string form is what every existing config and the README use, so
/// it stays the documented shape; the list is an additive convenience.
fn one_or_many<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<String>>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Option::<OneOrMany>::deserialize(d)? {
        None => None,
        Some(OneOrMany::One(s)) => Some(vec![s]),
        Some(OneOrMany::Many(v)) => Some(v),
    })
}

impl ControllerConfig {
    /// Whether the configured host disables TLS outright. An absent scheme
    /// means https, so only an explicit `http://` counts.
    pub fn is_plaintext(&self) -> bool {
        self.host.trim().to_ascii_lowercase().starts_with("http://")
    }
}

/// Ceilings applied to every request, before any per-token override.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "default_max_vouchers")]
    pub max_vouchers_per_request: u32,
    #[serde(default = "default_max_validity")]
    pub max_validity_minutes: u64,
    /// Requests per minute per token. `0` disables rate limiting.
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_minute: u32,
    /// Requests per minute per client IP, charged *before* authentication.
    ///
    /// Verifying a token costs a full Argon2 hash against every configured
    /// token, and a wrong token is never cached — so without this an
    /// unauthenticated caller can spend the machine's CPU at will. `0` disables
    /// it, which is right only when something in front already limits by
    /// source. Note the counter keys on the peer address: behind a reverse
    /// proxy every client shares one, so let that proxy do this instead.
    #[serde(default = "default_pre_auth_rate_limit")]
    pub rate_limit_per_ip_per_minute: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenConfig {
    /// Label used in audit logs. Never secret; make it identify the device.
    pub name: String,
    /// Argon2id PHC string produced by `unifi-voucher-proxy hash-token`.
    pub hash: String,
    /// Site ids this token may touch. `["*"]` means every site.
    #[serde(default = "default_sites")]
    pub sites: Vec<String>,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<Scope>,
    pub max_vouchers_per_request: Option<u32>,
    pub max_validity_minutes: Option<u64>,
    pub rate_limit_per_minute: Option<u32>,

    /// When this token stops working, as an RFC-3339 timestamp
    /// (`2027-03-01T00:00:00Z`). Absent means it never expires.
    ///
    /// Expiry is checked per request rather than at startup, so a long-running
    /// proxy stops honouring a token the moment it lapses — no restart needed.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

/// What a token may do.
///
/// The wire names are spelled explicitly rather than derived: they appear in
/// user-written config files, in `check-config` output and in GraphQL
/// responses, so they are API surface and must not drift with a serde rename
/// convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum Scope {
    /// List sites. Needed by clients that let the user pick one.
    #[serde(rename = "sites:read")]
    SitesRead,
    /// List existing vouchers.
    #[serde(rename = "vouchers:read")]
    VouchersRead,
    /// Create new vouchers.
    #[serde(rename = "vouchers:create")]
    VouchersCreate,
    /// Delete (revoke) vouchers.
    #[serde(rename = "vouchers:revoke")]
    VouchersRevoke,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::SitesRead => "sites:read",
            Scope::VouchersRead => "vouchers:read",
            Scope::VouchersCreate => "vouchers:create",
            Scope::VouchersRevoke => "vouchers:revoke",
        }
    }
}

impl TokenConfig {
    pub fn allows_site(&self, site: &str) -> bool {
        self.sites.iter().any(|s| s == "*" || s == site)
    }

    pub fn has_scope(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }

    /// Whether the token has lapsed as of [now].
    ///
    /// `now` is passed in rather than read from the clock so the behaviour can
    /// be tested at chosen instants instead of by sleeping.
    pub fn is_expired_at(&self, now: OffsetDateTime) -> bool {
        self.expires_at.is_some_and(|t| now >= t)
    }

    /// How long until it lapses; `None` when it never does, negative when it
    /// already has.
    pub fn expires_in(&self, now: OffsetDateTime) -> Option<time::Duration> {
        self.expires_at.map(|t| t - now)
    }

    /// Effective ceiling: a token may tighten a global limit but never raise it.
    pub fn effective_max_vouchers(&self, global: &Limits) -> u32 {
        self.max_vouchers_per_request
            .map_or(global.max_vouchers_per_request, |v| {
                v.min(global.max_vouchers_per_request)
            })
    }

    pub fn effective_max_validity(&self, global: &Limits) -> u64 {
        self.max_validity_minutes
            .map_or(global.max_validity_minutes, |v| {
                v.min(global.max_validity_minutes)
            })
    }

    pub fn effective_rate_limit(&self, global: &Limits) -> u32 {
        match (self.rate_limit_per_minute, global.rate_limit_per_minute) {
            (Some(t), 0) => t,
            (Some(t), g) => t.min(g),
            (None, g) => g,
        }
    }
}

fn default_bind() -> SocketAddr {
    "0.0.0.0:8080".parse().expect("valid default bind address")
}
fn default_timeout() -> Duration {
    Duration::from_secs(15)
}
fn default_body_limit() -> usize {
    64 * 1024
}
fn default_max_vouchers() -> u32 {
    10
}
fn default_max_validity() -> u64 {
    60 * 24 * 30 // 30 days
}
/// Generous next to the per-token default of 60: this is a flood stop, not a
/// quota, and it must not bite a client that is behaving.
fn default_pre_auth_rate_limit() -> u32 {
    120
}

fn default_rate_limit() -> u32 {
    60
}
fn default_sites() -> Vec<String> {
    vec!["*".to_string()]
}
fn default_scopes() -> Vec<Scope> {
    vec![
        Scope::SitesRead,
        Scope::VouchersRead,
        Scope::VouchersCreate,
        Scope::VouchersRevoke,
    ]
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            upstream_timeout: default_timeout(),
            max_body_bytes: default_body_limit(),
            graphql_playground: false,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_vouchers_per_request: default_max_vouchers(),
            max_validity_minutes: default_max_validity(),
            rate_limit_per_minute: default_rate_limit(),
            rate_limit_per_ip_per_minute: default_pre_auth_rate_limit(),
        }
    }
}

impl Config {
    /// Loads TOML (if present) and overlays `UVP_*` env vars. `__` separates
    /// nesting levels, so `UVP_CONTROLLER__API_KEY` sets `controller.api_key`.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let mut figment = Figment::new();
        if let Some(p) = path {
            if !p.exists() {
                bail!("config file not found: {}", p.display());
            }
            figment = figment.merge(Toml::file(p));
        }
        let config: Config = figment
            // UVP_LOG and UVP_LOG_FORMAT steer tracing, not this struct, and
            // `deny_unknown_fields` would otherwise refuse to start with them set.
            .merge(
                Env::prefixed("UVP_")
                    .split("__")
                    .ignore(&["LOG", "LOG_FORMAT"]),
            )
            .extract()
            .context("invalid configuration")?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.controller.api_key.is_empty() {
            bail!("controller.api_key is empty — set it in the config file or via UVP_CONTROLLER__API_KEY");
        }
        if self.tokens.is_empty() {
            bail!("no tokens configured — the proxy would reject every request; add at least one [[tokens]] entry (generate one with `unifi-voucher-proxy hash-token`)");
        }
        for t in &self.tokens {
            if t.name.trim().is_empty() {
                bail!("every token needs a non-empty name (it is what shows up in the audit log)");
            }
            if !t.hash.starts_with("$argon2") {
                bail!(
                    "token '{}' has a hash that is not an Argon2 PHC string — store the output of `unifi-voucher-proxy hash-token`, not the token itself",
                    t.name
                );
            }
            if t.scopes.is_empty() {
                bail!("token '{}' has no scopes and could do nothing", t.name);
            }
        }
        let tls = &self.controller.tls;
        if tls.insecure_skip_verify && tls.fingerprint_sha256.is_some() {
            bail!(
                "controller.tls: set either fingerprint_sha256 or insecure_skip_verify, not both"
            );
        }
        // A plaintext controller URL puts the full-control API key on the wire
        // in the clear, which is precisely what this proxy exists to prevent.
        // Refused unless the operator says otherwise in so many words.
        if self.controller.is_plaintext() && !tls.allow_plaintext {
            bail!(
                "controller.host is {} — the API key would travel unencrypted. Use https://, or set controller.tls.allow_plaintext = true if a TLS-terminating sidecar on this host is doing the encryption",
                self.controller.host.trim()
            );
        }
        // An empty pin is not a pin. `serve` catches this when it builds the
        // TLS config; catching it here means `check-config` agrees.
        if let Some(fps) = &tls.fingerprint_sha256 {
            if fps.is_empty() {
                bail!("controller.tls.fingerprint_sha256 is an empty list — remove the key to fall back to WebPKI verification, or put a fingerprint in it");
            }
            for fp in fps {
                crate::tls::normalize_fingerprint(fp)
                    .context("controller.tls.fingerprint_sha256 is not usable")?;
            }
        }
        Ok(())
    }
}
