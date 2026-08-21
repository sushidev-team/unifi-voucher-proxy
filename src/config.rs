use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use figment::providers::{Env, Format, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};

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
    /// SHA-256 fingerprint of the controller's leaf certificate, hex encoded
    /// (colons and `sha256:` prefix are tolerated). When set, the certificate
    /// must match exactly — this is how you get a trustworthy channel to a box
    /// that ships a self-signed cert.
    pub fingerprint_sha256: Option<String>,
    /// Accept any certificate. Requires no fingerprint to be set and is loudly
    /// warned about on every startup; provided only so first-run setup can
    /// discover the fingerprint.
    #[serde(default)]
    pub insecure_skip_verify: bool,
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
            .merge(Env::prefixed("UVP_").split("__").ignore(&["LOG", "LOG_FORMAT"]))
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
        Ok(())
    }
}
