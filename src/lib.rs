//! A scoped, auditable proxy for the UniFi Network Integration API.
//!
//! UniFi API keys carry the full rights of the admin that created them, and
//! Ubiquiti offers no per-endpoint scoping. This proxy is the missing scope: it
//! holds the real key on hardware you control and exposes only hotspot voucher
//! operations to clients, each with its own token, site allowlist, scopes,
//! quotas and audit trail.

pub mod audit;
pub mod auth;
pub mod config;
pub mod error;
pub mod graphql;
pub mod metrics;
pub mod model;
pub mod policy;
pub mod ratelimit;
pub mod routes;
pub mod secret;
pub mod state;
pub mod tls;
pub mod upstream;

pub use config::Config;
pub use state::{AppState, SharedState};
