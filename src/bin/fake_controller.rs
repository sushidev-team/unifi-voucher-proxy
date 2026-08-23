//! A stand-in UniFi console for local development.
//!
//! Speaks the four Integration API calls the proxy forwards, over TLS with a
//! self-signed certificate — like a real console, so certificate pinning is
//! exercised rather than skipped.
//!
//! It exists because the real thing is awkward to develop against: the
//! Integration API is a UniFi OS feature, so a Docker `unifi-network-application`
//! does not have it at all, and a real console cannot easily be made to return a
//! 401, time out, or hand back a differently-shaped envelope on demand.
//!
//! Deliberately a separate binary behind the `testing` feature. The proxy's
//! whole claim is that it only ever forwards four named calls; a mode inside it
//! that fabricates answers would make that claim conditional, and a
//! misconfigured deployment would hand out voucher codes that do not work.
//!
//!     cargo run --features testing --bin fake-controller
//!
//! Quirks reproduced on purpose, because each one has cost us a bug:
//!   * `POST` answers `{"vouchers": [...]}` while `GET` answers `{"data": [...]}`
//!   * vouchers carry no `expiresAt`
//!   * the list endpoint ignores paging beyond `limit`

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;
use serde_json::{json, Value};

#[derive(Parser)]
#[command(
    name = "fake-controller",
    about = "A stand-in UniFi console for developing against, with a self-signed certificate"
)]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:8443")]
    bind: SocketAddr,

    /// The key it accepts. Anything else gets a 401, so the proxy's own
    /// "controller rejected our key" path is reachable without breaking a real
    /// console.
    #[arg(long, default_value = "test-api-key")]
    api_key: String,

    /// Reject every request, to exercise the proxy's upstream-auth failure path.
    #[arg(long)]
    always_401: bool,

    /// Delay every response, to exercise upstream timeouts.
    #[arg(long, default_value_t = 0)]
    delay_ms: u64,

    /// Print the certificate fingerprint and exit — the value to pin.
    #[arg(long)]
    print_fingerprint: bool,
}

#[derive(Clone)]
struct Voucher {
    id: String,
    code: String,
    name: String,
    time_limit_minutes: u64,
    authorized_guest_limit: u32,
}

impl Voucher {
    fn to_json(&self) -> Value {
        // No `expiresAt`: the live API does not send one, and assuming it did
        // is exactly the sort of thing this fake exists to keep honest.
        json!({
            "id": self.id,
            "code": self.code,
            "name": self.name,
            "timeLimitMinutes": self.time_limit_minutes,
            "authorizedGuestLimit": self.authorized_guest_limit,
            "authorizedGuestCount": 0,
            "expired": false,
            "createdAt": "2026-01-01T00:00:00Z",
        })
    }
}

struct Console {
    cfg: Cli,
    vouchers: RwLock<HashMap<String, Vec<Voucher>>>,
    next: AtomicU64,
}

type Shared = Arc<Console>;

const SITE_ID: &str = "default";

impl Console {
    /// Mirrors the real API: any key that is not the configured one is a 401
    /// with the same envelope, so error handling is exercised for real.
    fn check(&self, headers: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
        if self.cfg.always_401 {
            return Err(unauthorized());
        }
        let ok = headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == self.cfg.api_key);
        if ok { Ok(()) } else { Err(unauthorized()) }
    }

    async fn pause(&self) {
        if self.cfg.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.cfg.delay_ms)).await;
        }
    }
}

fn unauthorized() -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"message": "Unauthorized"})),
    )
}

type Reply = Result<Json<Value>, (StatusCode, Json<Value>)>;

async fn list_sites(State(s): State<Shared>, headers: HeaderMap) -> Reply {
    s.check(&headers)?;
    s.pause().await;
    Ok(Json(json!({
        "data": [{ "id": SITE_ID, "name": "Default", "internalReference": "default" }]
    })))
}

async fn list_vouchers(
    State(s): State<Shared>,
    headers: HeaderMap,
    Path(site): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Reply {
    s.check(&headers)?;
    s.pause().await;
    let limit: usize = q
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
        .min(1000);
    let store = s.vouchers.read().expect("voucher store poisoned");
    let rows: Vec<Value> = store
        .get(&site)
        .map(|v| v.iter().take(limit).map(Voucher::to_json).collect())
        .unwrap_or_default();
    // Reads use the `data` envelope.
    Ok(Json(json!({ "data": rows })))
}

async fn create_vouchers(
    State(s): State<Shared>,
    headers: HeaderMap,
    Path(site): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    s.check(&headers)?;
    s.pause().await;

    let count = body.get("count").and_then(Value::as_u64).unwrap_or(1);
    let minutes = body
        .get("timeLimitMinutes")
        .and_then(Value::as_u64)
        .unwrap_or(60);
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("Voucher")
        .to_string();
    let guests = body
        .get("authorizedGuestLimit")
        .and_then(Value::as_u64)
        .unwrap_or(1) as u32;

    if minutes == 0 || minutes > 1_000_000 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "timeLimitMinutes out of range"})),
        ));
    }

    let mut made = Vec::new();
    {
        let mut store = s.vouchers.write().expect("voucher store poisoned");
        let list = store.entry(site).or_default();
        for _ in 0..count {
            let n = s.next.fetch_add(1, Ordering::Relaxed);
            let v = Voucher {
                id: format!("v{n}"),
                // Ten digits, like the real thing — the app formats it as
                // 12345-67890 and would look wrong with anything else.
                code: format!("{:010}", 1_000_000_000u64 + n),
                name: name.clone(),
                time_limit_minutes: minutes,
                authorized_guest_limit: guests,
            };
            made.push(v.to_json());
            list.push(v);
        }
    }
    // Creates use the `vouchers` envelope. This asymmetry is real, and reading
    // it as `data` is what once made the app show the oldest voucher instead of
    // the new one.
    Ok(Json(json!({ "vouchers": made })))
}

async fn delete_voucher(
    State(s): State<Shared>,
    headers: HeaderMap,
    Path((site, id)): Path<(String, String)>,
) -> Reply {
    s.check(&headers)?;
    s.pause().await;
    let mut store = s.vouchers.write().expect("voucher store poisoned");
    let list = store.entry(site).or_default();
    let before = list.len();
    list.retain(|v| v.id != id);
    if list.len() == before {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"message": "Voucher not found"})),
        ));
    }
    Ok(Json(json!({})))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Cli::parse();

    // A self-signed certificate, like every UniFi console ships with — so the
    // proxy's pinning is exercised here rather than only in unit tests.
    let cert = rcgen::generate_simple_self_signed(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])?;
    let der = cert.cert.der().to_vec();
    let fingerprint = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&der));

    if cfg.print_fingerprint {
        println!("{fingerprint}");
        return Ok(());
    }

    let bind = cfg.bind;
    let api_key = cfg.api_key.clone();
    let state: Shared = Arc::new(Console {
        cfg,
        vouchers: RwLock::new(HashMap::new()),
        next: AtomicU64::new(1),
    });

    const API: &str = "/proxy/network/integration/v1";
    let app = Router::new()
        .route(&format!("{API}/sites"), get(list_sites))
        .route(
            &format!("{API}/sites/{{site}}/hotspot/vouchers"),
            get(list_vouchers).post(create_vouchers),
        )
        .route(
            &format!("{API}/sites/{{site}}/hotspot/vouchers/{{id}}"),
            axum::routing::delete(delete_voucher),
        )
        .with_state(state);

    println!("fake UniFi console on https://{bind}");
    println!("  api key      {api_key}");
    println!("  fingerprint  {fingerprint}");
    println!();
    println!("Point the proxy at it:");
    println!("  UVP_CONTROLLER__HOST=https://{bind} \\");
    println!("  UVP_CONTROLLER__API_KEY={api_key} \\");
    println!("  UVP_CONTROLLER__TLS__FINGERPRINT_SHA256={fingerprint} \\");
    println!("    unifi-voucher-proxy serve --config config.toml");

    axum_server::bind_rustls(
        bind,
        axum_server::tls_rustls::RustlsConfig::from_der(
            vec![der],
            cert.key_pair.serialize_der(),
        )
        .await?,
    )
    .serve(app.into_make_service())
    .await?;
    Ok(())
}
