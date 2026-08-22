use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tokio::signal;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use unifi_voucher_proxy::{auth, config::Config, routes, state::AppState, tls};

#[derive(Parser)]
#[command(
    name = "unifi-voucher-proxy",
    version,
    about = "A scoped, auditable proxy for the UniFi Network Integration API",
    long_about = "Holds your full-control UniFi API key so voucher apps never have to. \
                  Clients get their own tokens, limited to hotspot voucher operations \
                  on the sites you allow."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the proxy (default).
    Serve {
        #[arg(short, long, env = "UVP_CONFIG", default_value = "config.toml")]
        config: PathBuf,
    },
    /// Mint a client token — or hash one you chose yourself — and print the
    /// config snippet for it.
    HashToken {
        /// Label for the token; shows up in every audit line.
        #[arg(short, long, default_value = "client")]
        name: String,

        /// Use this key instead of generating one. Beware: it lands in your
        /// shell history — prefer --stdin.
        #[arg(short, long, conflicts_with = "stdin")]
        token: Option<String>,

        /// Read the key from stdin, so it never appears in the process list or
        /// shell history: `printf %s "$KEY" | unifi-voucher-proxy hash-token --stdin`
        #[arg(long)]
        stdin: bool,

        /// Hash a key that failed the strength check anyway.
        #[arg(long)]
        allow_weak: bool,
    },
    /// Read the controller's TLS certificate fingerprint, for pinning.
    FetchFingerprint {
        /// Controller host, e.g. 192.168.1.1
        #[arg(short = 'H', long, env = "UVP_CONTROLLER__HOST")]
        host: String,
    },
    /// Probe a running instance's /healthz. Exits non-zero when unhealthy —
    /// this is what the container HEALTHCHECK runs, since the image has no shell.
    Healthcheck {
        #[arg(
            long,
            env = "UVP_HEALTHCHECK_URL",
            default_value = "http://127.0.0.1:8080/healthz"
        )]
        url: String,
    },
    /// Validate a config file and print what it grants, without starting up.
    CheckConfig {
        #[arg(short, long, env = "UVP_CONFIG", default_value = "config.toml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    match Cli::parse().command {
        Some(Command::HashToken {
            name,
            token,
            stdin,
            allow_weak,
        }) => hash_token(&name, token, stdin, allow_weak),
        Some(Command::FetchFingerprint { host }) => fetch_fingerprint(&host).await,
        Some(Command::Healthcheck { url }) => healthcheck(&url).await,
        Some(Command::CheckConfig { config }) => check_config(&config),
        Some(Command::Serve { config }) => serve(&config).await,
        None => serve(&PathBuf::from("config.toml")).await,
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("UVP_LOG")
        .unwrap_or_else(|_| EnvFilter::new("unifi_voucher_proxy=info,audit=info,warn"));
    let registry = tracing_subscriber::registry().with(filter);
    // Structured output is the right default for a container; a human running
    // it in a terminal gets the readable form.
    if std::env::var("UVP_LOG_FORMAT").as_deref() == Ok("json") {
        registry
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        registry.with(tracing_subscriber::fmt::layer()).init();
    }
}

async fn serve(path: &Path) -> Result<()> {
    let cfg = Config::load(Some(path))?;
    warn_about_weak_settings(&cfg);

    let state = AppState::new(&cfg)?;
    let app = routes::router_with(
        state,
        cfg.server.max_body_bytes,
        cfg.server.graphql_playground,
    );

    let listener = TcpListener::bind(cfg.server.bind)
        .await
        .with_context(|| format!("cannot bind {}", cfg.server.bind))?;

    tracing::info!(
        bind = %cfg.server.bind,
        controller = %cfg.controller.host,
        tokens = cfg.tokens.len(),
        pinned = cfg.controller.tls.fingerprint_sha256.is_some(),
        "unifi-voucher-proxy {} listening",
        env!("CARGO_PKG_VERSION")
    );

    // `into_make_service_with_connect_info` is what puts the peer address in
    // the request extensions; without it the pre-auth rate limit has no key to
    // count against and silently does nothing.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server error")
}

/// Configuration that works but weakens the guarantees is called out on every
/// start, not silently accepted.
fn warn_about_weak_settings(cfg: &Config) {
    if cfg.controller.tls.insecure_skip_verify {
        tracing::warn!(
            "controller.tls.insecure_skip_verify is on — the connection to the controller is \
             unauthenticated and an on-path attacker could capture the API key. Run \
             `unifi-voucher-proxy fetch-fingerprint` and pin the certificate instead."
        );
    }
    if cfg.controller.tls.allow_plaintext && cfg.controller.is_plaintext() {
        tracing::warn!(
            "controller.host is plaintext http:// and allow_plaintext is on — the full-control \
             API key travels unencrypted. This is only safe if a TLS-terminating sidecar on this \
             host is doing the encryption."
        );
    }
    if cfg.limits.rate_limit_per_ip_per_minute == 0 {
        tracing::warn!(
            "limits.rate_limit_per_ip_per_minute is 0 — nothing bounds how much Argon2 work an \
             unauthenticated caller can trigger. Leave this on unless something in front of the \
             proxy already limits by source address."
        );
    }
    for t in &cfg.tokens {
        if t.sites.iter().any(|s| s == "*") {
            tracing::warn!(
                token = %t.name,
                "token may use every site on the controller; consider listing site ids explicitly"
            );
        }
    }
}

fn hash_token(
    name: &str,
    custom: Option<String>,
    from_stdin: bool,
    allow_weak: bool,
) -> Result<()> {
    let supplied = match (custom, from_stdin) {
        (Some(t), _) => Some(t),
        (None, true) => {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("failed to read the key from stdin")?;
            // Only a trailing newline is stripped; a key may legitimately end
            // in a space, and silently trimming it would break authentication
            // in a way that is miserable to debug.
            Some(buf.trim_end_matches(['\n', '\r']).to_string())
        }
        (None, false) => None,
    };

    let (token, generated) = match supplied {
        Some(t) => {
            match auth::assess_strength(&t) {
                Ok(bits) => tracing::info!("custom key accepted (~{bits:.0} bits of entropy)"),
                Err(why) if allow_weak => {
                    tracing::warn!(
                        "custom key is weak ({why}) — accepted because --allow-weak was given"
                    );
                }
                Err(why) => {
                    anyhow::bail!(
                        "refusing to hash this key: {why}.\n\
                         This key is the only thing between a client and your controller. \
                         Pass --allow-weak to override, or omit --token to have one generated."
                    );
                }
            }
            (t, false)
        }
        None => (auth::generate_token()?.0, true),
    };

    let hash = auth::hash_token(&token)?;
    println!("Add this to your config.toml:\n");
    println!("[[tokens]]");
    println!("name = \"{name}\"");
    println!("hash = \"{hash}\"");
    println!("sites = [\"*\"]              # replace with explicit site ids where you can");
    println!(
        "scopes = [\"sites:read\", \"vouchers:read\", \"vouchers:create\", \"vouchers:revoke\"]"
    );
    if generated {
        println!("\nGive this token to the client — it is shown once and is not recoverable:\n");
        println!("  {token}\n");
    } else {
        println!("\nOnly the hash is stored. Keep your key wherever you keep your other secrets;");
        println!("it cannot be recovered from the config.\n");
    }
    Ok(())
}

async fn fetch_fingerprint(host: &str) -> Result<()> {
    let base = if host.starts_with("http://") || host.starts_with("https://") {
        host.trim_end_matches('/').to_string()
    } else {
        format!("https://{}", host.trim_end_matches('/'))
    };
    let url = format!("{base}/proxy/network/integration/v1/sites");
    let fp = tls::probe_fingerprint(&url, Duration::from_secs(10)).await?;
    println!("Certificate fingerprint for {base}:\n");
    println!("  {fp}\n");
    println!("Put it in your config.toml:\n");
    println!("[controller.tls]");
    println!("fingerprint_sha256 = \"{fp}\"");
    Ok(())
}

async fn healthcheck(url: &str) -> Result<()> {
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls::client_config(&Default::default())?)
        .timeout(Duration::from_secs(5))
        .build()
        .context("failed to build the healthcheck client")?;
    let res = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("{url} is not answering"))?;
    if res.status().is_success() {
        Ok(())
    } else {
        anyhow::bail!("{url} answered HTTP {}", res.status().as_u16())
    }
}

fn check_config(path: &Path) -> Result<()> {
    let cfg = Config::load(Some(path))?;
    println!("Config OK: {}\n", path.display());
    println!("  controller     {}", cfg.controller.host);
    println!(
        "  tls            {}",
        if cfg.controller.is_plaintext() {
            "NONE — plaintext http://, the API key travels unencrypted".to_string()
        } else {
            match (
                &cfg.controller.tls.fingerprint_sha256,
                cfg.controller.tls.insecure_skip_verify,
            ) {
                (Some(fp), _) => format!("pinned to {fp}"),
                (None, true) => "INSECURE — certificate not verified".to_string(),
                (None, false) => "standard WebPKI verification".to_string(),
            }
        }
    );
    println!("  bind           {}", cfg.server.bind);
    println!(
        "  global limits  {} vouchers/request, {} min validity, {} req/min",
        cfg.limits.max_vouchers_per_request,
        cfg.limits.max_validity_minutes,
        cfg.limits.rate_limit_per_minute
    );
    println!(
        "  pre-auth       {}",
        match cfg.limits.rate_limit_per_ip_per_minute {
            0 => "UNLIMITED — an unauthenticated caller can spend Argon2 time freely".to_string(),
            n => format!("{n} req/min per client IP"),
        }
    );
    println!("\n  tokens ({}):", cfg.tokens.len());
    for t in &cfg.tokens {
        auth::load_hash_check(&t.hash)?;
        println!(
            "    {:<16} sites={:<24} scopes={} (max {} vouchers, {} min, {} req/min)",
            t.name,
            t.sites.join(","),
            t.scopes
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(","),
            t.effective_max_vouchers(&cfg.limits),
            t.effective_max_validity(&cfg.limits),
            t.effective_rate_limit(&cfg.limits),
        );
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to listen for ctrl-c");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to listen for SIGTERM")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutting down");
}
