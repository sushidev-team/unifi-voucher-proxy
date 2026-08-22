//! Certificate pinning, exercised against a real TLS handshake.
//!
//! Pinning is the control that stops someone on the LAN from impersonating the
//! console and collecting the API key, so it is tested against an actual
//! server presenting an actual self-signed certificate rather than a mock.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use unifi_voucher_proxy::config::{ControllerConfig, TlsConfig};
use unifi_voucher_proxy::secret::Secret;
use unifi_voucher_proxy::tls;
use unifi_voucher_proxy::upstream::Upstream;

/// A throwaway TLS server presenting a self-signed certificate, like a console.
struct StubConsole {
    addr: std::net::SocketAddr,
    fingerprint: String,
}

async fn stub_console(body: &'static str, status: u16) -> StubConsole {
    stub_console_with(body, status, None).await
}

/// As above, but pinned to one protocol version. rustls negotiates TLS 1.3 by
/// default; the 1.2 handshake takes a different code path through the custom
/// verifier, and consoles on older firmware still speak it.
async fn stub_console_with(
    body: &'static str,
    status: u16,
    version: Option<&'static rustls::SupportedProtocolVersion>,
) -> StubConsole {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let fingerprint = hex::encode(Sha256::digest(cert_der.as_ref()));
    let key = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();

    let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ));
    let builder = match version {
        Some(v) => builder.with_protocol_versions(&[v]).unwrap(),
        None => builder.with_safe_default_protocol_versions().unwrap(),
    };
    let server_config = builder
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                // Drain whatever the client sent, then answer minimally. The
                // handshake is the interesting part; the body just has to parse.
                let mut buf = [0u8; 2048];
                let _ = tls.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });

    StubConsole { addr, fingerprint }
}

fn controller(addr: std::net::SocketAddr, tls: TlsConfig) -> ControllerConfig {
    ControllerConfig {
        host: format!("https://{addr}"),
        api_key: Secret::new("upstream-key"),
        tls,
    }
}

#[tokio::test]
async fn a_matching_fingerprint_is_accepted() {
    let console = stub_console(r#"{"data":[{"id":"default","name":"Default"}]}"#, 200).await;

    let upstream = Upstream::new(
        &controller(
            console.addr,
            TlsConfig {
                fingerprint_sha256: Some(console.fingerprint.clone()),
                insecure_skip_verify: false,
                allow_plaintext: false,
            },
        ),
        Duration::from_secs(5),
    )
    .unwrap();

    let body = upstream.list_sites().await.unwrap();
    assert_eq!(body["data"][0]["id"], "default");
}

#[tokio::test]
async fn a_different_certificate_is_refused() {
    let console = stub_console("{}", 200).await;
    // A valid-looking fingerprint that is not this console's.
    let wrong = "b".repeat(64);

    let upstream = Upstream::new(
        &controller(
            console.addr,
            TlsConfig {
                fingerprint_sha256: Some(wrong),
                insecure_skip_verify: false,
                allow_plaintext: false,
            },
        ),
        Duration::from_secs(5),
    )
    .unwrap();

    let err = upstream.list_sites().await.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("fingerprint mismatch"),
        "expected a pinning failure, got: {msg}"
    );
    assert_eq!(err.status(), axum::http::StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn the_pin_survives_the_spellings_people_actually_paste() {
    let console = stub_console(r#"{"data":[]}"#, 200).await;
    let colonized = console
        .fingerprint
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(":")
        .to_uppercase();

    let upstream = Upstream::new(
        &controller(
            console.addr,
            TlsConfig {
                fingerprint_sha256: Some(format!("sha256:{colonized}")),
                insecure_skip_verify: false,
                allow_plaintext: false,
            },
        ),
        Duration::from_secs(5),
    )
    .unwrap();

    assert!(upstream.list_sites().await.is_ok());
}

#[tokio::test]
async fn insecure_mode_connects_to_anything() {
    let console = stub_console(r#"{"data":[]}"#, 200).await;

    let upstream = Upstream::new(
        &controller(
            console.addr,
            TlsConfig {
                fingerprint_sha256: None,
                insecure_skip_verify: true,
                allow_plaintext: false,
            },
        ),
        Duration::from_secs(5),
    )
    .unwrap();

    assert!(upstream.list_sites().await.is_ok());
}

#[tokio::test]
async fn the_secure_default_rejects_a_self_signed_console() {
    let console = stub_console("{}", 200).await;

    // Neither pinned nor insecure: ordinary WebPKI verification, which a
    // stock console cannot pass. Failing here is the point — it pushes the
    // operator towards pinning instead of towards turning verification off.
    let upstream = Upstream::new(
        &controller(console.addr, TlsConfig::default()),
        Duration::from_secs(5),
    )
    .unwrap();

    assert!(upstream.list_sites().await.is_err());
}

#[tokio::test]
async fn fetch_fingerprint_reports_what_the_console_presents() {
    let console = stub_console("{}", 401).await;
    let url = format!(
        "https://{}/proxy/network/integration/v1/sites",
        console.addr
    );

    // A 401 is fine: the handshake is what is being probed.
    let found = tls::probe_fingerprint(&url, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(found, console.fingerprint);
}

#[tokio::test]
async fn fetch_fingerprint_fails_clearly_when_nothing_answers() {
    // Port 1 on loopback: reliably closed.
    let err = tls::probe_fingerprint("https://127.0.0.1:1/", Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("could not open a TLS connection"));
}

#[tokio::test]
async fn a_malformed_pin_is_rejected_at_construction() {
    let err = Upstream::new(
        &controller(
            "127.0.0.1:9".parse().unwrap(),
            TlsConfig {
                fingerprint_sha256: Some("not-a-fingerprint".into()),
                insecure_skip_verify: false,
                allow_plaintext: false,
            },
        ),
        Duration::from_secs(1),
    )
    .unwrap_err();
    assert!(err.to_string().contains("fingerprint_sha256"));
}

#[tokio::test]
async fn an_unreachable_controller_is_reported_as_such() {
    let upstream = Upstream::new(
        &controller("127.0.0.1:1".parse().unwrap(), TlsConfig::default()),
        Duration::from_secs(2),
    )
    .unwrap();
    let err = upstream.list_sites().await.unwrap_err();
    assert_eq!(err.status(), axum::http::StatusCode::BAD_GATEWAY);
    assert!(err.to_string().contains("Cannot reach") || err.to_string().contains("cannot reach"));
}

#[tokio::test]
async fn pinning_works_over_tls_1_2_as_well() {
    let console = stub_console_with(
        r#"{"data":[{"id":"default"}]}"#,
        200,
        Some(&rustls::version::TLS12),
    )
    .await;

    let upstream = Upstream::new(
        &controller(
            console.addr,
            TlsConfig {
                fingerprint_sha256: Some(console.fingerprint.clone()),
                insecure_skip_verify: false,
                allow_plaintext: false,
            },
        ),
        Duration::from_secs(5),
    )
    .unwrap();

    assert_eq!(
        upstream.list_sites().await.unwrap()["data"][0]["id"],
        "default"
    );
}

#[tokio::test]
async fn a_mismatch_is_caught_over_tls_1_2_too() {
    let console = stub_console_with("{}", 200, Some(&rustls::version::TLS12)).await;

    let upstream = Upstream::new(
        &controller(
            console.addr,
            TlsConfig {
                fingerprint_sha256: Some("c".repeat(64)),
                insecure_skip_verify: false,
                allow_plaintext: false,
            },
        ),
        Duration::from_secs(5),
    )
    .unwrap();

    assert!(upstream
        .list_sites()
        .await
        .unwrap_err()
        .to_string()
        .contains("fingerprint mismatch"));
}

#[tokio::test]
async fn insecure_mode_also_works_over_tls_1_2() {
    let console = stub_console_with(r#"{"data":[]}"#, 200, Some(&rustls::version::TLS12)).await;
    let upstream = Upstream::new(
        &controller(
            console.addr,
            TlsConfig {
                fingerprint_sha256: None,
                insecure_skip_verify: true,
                allow_plaintext: false,
            },
        ),
        Duration::from_secs(5),
    )
    .unwrap();
    assert!(upstream.list_sites().await.is_ok());
}

#[tokio::test]
async fn an_untrusted_certificate_says_how_to_fix_it() {
    let console = stub_console("{}", 200).await;
    let err = Upstream::new(
        &controller(console.addr, TlsConfig::default()),
        Duration::from_secs(5),
    )
    .unwrap()
    .list_sites()
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("fetch-fingerprint"),
        "the error should point at the fix, got: {err}"
    );
}
