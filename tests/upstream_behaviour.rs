//! How the proxy handles what the controller actually sends back.
//!
//! Firmware revisions differ in how they answer, and a proxy that turns an
//! odd-but-harmless response into a 500 is worse than no proxy. These tests pin
//! the translation from upstream reply to client-visible result.

use std::time::Duration;

use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use unifi_voucher_proxy::config::{ControllerConfig, TlsConfig};
use unifi_voucher_proxy::secret::Secret;
use unifi_voucher_proxy::upstream::Upstream;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const API: &str = "/proxy/network/integration/v1";

fn upstream_for(uri: &str, timeout: Duration) -> Upstream {
    Upstream::new(
        &ControllerConfig {
            host: uri.to_string(),
            api_key: Secret::new("upstream-key"),
            tls: TlsConfig::default(),
        },
        timeout,
    )
    .unwrap()
}

#[tokio::test]
async fn revoking_a_voucher_reaches_the_right_path() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path(format!("{API}/sites/default/hotspot/vouchers/abc123")))
        .and(header("x-api-key", "upstream-key"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let upstream = upstream_for(&server.uri(), Duration::from_secs(5));
    upstream.delete_voucher("default", "abc123").await.unwrap();
}

#[tokio::test]
async fn an_empty_success_body_is_not_an_error() {
    // DELETE commonly answers 200 with no body at all.
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let upstream = upstream_for(&server.uri(), Duration::from_secs(5));
    let body = upstream.delete_voucher("default", "v1").await.unwrap();
    assert!(body.is_null());
}

#[tokio::test]
async fn a_non_json_success_body_is_not_an_error_either() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>oops</html>"))
        .mount(&server)
        .await;

    let upstream = upstream_for(&server.uri(), Duration::from_secs(5));
    assert!(upstream.list_sites().await.unwrap().is_null());
}

#[tokio::test]
async fn a_rejected_key_is_reported_as_the_proxys_problem_not_the_clients() {
    // The client's own token was fine; it is the proxy's upstream key that the
    // controller refused, and the message should say so.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let upstream = upstream_for(&server.uri(), Duration::from_secs(5));
    let err = upstream.list_sites().await.unwrap_err();
    assert!(
        err.to_string().contains("rejected the proxy's API key"),
        "{err}"
    );
}

#[tokio::test]
async fn an_unexplained_upstream_failure_still_names_its_status() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let upstream = upstream_for(&server.uri(), Duration::from_secs(5));
    let err = upstream.list_sites().await.unwrap_err();
    assert!(err.to_string().contains("503"), "{err}");
    assert_eq!(err.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn the_controllers_own_message_is_preferred_when_it_gives_one() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(json!({"message": "count must be positive"})),
        )
        .mount(&server)
        .await;

    let upstream = upstream_for(&server.uri(), Duration::from_secs(5));
    let err = upstream
        .create_vouchers("default", &json!({"name": "x"}))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("count must be positive"));
}

#[tokio::test]
async fn a_slow_controller_times_out_rather_than_hanging_the_client() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&server)
        .await;

    let upstream = upstream_for(&server.uri(), Duration::from_millis(200));
    let err = upstream.list_sites().await.unwrap_err();
    assert!(err.to_string().contains("timed out"), "{err}");
}

#[tokio::test]
async fn an_unintelligible_reply_is_reported_without_guessing() {
    // A raw socket that answers with something that is not HTTP at all. The
    // proxy should fail plainly rather than mislabel it as a connection or
    // certificate problem.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream.write_all(b"NOT-HTTP\r\n\r\n").await;
            let _ = stream.shutdown().await;
        }
    });

    let upstream = upstream_for(&format!("http://{addr}"), Duration::from_secs(2));
    let err = upstream.list_sites().await.unwrap_err();
    assert_eq!(err.status(), axum::http::StatusCode::BAD_GATEWAY);
    assert!(err.to_string().contains("request failed"), "{err}");
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    // Following one would let a compromised console bounce the API key to any
    // host it likes.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "http://attacker.example/steal"),
        )
        .mount(&server)
        .await;

    let upstream = upstream_for(&server.uri(), Duration::from_secs(5));
    let err = upstream.list_sites().await.unwrap_err();
    assert_eq!(err.status(), axum::http::StatusCode::FOUND);
}

#[tokio::test]
async fn a_plain_http_host_is_left_alone() {
    // `http://` is preserved rather than upgraded, so a proxy talking to a
    // controller over a trusted local link still works.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{API}/sites")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;

    assert!(upstream_for(&server.uri(), Duration::from_secs(5))
        .list_sites()
        .await
        .is_ok());
}
