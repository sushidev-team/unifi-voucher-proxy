//! End-to-end tests against a stubbed UniFi controller.
//!
//! These are the tests that matter for the project's premise: that a client
//! holding a proxy token cannot reach anything on the controller except the
//! voucher operations it was granted, and that the real API key never leaves
//! the proxy.

use axum_test::TestServer;
use serde_json::{json, Value};
use unifi_voucher_proxy::auth;
use unifi_voucher_proxy::config::{
    Config, ControllerConfig, Limits, Scope, ServerConfig, TlsConfig, TokenConfig,
};
use unifi_voucher_proxy::routes;
use unifi_voucher_proxy::secret::Secret;
use unifi_voucher_proxy::state::AppState;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const UPSTREAM_KEY: &str = "REAL-UNIFI-API-KEY-DO-NOT-LEAK";
const API: &str = "/proxy/network/integration/v1";

struct Harness {
    server: TestServer,
    token: String,
    upstream: MockServer,
}

/// Builds a proxy wired to a stub controller. `tokens` describes the callers.
async fn harness(build: impl FnOnce(&mut TokenConfig)) -> Harness {
    let upstream = MockServer::start().await;
    let (token, hash) = auth::generate_token().unwrap();

    let mut token_cfg = TokenConfig {
        name: "test-client".into(),
        hash,
        sites: vec!["*".into()],
        scopes: vec![
            Scope::SitesRead,
            Scope::VouchersRead,
            Scope::VouchersCreate,
            Scope::VouchersRevoke,
        ],
        max_vouchers_per_request: None,
        max_validity_minutes: None,
        rate_limit_per_minute: Some(0),
    };
    build(&mut token_cfg);

    let cfg = Config {
        server: ServerConfig::default(),
        controller: ControllerConfig {
            host: upstream.uri(),
            api_key: Secret::new(UPSTREAM_KEY),
            tls: TlsConfig::default(),
        },
        limits: Limits {
            max_vouchers_per_request: 10,
            max_validity_minutes: 1440,
            rate_limit_per_minute: 0,
        },
        tokens: vec![token_cfg],
    };

    let state = AppState::new(&cfg).unwrap();
    let app = routes::router(state, cfg.server.max_body_bytes);
    Harness {
        server: TestServer::new(app).unwrap(),
        token,
        upstream,
    }
}

async fn default_harness() -> Harness {
    harness(|_| {}).await
}

// --- the allowlist ---------------------------------------------------------

#[tokio::test]
async fn refuses_every_path_it_does_not_explicitly_serve() {
    let h = default_harness().await;

    // A representative slice of what a full-control key could otherwise reach.
    let blocked = [
        "/proxy/network/integration/v1/sites/default/devices",
        "/proxy/network/integration/v1/sites/default/clients",
        "/proxy/network/integration/v1/sites/default/firewall/rules",
        "/proxy/network/api/s/default/rest/wlanconf",
        "/api/self",
        "/api/auth/login",
        "/proxy/network/integration/v1",
        "/",
    ];

    for p in blocked {
        let res = h.server.get(p).add_header("x-api-key", &h.token).await;
        assert_eq!(
            res.status_code(),
            403,
            "{p} should have been refused, got {}",
            res.status_code()
        );
    }

    // Nothing reached the controller at all.
    assert!(
        h.upstream.received_requests().await.unwrap().is_empty(),
        "blocked paths must not produce upstream traffic"
    );
}

#[tokio::test]
async fn refuses_write_verbs_on_allowed_read_paths() {
    let h = default_harness().await;
    for res in [
        h.server
            .put(&format!("{API}/sites"))
            .add_header("x-api-key", &h.token)
            .await,
        h.server
            .delete(&format!("{API}/sites"))
            .add_header("x-api-key", &h.token)
            .await,
    ] {
        assert_eq!(res.status_code(), 403);
    }
}

// --- authentication --------------------------------------------------------

#[tokio::test]
async fn rejects_missing_and_wrong_tokens() {
    let h = default_harness().await;

    let anon = h.server.get(&format!("{API}/sites")).await;
    assert_eq!(anon.status_code(), 401);

    let wrong = h
        .server
        .get(&format!("{API}/sites"))
        .add_header("x-api-key", "uvp_definitely-not-valid")
        .await;
    assert_eq!(wrong.status_code(), 401);

    // Notably: presenting the controller's real key to the proxy is not a way in.
    let upstream_key = h
        .server
        .get(&format!("{API}/sites"))
        .add_header("x-api-key", UPSTREAM_KEY)
        .await;
    assert_eq!(upstream_key.status_code(), 401);

    assert!(h.upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn healthz_needs_no_token_and_says_nothing_useful() {
    let h = default_harness().await;
    let res = h.server.get("/healthz").await;
    res.assert_status_ok();
    let body: Value = res.json();
    assert_eq!(body["status"], "ok");
    assert!(!body.to_string().contains(UPSTREAM_KEY));
}

// --- the key stays home ----------------------------------------------------

#[tokio::test]
async fn forwards_the_real_key_upstream_and_never_back_to_the_client() {
    let h = default_harness().await;
    Mock::given(method("GET"))
        .and(path(format!("{API}/sites")))
        .and(header("x-api-key", UPSTREAM_KEY))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "default", "name": "Default"}]
        })))
        .expect(1)
        .mount(&h.upstream)
        .await;

    let res = h
        .server
        .get(&format!("{API}/sites"))
        .add_header("x-api-key", &h.token)
        .await;
    res.assert_status_ok();

    let text = res.text();
    assert!(text.contains("default"));
    assert!(
        !text.contains(UPSTREAM_KEY),
        "the controller key must never appear in a client response"
    );
    assert!(
        !text.contains(&h.token),
        "the client token must not be echoed either"
    );
}

// --- scopes ----------------------------------------------------------------

#[tokio::test]
async fn a_read_only_token_cannot_create_or_revoke() {
    let h = harness(|t| t.scopes = vec![Scope::SitesRead, Scope::VouchersRead]).await;

    let create = h
        .server
        .post(&format!("{API}/sites/default/hotspot/vouchers"))
        .add_header("x-api-key", &h.token)
        .json(&json!({"name": "Guest", "count": 1, "timeLimitMinutes": 60}))
        .await;
    assert_eq!(create.status_code(), 403);
    assert!(create.text().contains("vouchers:create"));

    let revoke = h
        .server
        .delete(&format!("{API}/sites/default/hotspot/vouchers/abc123"))
        .add_header("x-api-key", &h.token)
        .await;
    assert_eq!(revoke.status_code(), 403);

    assert!(h.upstream.received_requests().await.unwrap().is_empty());
}

// --- site scoping ----------------------------------------------------------

#[tokio::test]
async fn a_site_scoped_token_cannot_touch_another_site() {
    let h = harness(|t| t.sites = vec!["guest-site".into()]).await;

    let res = h
        .server
        .get(&format!("{API}/sites/corporate/hotspot/vouchers"))
        .add_header("x-api-key", &h.token)
        .await;
    assert_eq!(res.status_code(), 403);
    assert!(h.upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_site_scoped_token_is_not_told_the_other_sites_exist() {
    let h = harness(|t| t.sites = vec!["guest-site".into()]).await;
    Mock::given(method("GET"))
        .and(path(format!("{API}/sites")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"id": "guest-site", "name": "Guest"},
                {"id": "corporate", "name": "HQ"}
            ]
        })))
        .mount(&h.upstream)
        .await;

    let res = h
        .server
        .get(&format!("{API}/sites"))
        .add_header("x-api-key", &h.token)
        .await;
    res.assert_status_ok();
    let body: Value = res.json();
    let sites = body["data"].as_array().unwrap();
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0]["id"], "guest-site");
    assert!(!res.text().contains("corporate"));
}

// --- request policy --------------------------------------------------------

#[tokio::test]
async fn enforces_the_voucher_ceiling_before_calling_the_controller() {
    let h = harness(|t| t.max_vouchers_per_request = Some(3)).await;

    let res = h
        .server
        .post(&format!("{API}/sites/default/hotspot/vouchers"))
        .add_header("x-api-key", &h.token)
        .json(&json!({"name": "Guest", "count": 100, "timeLimitMinutes": 60}))
        .await;
    assert_eq!(res.status_code(), 403);
    assert!(h.upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn strips_nothing_and_forwards_a_canonical_body() {
    let h = default_harness().await;
    Mock::given(method("POST"))
        .and(path(format!("{API}/sites/default/hotspot/vouchers")))
        .and(header("x-api-key", UPSTREAM_KEY))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "vouchers": [{"id": "v1", "code": "1234567"}]
        })))
        .expect(1)
        .mount(&h.upstream)
        .await;

    let res = h
        .server
        .post(&format!("{API}/sites/default/hotspot/vouchers"))
        .add_header("x-api-key", &h.token)
        .json(&json!({
            "name": "Guest", "count": 2, "timeLimitMinutes": 480, "authorizedGuestLimit": 1
        }))
        .await;
    res.assert_status_ok();

    let received = &h.upstream.received_requests().await.unwrap()[0];
    let sent: Value = serde_json::from_slice(&received.body).unwrap();
    assert_eq!(sent["count"], 2);
    assert_eq!(sent["timeLimitMinutes"], 480);
    assert_eq!(sent["name"], "Guest");
}

#[tokio::test]
async fn refuses_bodies_carrying_fields_it_does_not_know() {
    let h = default_harness().await;
    let res = h
        .server
        .post(&format!("{API}/sites/default/hotspot/vouchers"))
        .add_header("x-api-key", &h.token)
        .json(&json!({
            "name": "Guest", "count": 1, "timeLimitMinutes": 60,
            "note": "smuggled", "adminOverride": true
        }))
        .await;
    assert_eq!(res.status_code(), 400);
    assert!(h.upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn refuses_ids_that_try_to_leave_the_voucher_namespace() {
    let h = default_harness().await;
    for id in ["..%2f..%2fapi%2fself", "abc%3Flimit%3D1", "a%20b"] {
        let res = h
            .server
            .delete(&format!("{API}/sites/default/hotspot/vouchers/{id}"))
            .add_header("x-api-key", &h.token)
            .await;
        assert_eq!(res.status_code(), 400, "id {id} should have been refused");
    }
    assert!(h.upstream.received_requests().await.unwrap().is_empty());
}

// --- rate limiting ---------------------------------------------------------

#[tokio::test]
async fn stops_a_token_that_exceeds_its_quota() {
    let h = harness(|t| t.rate_limit_per_minute = Some(2)).await;
    Mock::given(method("GET"))
        .and(path(format!("{API}/sites")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&h.upstream)
        .await;

    for _ in 0..2 {
        let res = h
            .server
            .get(&format!("{API}/sites"))
            .add_header("x-api-key", &h.token)
            .await;
        res.assert_status_ok();
    }
    let blocked = h
        .server
        .get(&format!("{API}/sites"))
        .add_header("x-api-key", &h.token)
        .await;
    assert_eq!(blocked.status_code(), 429);
}

// --- upstream behaviour ----------------------------------------------------

#[tokio::test]
async fn passes_controller_errors_through_without_leaking_detail() {
    let h = default_harness().await;
    Mock::given(method("GET"))
        .and(path(format!("{API}/sites/default/hotspot/vouchers")))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"message": "Unauthorized", "key": UPSTREAM_KEY})),
        )
        .mount(&h.upstream)
        .await;

    let res = h
        .server
        .get(&format!("{API}/sites/default/hotspot/vouchers"))
        .add_header("x-api-key", &h.token)
        .await;
    assert_eq!(res.status_code(), 401);
    assert!(
        !res.text().contains(UPSTREAM_KEY),
        "an upstream body must not be relayed verbatim"
    );
}

#[tokio::test]
async fn info_tells_a_client_exactly_what_it_may_do() {
    let h = harness(|t| {
        t.sites = vec!["guest-site".into()];
        t.scopes = vec![Scope::VouchersRead, Scope::VouchersCreate];
        t.max_vouchers_per_request = Some(5);
    })
    .await;

    let res = h
        .server
        .get("/proxy/info")
        .add_header("x-api-key", &h.token)
        .await;
    res.assert_status_ok();
    let body: Value = res.json();
    assert_eq!(body["token"], "test-client");
    assert_eq!(body["sites"][0], "guest-site");
    assert_eq!(body["limits"]["maxVouchersPerRequest"], 5);
    let scopes = body["scopes"].as_array().unwrap();
    assert!(scopes.iter().any(|s| s == "vouchers:read"));
    assert!(!scopes.iter().any(|s| s == "vouchers:revoke"));
}

#[tokio::test]
async fn a_site_response_in_an_unexpected_shape_is_passed_through_untouched() {
    // Site filtering must not silently swallow a response it cannot interpret:
    // returning an empty list would look like "you have no sites" and send the
    // operator hunting in the wrong place.
    let h = harness(|t| t.sites = vec!["guest-site".into()]).await;
    Mock::given(method("GET"))
        .and(path(format!("{API}/sites")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"meta": {"rc": "ok"}})))
        .mount(&h.upstream)
        .await;

    let res = h
        .server
        .get(&format!("{API}/sites"))
        .add_header("x-api-key", &h.token)
        .await;
    res.assert_status_ok();
    assert_eq!(res.json::<Value>()["meta"]["rc"], "ok");
}

#[tokio::test]
async fn a_wildcard_token_sees_the_site_list_unfiltered() {
    let h = default_harness().await;
    Mock::given(method("GET"))
        .and(path(format!("{API}/sites")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": [
            {"id": "a", "name": "A"}, {"id": "b", "name": "B"}
        ]})))
        .mount(&h.upstream)
        .await;

    let res = h
        .server
        .get(&format!("{API}/sites"))
        .add_header("x-api-key", &h.token)
        .await;
    assert_eq!(res.json::<Value>()["data"].as_array().unwrap().len(), 2);
}
