//! The GraphQL layer must not be a way around the REST layer's limits.
//!
//! Every restriction asserted in `proxy.rs` is asserted again here through
//! GraphQL, because a convenience API that quietly widens reach would defeat
//! the point of the proxy.

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

impl Harness {
    /// Posts a GraphQL document and returns the parsed response.
    async fn gql(&self, query: &str) -> Value {
        self.server
            .post("/graphql")
            .add_header("x-api-key", &self.token)
            .json(&json!({ "query": query }))
            .await
            .json()
    }

    /// Posts a document with variables, the way a generated client does.
    async fn gql_vars(&self, query: &str, variables: Value) -> Value {
        self.server
            .post("/graphql")
            .add_header("x-api-key", &self.token)
            .json(&json!({ "query": query, "variables": variables }))
            .await
            .json()
    }

    /// First error message from a GraphQL response, if any.
    fn error(res: &Value) -> Option<String> {
        res.get("errors")?
            .as_array()?
            .first()?
            .get("message")?
            .as_str()
            .map(str::to_string)
    }

    fn error_code(res: &Value) -> Option<String> {
        res.get("errors")?.as_array()?.first()?["extensions"]["code"]
            .as_str()
            .map(str::to_string)
    }
}

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
        expires_at: None,
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
            rate_limit_per_ip_per_minute: 0,
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

// --- it works at all -------------------------------------------------------

#[tokio::test]
async fn queries_vouchers_through_graphql() {
    let h = default_harness().await;
    Mock::given(method("GET"))
        .and(path(format!("{API}/sites/default/hotspot/vouchers")))
        .and(header("x-api-key", UPSTREAM_KEY))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": [
            {"id": "v1", "code": "1234567890", "name": "Guest",
             "timeLimitMinutes": 480, "authorizedGuestLimit": 2,
             "authorizedGuestCount": 1, "expired": false}
        ]})))
        .mount(&h.upstream)
        .await;

    let res = h
        .gql(r#"{ vouchers(siteId: "default") { id code name timeLimitMinutes authorizedGuestCount expired } }"#)
        .await;

    assert!(Harness::error(&res).is_none(), "{res}");
    let v = &res["data"]["vouchers"][0];
    assert_eq!(v["id"], "v1");
    assert_eq!(v["code"], "1234567890");
    assert_eq!(v["timeLimitMinutes"], 480);
    assert_eq!(v["authorizedGuestCount"], 1);
    assert_eq!(v["expired"], false);
}

#[tokio::test]
async fn creates_vouchers_through_graphql() {
    let h = default_harness().await;
    Mock::given(method("POST"))
        .and(path(format!("{API}/sites/default/hotspot/vouchers")))
        .and(header("x-api-key", UPSTREAM_KEY))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"vouchers": [
                {"id": "v9", "code": "5555500000"}
            ]})),
        )
        .expect(1)
        .mount(&h.upstream)
        .await;

    let res = h
        .gql(r#"mutation { createVouchers(siteId: "default", input: {name: "Guest", count: 1, timeLimitMinutes: 480}) { id code } }"#)
        .await;

    assert!(Harness::error(&res).is_none(), "{res}");
    assert_eq!(res["data"]["createVouchers"][0]["code"], "5555500000");

    let sent: Value =
        serde_json::from_slice(&h.upstream.received_requests().await.unwrap()[0].body).unwrap();
    assert_eq!(sent["name"], "Guest");
    assert_eq!(sent["timeLimitMinutes"], 480);
}

#[tokio::test]
async fn info_needs_no_scope_and_reports_the_grants() {
    let h = harness(|t| {
        t.sites = vec!["guest-site".into()];
        t.scopes = vec![Scope::VouchersRead];
        t.max_vouchers_per_request = Some(4);
    })
    .await;

    let res = h
        .gql("{ info { name sites scopes maxVouchersPerRequest maxValidityMinutes } }")
        .await;
    assert!(Harness::error(&res).is_none(), "{res}");
    let info = &res["data"]["info"];
    assert_eq!(info["name"], "test-client");
    assert_eq!(info["sites"][0], "guest-site");
    assert_eq!(info["scopes"], json!(["vouchers:read"]));
    assert_eq!(info["maxVouchersPerRequest"], 4);
}

// --- the limits still hold -------------------------------------------------

#[tokio::test]
async fn graphql_needs_a_token_like_everything_else() {
    let h = default_harness().await;
    let res = h
        .server
        .post("/graphql")
        .json(&json!({"query": "{ info { name } }"}))
        .await;
    assert_eq!(res.status_code(), 401);
    assert!(h.upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn graphql_does_not_bypass_scopes() {
    let h = harness(|t| t.scopes = vec![Scope::SitesRead, Scope::VouchersRead]).await;

    let res = h
        .gql(r#"mutation { createVouchers(siteId: "default", input: {name: "X", count: 1, timeLimitMinutes: 60}) { id } }"#)
        .await;
    assert_eq!(Harness::error_code(&res).as_deref(), Some("forbidden"));
    assert!(Harness::error(&res).unwrap().contains("vouchers:create"));

    let res = h
        .gql(r#"mutation { revokeVoucher(siteId: "default", voucherId: "v1") { revoked } }"#)
        .await;
    assert_eq!(Harness::error_code(&res).as_deref(), Some("forbidden"));

    assert!(h.upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn graphql_does_not_bypass_site_scoping() {
    let h = harness(|t| t.sites = vec!["guest-site".into()]).await;

    let res = h.gql(r#"{ vouchers(siteId: "corporate") { id } }"#).await;
    assert_eq!(Harness::error_code(&res).as_deref(), Some("forbidden"));
    assert!(h.upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn graphql_hides_sites_outside_the_allowlist() {
    let h = harness(|t| t.sites = vec!["guest-site".into()]).await;
    Mock::given(method("GET"))
        .and(path(format!("{API}/sites")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": [
            {"id": "guest-site", "name": "Guest"},
            {"id": "corporate", "name": "HQ"}
        ]})))
        .mount(&h.upstream)
        .await;

    let res = h.gql("{ sites { id name } }").await;
    let sites = res["data"]["sites"].as_array().unwrap();
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0]["id"], "guest-site");
    assert!(!res.to_string().contains("corporate"));
}

#[tokio::test]
async fn graphql_does_not_bypass_the_voucher_ceiling() {
    let h = harness(|t| t.max_vouchers_per_request = Some(3)).await;
    let res = h
        .gql(r#"mutation { createVouchers(siteId: "default", input: {name: "X", count: 99, timeLimitMinutes: 60}) { id } }"#)
        .await;
    assert_eq!(Harness::error_code(&res).as_deref(), Some("forbidden"));
    assert!(h.upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn graphql_does_not_bypass_the_validity_ceiling() {
    let h = harness(|t| t.max_validity_minutes = Some(60)).await;
    let res = h
        .gql(r#"mutation { createVouchers(siteId: "default", input: {name: "X", count: 1, timeLimitMinutes: 100000}) { id } }"#)
        .await;
    assert_eq!(Harness::error_code(&res).as_deref(), Some("forbidden"));
    assert!(h.upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn graphql_does_not_bypass_id_validation() {
    let h = default_harness().await;
    let res = h
        .gql(r#"{ vouchers(siteId: "../../api/self") { id } }"#)
        .await;
    assert_eq!(Harness::error_code(&res).as_deref(), Some("bad_request"));
    assert!(h.upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn graphql_never_reveals_the_controller_key() {
    let h = default_harness().await;
    Mock::given(method("GET"))
        .and(path(format!("{API}/sites")))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"message": "boom", "leaked": UPSTREAM_KEY})),
        )
        .mount(&h.upstream)
        .await;

    let res = h.gql("{ sites { id } }").await;
    assert!(!res.to_string().contains(UPSTREAM_KEY));
}

// --- amplification ---------------------------------------------------------

#[tokio::test]
async fn each_upstream_call_costs_quota_even_within_one_document() {
    let h = harness(|t| t.rate_limit_per_minute = Some(2)).await;
    Mock::given(method("GET"))
        .and(path(format!("{API}/sites")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&h.upstream)
        .await;

    // Three aliased calls in one request: the third must be refused, otherwise
    // GraphQL would be a way to spend one request's quota N times over.
    let res = h
        .gql("{ a: sites { id } b: sites { id } c: sites { id } }")
        .await;
    let errors = res["errors"].as_array().cloned().unwrap_or_default();
    assert!(!errors.is_empty(), "expected a rate-limit error, got {res}");
    assert!(errors
        .iter()
        .any(|e| e["extensions"]["code"] == "rate_limited"));
}

#[tokio::test]
async fn refuses_documents_deeper_than_the_schema_warrants() {
    let h = default_harness().await;
    // Deliberately absurd nesting; the schema is flat so this can only be abuse.
    let deep = format!("{}{}", "{ info { name ".repeat(12), "} ".repeat(12));
    let res = h.gql(&deep).await;
    assert!(res.get("errors").is_some());
    assert!(h.upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn does_not_accept_batched_documents() {
    let h = default_harness().await;
    // A JSON array is the batch form; accepting it would let one request carry
    // an unbounded number of operations.
    let res = h
        .server
        .post("/graphql")
        .add_header("x-api-key", &h.token)
        .json(&json!([
            {"query": "{ info { name } }"},
            {"query": "{ info { name } }"}
        ]))
        .await;
    assert_ne!(res.status_code(), 200);
}

// --- schema surface --------------------------------------------------------

/// Extracts the field names declared inside `type <name> { ... }`.
///
/// Checked as an exact set rather than by substring: doc comments legitimately
/// mention words like "device", and a substring test would either fail on prose
/// or pass on a real field hidden in a comment.
fn root_fields(sdl: &str, type_name: &str) -> Vec<String> {
    let header = format!("type {type_name} {{");
    let Some(start) = sdl.find(&header) else {
        return Vec::new();
    };
    let body = &sdl[start + header.len()..];
    let end = body.find("\n}").unwrap_or(body.len());

    let mut fields = Vec::new();
    let mut in_doc = false;
    for line in body[..end].lines() {
        let t = line.trim();
        if t.starts_with("\"\"\"") {
            // A `"""..."""` on one line is a whole doc comment; a bare `"""`
            // opens or closes a multi-line one.
            if !(t.len() > 6 && t.ends_with("\"\"\"")) {
                in_doc = !in_doc;
            }
            continue;
        }
        if in_doc || t.is_empty() || t.starts_with('#') {
            continue;
        }
        let name: String = t
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        // A field declaration is `name(args): Type` or `name: Type`; prose is not.
        let rest = &t[name.len()..];
        if !name.is_empty() && (rest.starts_with('(') || rest.starts_with(':')) {
            fields.push(name);
        }
    }
    fields
}

#[tokio::test]
async fn the_schema_exposes_only_voucher_operations() {
    let h = default_harness().await;
    let sdl = h
        .server
        .get("/graphql/schema")
        .add_header("x-api-key", &h.token)
        .await;
    sdl.assert_status_ok();
    let text = sdl.text();

    // The whole point of the proxy is that this list is short and fixed. If a
    // future change adds a root field, this test should fail and make someone
    // justify it.
    let mut queries = root_fields(&text, "Query");
    queries.sort();
    assert_eq!(queries, vec!["info", "sites", "vouchers"], "SDL:\n{text}");

    let mut mutations = root_fields(&text, "Mutation");
    mutations.sort();
    assert_eq!(
        mutations,
        vec!["createVouchers", "revokeVoucher"],
        "SDL:\n{text}"
    );

    // And no type describing controller infrastructure exists at all.
    for forbidden in [
        "type Device",
        "type Client",
        "type Firewall",
        "type Network",
    ] {
        assert!(
            !text.contains(forbidden),
            "SDL unexpectedly declares {forbidden}"
        );
    }
}

#[tokio::test]
async fn the_playground_is_off_unless_enabled() {
    let h = default_harness().await;
    let res = h
        .server
        .get("/graphql")
        .add_header("x-api-key", &h.token)
        .await;
    assert_eq!(res.status_code(), 403);
}

// --- remaining surface ------------------------------------------------------

#[tokio::test]
async fn revoking_through_graphql_reaches_the_controller() {
    let h = default_harness().await;
    Mock::given(method("DELETE"))
        .and(path(format!("{API}/sites/default/hotspot/vouchers/abc123")))
        .and(header("x-api-key", UPSTREAM_KEY))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&h.upstream)
        .await;

    let res = h
        .gql(r#"mutation { revokeVoucher(siteId: "default", voucherId: "abc123") { id revoked } }"#)
        .await;

    assert!(Harness::error(&res).is_none(), "{res}");
    assert_eq!(res["data"]["revokeVoucher"]["id"], "abc123");
    assert_eq!(res["data"]["revokeVoucher"]["revoked"], true);
}

#[tokio::test]
async fn optional_voucher_settings_survive_the_round_trip() {
    let h = default_harness().await;
    Mock::given(method("POST"))
        .and(path(format!("{API}/sites/default/hotspot/vouchers")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"vouchers": [
                {"id": "v1", "code": "1", "dataUsageLimitMBytes": 1024,
                 "rxRateLimitKbps": 500, "txRateLimitKbps": 600}
            ]})),
        )
        .mount(&h.upstream)
        .await;

    let res = h
        .gql(
            r#"mutation { createVouchers(siteId: "default", input: {
            name: "Guest", count: 1, timeLimitMinutes: 60,
            dataUsageLimitMBytes: 1024, rxRateLimitKbps: 500, txRateLimitKbps: 600
        }) { id dataUsageLimitMBytes rxRateLimitKbps txRateLimitKbps } }"#,
        )
        .await;

    assert!(Harness::error(&res).is_none(), "{res}");
    let v = &res["data"]["createVouchers"][0];
    assert_eq!(v["dataUsageLimitMBytes"], 1024);
    assert_eq!(v["txRateLimitKbps"], 600);

    let sent: Value =
        serde_json::from_slice(&h.upstream.received_requests().await.unwrap()[0].body).unwrap();
    assert_eq!(sent["dataUsageLimitMBytes"], 1024);
    assert_eq!(sent["rxRateLimitKbps"], 500);
}

#[tokio::test]
async fn an_upstream_failure_surfaces_as_a_graphql_error() {
    let h = default_harness().await;
    Mock::given(method("GET"))
        .and(path(format!("{API}/sites/default/hotspot/vouchers")))
        .respond_with(ResponseTemplate::new(503))
        .mount(&h.upstream)
        .await;

    let res = h.gql(r#"{ vouchers(siteId: "default") { id } }"#).await;
    assert_eq!(Harness::error_code(&res).as_deref(), Some("upstream_error"));
}

#[tokio::test]
async fn the_playground_is_served_when_it_is_switched_on() {
    let upstream = MockServer::start().await;
    let (token, hash) = auth::generate_token().unwrap();
    let cfg = Config {
        server: ServerConfig {
            graphql_playground: true,
            ..ServerConfig::default()
        },
        controller: ControllerConfig {
            host: upstream.uri(),
            api_key: Secret::new(UPSTREAM_KEY),
            tls: TlsConfig::default(),
        },
        limits: Limits::default(),
        tokens: vec![TokenConfig {
            name: "test-client".into(),
            hash,
            sites: vec!["*".into()],
            scopes: vec![Scope::SitesRead],
            max_vouchers_per_request: None,
            max_validity_minutes: None,
            rate_limit_per_minute: Some(0),
            expires_at: None,
        }],
    };
    let state = AppState::new(&cfg).unwrap();
    let app = routes::router_with(state, cfg.server.max_body_bytes, true);
    let server = TestServer::new(app).unwrap();

    let res = server.get("/graphql").add_header("x-api-key", &token).await;
    res.assert_status_ok();
    assert!(res.text().contains("GraphiQL") || res.text().contains("graphiql"));
}

#[tokio::test]
async fn omitted_input_fields_fall_back_to_their_documented_defaults() {
    let h = default_harness().await;
    Mock::given(method("POST"))
        .and(path(format!("{API}/sites/default/hotspot/vouchers")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"vouchers": [{"id": "v1"}]})))
        .mount(&h.upstream)
        .await;

    // Neither count nor authorizedGuestLimit is given; both should default to 1
    // rather than the mutation failing or sending nulls upstream.
    let res = h
        .gql(r#"mutation { createVouchers(siteId: "default", input: {name: "Guest", timeLimitMinutes: 60}) { id } }"#)
        .await;
    assert!(Harness::error(&res).is_none(), "{res}");

    let sent: Value =
        serde_json::from_slice(&h.upstream.received_requests().await.unwrap()[0].body).unwrap();
    assert_eq!(sent["count"], 1);
    assert_eq!(sent["authorizedGuestLimit"], 1);
}

#[tokio::test]
async fn input_arrives_the_same_way_whether_inline_or_as_a_variable() {
    // Real clients send variables, and async-graphql takes a different parsing
    // path for them than for inline literals — so the limits have to be proven
    // on both.
    let h = harness(|t| t.max_vouchers_per_request = Some(3)).await;
    Mock::given(method("POST"))
        .and(path(format!("{API}/sites/default/hotspot/vouchers")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"vouchers": [{"id": "v1", "code": "9"}]})),
        )
        .mount(&h.upstream)
        .await;

    const DOC: &str = r#"
        mutation Issue($site: String!, $input: CreateVoucherInput!) {
          createVouchers(siteId: $site, input: $input) { id code }
        }
    "#;

    let ok = h
        .gql_vars(
            DOC,
            json!({"site": "default", "input": {
                "name": "Guest", "count": 2, "timeLimitMinutes": 480,
                "authorizedGuestLimit": 1, "dataUsageLimitMBytes": 256
            }}),
        )
        .await;
    assert!(Harness::error(&ok).is_none(), "{ok}");
    assert_eq!(ok["data"]["createVouchers"][0]["code"], "9");

    let sent: Value =
        serde_json::from_slice(&h.upstream.received_requests().await.unwrap()[0].body).unwrap();
    assert_eq!(sent["count"], 2);
    assert_eq!(sent["dataUsageLimitMBytes"], 256);

    // The ceiling applies to variable input exactly as it does inline.
    let refused = h
        .gql_vars(
            DOC,
            json!({"site": "default", "input": {
                "name": "Guest", "count": 99, "timeLimitMinutes": 480
            }}),
        )
        .await;
    assert_eq!(Harness::error_code(&refused).as_deref(), Some("forbidden"));

    // And so does the site allowlist.
    let elsewhere = h
        .gql_vars(
            DOC,
            json!({"site": "../../api/self", "input": {
                "name": "Guest", "count": 1, "timeLimitMinutes": 60
            }}),
        )
        .await;
    assert_eq!(
        Harness::error_code(&elsewhere).as_deref(),
        Some("bad_request")
    );
}

#[tokio::test]
async fn a_variable_that_does_not_fit_the_input_type_is_rejected() {
    let h = default_harness().await;
    let res = h
        .gql_vars(
            r#"mutation Issue($input: CreateVoucherInput!) {
                 createVouchers(siteId: "default", input: $input) { id }
               }"#,
            json!({"input": {"name": "Guest", "timeLimitMinutes": "not-a-number"}}),
        )
        .await;
    assert!(res.get("errors").is_some(), "{res}");
    assert!(h.upstream.received_requests().await.unwrap().is_empty());
}
