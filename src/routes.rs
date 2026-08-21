use std::time::Instant;

use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use tower_http::limit::RequestBodyLimitLayer;

use crate::audit::AuditRecord;
use crate::config::Scope;
use crate::error::{ProxyError, ProxyResult};
use crate::policy::CreateVoucherRequest;
use crate::state::{Caller, SharedState};

/// The UniFi Integration API prefix. Serving the real paths means an existing
/// client only has to swap its host and key — no client changes, no bespoke
/// protocol to keep in sync.
const API: &str = "/proxy/network/integration/v1";

pub fn router(state: SharedState, max_body_bytes: usize) -> Router {
    router_with(state, max_body_bytes, false)
}

pub fn router_with(state: SharedState, max_body_bytes: usize, playground: bool) -> Router {
    let api = Router::new()
        .route(&format!("{API}/sites"), get(list_sites))
        .route(
            &format!("{API}/sites/{{site}}/hotspot/vouchers"),
            get(list_vouchers).post(create_vouchers),
        )
        .route(
            &format!("{API}/sites/{{site}}/hotspot/vouchers/{{voucher}}"),
            delete(delete_voucher),
        );

    // GET /graphql serves the explorer when enabled; POST is the endpoint
    // itself. Batched requests are not accepted — `GraphQLRequest` takes a
    // single document, so one HTTP request cannot fan out into an unbounded
    // number of them.
    let graphql = Router::new().route(
        "/graphql",
        post(graphql_handler).get(if playground {
            get(graphql_playground)
        } else {
            get(not_allowed)
        }),
    );

    Router::new()
        .route("/healthz", get(healthz))
        .route("/proxy/info", get(info))
        .route("/graphql/schema", get(graphql_sdl))
        .merge(graphql)
        .merge(api)
        // Anything not named above is refused rather than forwarded. This is
        // the whole premise of the proxy, so it is a route, not a comment.
        // Wrong-method requests on a known path are refused the same way, so a
        // probe gets one uniform answer and one audit line either way.
        .fallback(not_allowed)
        .method_not_allowed_fallback(not_allowed)
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
        .with_state(state)
}

/// Unauthenticated liveness probe. Reveals nothing about the controller.
async fn healthz() -> Json<Value> {
    Json(json!({"status": "ok", "service": "unifi-voucher-proxy"}))
}

/// Tells an authenticated client what it is actually allowed to do, so a UI can
/// hide controls instead of letting the user hit a 403.
async fn info(caller: Caller) -> Json<Value> {
    Json(json!({
        "service": "unifi-voucher-proxy",
        "version": env!("CARGO_PKG_VERSION"),
        "token": caller.token.name,
        "sites": caller.token.sites,
        "scopes": caller.token.scopes.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        "limits": {
            "maxVouchersPerRequest": caller.ceilings.max_vouchers,
            "maxValidityMinutes": caller.ceilings.max_validity_minutes,
        },
    }))
}

/// The GraphQL endpoint.
///
/// `Caller` is extracted before the document is even parsed, so an unauthenticated
/// request never reaches the schema. Both it and the shared state are handed to
/// the resolvers through the request context.
async fn graphql_handler(
    State(state): State<SharedState>,
    caller: Caller,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let started = Instant::now();
    let inner = req.into_inner();
    let shape = crate::graphql::describe(&inner.query);

    let response = state
        .schema
        .execute(inner.data(state.clone()).data(caller.clone()))
        .await;

    // The document itself is not logged: variables can carry guest names.
    AuditRecord {
        token: caller.name(),
        action: "graphql",
        site: None,
        target: Some(&shape),
        count: None,
        status: if response.is_ok() { 200 } else { 400 },
        outcome: if response.is_ok() {
            "ok"
        } else {
            "graphql_errors"
        },
        elapsed: started.elapsed(),
    }
    .emit();

    response.into()
}

/// The schema as SDL, so a client can generate types without introspection.
async fn graphql_sdl(_caller: Caller) -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        crate::graphql::sdl(),
    )
}

async fn graphql_playground() -> Html<String> {
    Html(async_graphql::http::graphiql_source("/graphql", None))
}

async fn not_allowed(method: axum::http::Method, uri: axum::http::Uri) -> ProxyError {
    crate::audit::rejected(uri.path(), &format!("blocked_{}", method.as_str()), 403);
    ProxyError::NotAllowed
}

async fn list_sites(State(state): State<SharedState>, caller: Caller) -> ProxyResult<Json<Value>> {
    let started = Instant::now();
    caller.require_scope(Scope::SitesRead)?;
    caller.charge(&state.rate, "sites:list")?;

    let result = state.upstream.list_sites().await;
    let filtered = result.map(|body| filter_sites(body, &caller));
    finish(&caller, "sites:list", None, None, None, started, filtered)
}

/// A token scoped to specific sites must not learn that other sites exist.
fn filter_sites(body: Value, caller: &Caller) -> Value {
    if caller.token.sites.iter().any(|s| s == "*") {
        return body;
    }
    let Some(list) = body.get("data").and_then(Value::as_array) else {
        return body;
    };
    let kept: Vec<Value> = list
        .iter()
        .filter(|site| {
            site.get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| caller.token.allows_site(id))
        })
        .cloned()
        .collect();
    json!({ "data": kept })
}

async fn list_vouchers(
    State(state): State<SharedState>,
    caller: Caller,
    Path(site): Path<String>,
) -> ProxyResult<Json<Value>> {
    let started = Instant::now();
    caller.require_scope(Scope::VouchersRead)?;
    caller.require_site(&site)?;
    caller.charge(&state.rate, "vouchers:list")?;

    let result = state.upstream.list_vouchers(&site).await;
    finish(
        &caller,
        "vouchers:list",
        Some(&site),
        None,
        None,
        started,
        result,
    )
}

async fn create_vouchers(
    State(state): State<SharedState>,
    caller: Caller,
    Path(site): Path<String>,
    Json(body): Json<Value>,
) -> ProxyResult<Json<Value>> {
    let started = Instant::now();
    caller.require_scope(Scope::VouchersCreate)?;
    caller.require_site(&site)?;

    let request = CreateVoucherRequest::parse(&body)?;
    request.enforce(caller.ceilings)?;
    caller.charge(&state.rate, "vouchers:create")?;

    let result = state
        .upstream
        .create_vouchers(&site, &request.to_upstream_body()?)
        .await;
    finish(
        &caller,
        "vouchers:create",
        Some(&site),
        None,
        Some(request.count),
        started,
        result,
    )
}

async fn delete_voucher(
    State(state): State<SharedState>,
    caller: Caller,
    Path((site, voucher)): Path<(String, String)>,
) -> ProxyResult<Json<Value>> {
    let started = Instant::now();
    caller.require_scope(Scope::VouchersRevoke)?;
    caller.require_site(&site)?;
    caller.charge(&state.rate, "vouchers:revoke")?;

    let result = state.upstream.delete_voucher(&site, &voucher).await;
    finish(
        &caller,
        "vouchers:revoke",
        Some(&site),
        Some(&voucher),
        None,
        started,
        result,
    )
}

/// Emits the audit record for a completed operation and shapes the response.
fn finish(
    caller: &Caller,
    action: &str,
    site: Option<&str>,
    target: Option<&str>,
    count: Option<u32>,
    started: Instant,
    result: ProxyResult<Value>,
) -> ProxyResult<Json<Value>> {
    let (status, outcome) = match &result {
        Ok(_) => (200, "ok".to_string()),
        Err(e) => (e.status().as_u16(), e.kind().to_string()),
    };
    AuditRecord {
        token: caller.name(),
        action,
        site,
        target,
        count,
        status,
        outcome: &outcome,
        elapsed: started.elapsed(),
    }
    .emit();
    result.map(Json)
}
