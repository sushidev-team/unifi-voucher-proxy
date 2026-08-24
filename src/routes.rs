use std::time::{Duration, Instant};

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

/// The metrics listener: one route, served on its own socket.
///
/// Deliberately not merged into the main router. See
/// [`ServerConfig::metrics_bind`](crate::config::ServerConfig::metrics_bind)
/// for why the reachability of this is a bind address rather than a token.
pub fn metrics_router(state: SharedState) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .fallback(not_found)
        .with_state(state)
}

async fn metrics(State(state): State<SharedState>) -> impl IntoResponse {
    let body = state
        .metrics
        .render(env!("CARGO_PKG_VERSION"), state.live().token_count);
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

async fn not_found() -> ProxyError {
    ProxyError::NotAllowed
}

/// Unauthenticated liveness probe. Reveals nothing about the controller.
async fn healthz() -> Json<Value> {
    Json(json!({"status": "ok", "service": "unifi-voucher-proxy"}))
}

/// Tells an authenticated client what it is actually allowed to do, so a UI can
/// hide controls instead of letting the user hit a 403.
async fn info(State(state): State<SharedState>, caller: Caller) -> Json<Value> {
    state.metrics.record_request(caller.name(), "info", "ok");
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

    let outcome = if response.is_ok() {
        "ok"
    } else {
        "graphql_errors"
    };
    state
        .metrics
        .record_request(caller.name(), "graphql", outcome);

    // The document itself is not logged: variables can carry guest names.
    AuditRecord {
        token: caller.name(),
        action: "graphql",
        site: None,
        target: Some(&shape),
        count: None,
        status: if response.is_ok() { 200 } else { 400 },
        outcome,
        elapsed: started.elapsed(),
    }
    .emit();

    response.into()
}

/// The schema as SDL, so a client can generate types without introspection.
async fn graphql_sdl(State(state): State<SharedState>, caller: Caller) -> impl IntoResponse {
    state
        .metrics
        .record_request(caller.name(), "graphql:schema", "ok");
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
    let live = state.live();
    let mut upstream = Duration::ZERO;

    // Every exit runs through `finish`, including the refusals. A `?` here
    // would return before the record is written, and a proxy that logs only
    // what it allowed answers half the question it exists to answer.
    let result = async {
        caller.require_scope(Scope::SitesRead)?;
        caller.charge(&live.rate, "sites:list")?;
        let up = Instant::now();
        let body = live.upstream.list_sites().await;
        upstream = up.elapsed();
        body.map(|b| filter_sites(b, &caller))
    }
    .await;

    finish(
        &state,
        &caller,
        "sites:list",
        None,
        None,
        None,
        started,
        upstream,
        result,
    )
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
    let live = state.live();
    let mut upstream = Duration::ZERO;

    let result = async {
        caller.require_scope(Scope::VouchersRead)?;
        caller.require_site(&site)?;
        caller.charge(&live.rate, "vouchers:list")?;
        let up = Instant::now();
        let body = live.upstream.list_vouchers(&site).await;
        upstream = up.elapsed();
        body
    }
    .await;

    finish(
        &state,
        &caller,
        "vouchers:list",
        Some(&site),
        None,
        None,
        started,
        upstream,
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
    let live = state.live();
    let mut upstream = Duration::ZERO;
    let mut count = None;

    let result = async {
        caller.require_scope(Scope::VouchersCreate)?;
        caller.require_site(&site)?;
        // Charged before the body is looked at, not after. Scope and site are
        // fixed lookups a caller cannot make expensive; parsing and policy work
        // on data the caller controls, so a client that only ever sends rejects
        // would otherwise get that work for free.
        caller.charge(&live.rate, "vouchers:create")?;

        let request = CreateVoucherRequest::parse(&body)?;
        request.enforce(caller.ceilings)?;
        count = Some(request.count);

        let up = Instant::now();
        let created = live
            .upstream
            .create_vouchers(&site, &request.to_upstream_body()?)
            .await;
        upstream = up.elapsed();
        created
    }
    .await;

    finish(
        &state,
        &caller,
        "vouchers:create",
        Some(&site),
        None,
        count,
        started,
        upstream,
        result,
    )
}

async fn delete_voucher(
    State(state): State<SharedState>,
    caller: Caller,
    Path((site, voucher)): Path<(String, String)>,
) -> ProxyResult<Json<Value>> {
    let started = Instant::now();
    let live = state.live();
    let mut upstream = Duration::ZERO;

    let result = async {
        caller.require_scope(Scope::VouchersRevoke)?;
        caller.require_site(&site)?;
        caller.charge(&live.rate, "vouchers:revoke")?;
        let up = Instant::now();
        let deleted = live.upstream.delete_voucher(&site, &voucher).await;
        upstream = up.elapsed();
        deleted
    }
    .await;

    finish(
        &state,
        &caller,
        "vouchers:revoke",
        Some(&site),
        Some(&voucher),
        None,
        started,
        upstream,
        result,
    )
}

/// Emits the audit record for a completed operation and shapes the response.
#[allow(clippy::too_many_arguments)]
fn finish(
    state: &SharedState,
    caller: &Caller,
    action: &str,
    site: Option<&str>,
    target: Option<&str>,
    count: Option<u32>,
    started: Instant,
    upstream: Duration,
    result: ProxyResult<Value>,
) -> ProxyResult<Json<Value>> {
    let (status, outcome) = match &result {
        Ok(_) => (200, "ok".to_string()),
        Err(e) => (e.status().as_u16(), e.kind().to_string()),
    };
    // Both surfaces are fed from one place, so an outcome cannot appear in the
    // audit log and be missing from the counters.
    state
        .metrics
        .record_request(caller.name(), action, &outcome);
    state.metrics.record_upstream(upstream.as_millis() as u64);
    if result.is_ok() {
        if let Some(n) = count {
            state.metrics.record_vouchers_created(caller.name(), n);
        }
    }
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
