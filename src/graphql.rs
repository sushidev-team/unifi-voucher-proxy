//! GraphQL surface over the same operations the REST routes expose.
//!
//! This layer adds convenience, not reach. Every resolver goes through the same
//! [`Caller`] — scopes, site allowlist, quotas and request policy — and calls
//! the same [`Upstream`](crate::upstream::Upstream) methods. There is no
//! resolver that can touch anything the REST side cannot.
//!
//! GraphQL does bring two amplification risks that REST does not, both closed
//! here: a document can nest arbitrarily (bounded by depth and complexity
//! limits) and can ask for many things at once (each upstream call is charged
//! against the caller's quota individually, and request batching is not
//! accepted).

use async_graphql::{
    Context, EmptySubscription, ErrorExtensions, InputObject, Object, Schema, SimpleObject,
};
use serde_json::json;

use crate::config::Scope;
use crate::error::ProxyError;
use crate::model::{Site, Voucher};
use crate::policy::CreateVoucherRequest;
use crate::state::{Caller, SharedState};

/// Query depth beyond this is refused. The schema is flat, so anything deep is
/// either a mistake or an attempt to make the server work for nothing.
const MAX_DEPTH: usize = 8;
/// Rough ceiling on total fields resolved in one document.
const MAX_COMPLEXITY: usize = 256;

pub type ProxySchema = Schema<Query, Mutation, EmptySubscription>;

pub fn schema() -> ProxySchema {
    Schema::build(Query, Mutation, EmptySubscription)
        .limit_depth(MAX_DEPTH)
        .limit_complexity(MAX_COMPLEXITY)
        .finish()
}

/// Maps a proxy error onto a GraphQL error, keeping the HTTP status and the
/// machine-readable kind in extensions so clients can branch on them.
pub(crate) fn to_gql(err: ProxyError) -> async_graphql::Error {
    let status = err.status().as_u16();
    let kind = err.kind().to_string();
    let message = match &err {
        // Internal detail is logged, not returned — same rule as the REST side.
        ProxyError::Internal(e) => {
            tracing::error!(error = ?e, "internal error");
            "internal proxy error".to_string()
        }
        other => other.to_string(),
    };
    async_graphql::Error::new(message).extend_with(|_, e| {
        e.set("code", kind.clone());
        e.set("status", status as i32);
    })
}

/// Pulls the request-scoped state out of the GraphQL context. Both values are
/// injected by the axum handler, so a missing one is a wiring bug, not input.
fn ctx_parts<'a>(ctx: &'a Context<'_>) -> async_graphql::Result<(&'a SharedState, &'a Caller)> {
    Ok((ctx.data::<SharedState>()?, ctx.data::<Caller>()?))
}

/// What the calling token is allowed to do.
#[derive(SimpleObject)]
pub struct TokenInfo {
    /// The token's label, as it appears in the audit log.
    pub name: String,
    /// Site ids this token may use; `["*"]` means all of them.
    pub sites: Vec<String>,
    pub scopes: Vec<String>,
    pub max_vouchers_per_request: i32,
    pub max_validity_minutes: i64,
}

/// Result of revoking a voucher.
#[derive(SimpleObject)]
pub struct RevokeResult {
    pub id: String,
    pub revoked: bool,
}

#[derive(Debug, InputObject)]
pub struct CreateVoucherInput {
    /// Label shown on the voucher.
    pub name: String,
    /// How many to create. Bounded by the token's ceiling.
    #[graphql(default = 1)]
    pub count: u32,
    /// Validity once redeemed. Bounded by the token's ceiling.
    pub time_limit_minutes: u64,
    /// Devices allowed per voucher.
    #[graphql(default = 1)]
    pub authorized_guest_limit: u32,
    pub data_usage_limit_m_bytes: Option<u64>,
    pub rx_rate_limit_kbps: Option<u64>,
    pub tx_rate_limit_kbps: Option<u64>,
}

impl From<CreateVoucherInput> for CreateVoucherRequest {
    fn from(i: CreateVoucherInput) -> Self {
        Self {
            name: i.name,
            count: i.count,
            time_limit_minutes: i.time_limit_minutes,
            authorized_guest_limit: i.authorized_guest_limit,
            data_usage_limit_m_bytes: i.data_usage_limit_m_bytes,
            rx_rate_limit_kbps: i.rx_rate_limit_kbps,
            tx_rate_limit_kbps: i.tx_rate_limit_kbps,
        }
    }
}

pub struct Query;

#[Object]
impl Query {
    /// What this token may do. Needs no scope — a client is always allowed to
    /// ask about itself, and it is how a UI knows which controls to show.
    async fn info(&self, ctx: &Context<'_>) -> async_graphql::Result<TokenInfo> {
        let (_, caller) = ctx_parts(ctx)?;
        Ok(TokenInfo {
            name: caller.token.name.clone(),
            sites: caller.token.sites.clone(),
            scopes: caller
                .token
                .scopes
                .iter()
                .map(|s| s.as_str().to_string())
                .collect(),
            max_vouchers_per_request: caller.ceilings.max_vouchers as i32,
            max_validity_minutes: caller.ceilings.max_validity_minutes as i64,
        })
    }

    /// Sites this token may use. Sites outside its allowlist are not listed.
    async fn sites(&self, ctx: &Context<'_>) -> async_graphql::Result<Vec<Site>> {
        let (state, caller) = ctx_parts(ctx)?;
        let live = state.live();
        caller.require_scope(Scope::SitesRead).map_err(to_gql)?;
        caller.charge(&live.rate, "graphql:sites").map_err(to_gql)?;

        let body = live.upstream.list_sites().await.map_err(to_gql)?;
        Ok(Site::list(&body)
            .into_iter()
            .filter(|s| caller.token.allows_site(&s.id))
            .collect())
    }

    /// Vouchers on a site.
    async fn vouchers(
        &self,
        ctx: &Context<'_>,
        site_id: String,
    ) -> async_graphql::Result<Vec<Voucher>> {
        let (state, caller) = ctx_parts(ctx)?;
        let live = state.live();
        caller.require_scope(Scope::VouchersRead).map_err(to_gql)?;
        caller.require_site(&site_id).map_err(to_gql)?;
        caller
            .charge(&live.rate, "graphql:vouchers")
            .map_err(to_gql)?;

        let body = live
            .upstream
            .list_vouchers(&site_id)
            .await
            .map_err(to_gql)?;
        Ok(Voucher::list(&body))
    }
}

pub struct Mutation;

#[Object]
impl Mutation {
    /// Creates vouchers and returns them.
    async fn create_vouchers(
        &self,
        ctx: &Context<'_>,
        site_id: String,
        input: CreateVoucherInput,
    ) -> async_graphql::Result<Vec<Voucher>> {
        let (state, caller) = ctx_parts(ctx)?;
        let live = state.live();
        caller
            .require_scope(Scope::VouchersCreate)
            .map_err(to_gql)?;
        caller.require_site(&site_id).map_err(to_gql)?;
        // Same ordering as the REST route: the quota is spent before policy
        // looks at caller-supplied values, so a stream of rejects is not free.
        caller
            .charge(&live.rate, "graphql:createVouchers")
            .map_err(to_gql)?;

        let request: CreateVoucherRequest = input.into();
        request.enforce(caller.ceilings).map_err(to_gql)?;

        let body = live
            .upstream
            .create_vouchers(&site_id, &request.to_upstream_body().map_err(to_gql)?)
            .await
            .map_err(to_gql)?;
        Ok(Voucher::list(&body))
    }

    /// Revokes a voucher.
    async fn revoke_voucher(
        &self,
        ctx: &Context<'_>,
        site_id: String,
        voucher_id: String,
    ) -> async_graphql::Result<RevokeResult> {
        let (state, caller) = ctx_parts(ctx)?;
        let live = state.live();
        caller
            .require_scope(Scope::VouchersRevoke)
            .map_err(to_gql)?;
        caller.require_site(&site_id).map_err(to_gql)?;
        caller
            .charge(&live.rate, "graphql:revokeVoucher")
            .map_err(to_gql)?;

        live.upstream
            .delete_voucher(&site_id, &voucher_id)
            .await
            .map_err(to_gql)?;
        Ok(RevokeResult {
            id: voucher_id,
            revoked: true,
        })
    }
}

/// The SDL, for clients that want the schema without running introspection.
pub fn sdl() -> String {
    schema().sdl()
}

/// Audit helper: describes a GraphQL document in one field for the log line,
/// without recording the document itself (variables can carry voucher names).
pub fn describe(query: &str) -> String {
    let kind = if query.trim_start().starts_with("mutation") {
        "mutation"
    } else {
        "query"
    };
    json!({ "kind": kind, "bytes": query.len() }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code_of(err: &async_graphql::Error) -> String {
        err.extensions
            .as_ref()
            .and_then(|e| e.get("code"))
            .map(|v| format!("{v:?}"))
            .unwrap_or_default()
    }

    #[test]
    fn proxy_errors_carry_their_code_and_status_into_graphql_extensions() {
        let err = to_gql(ProxyError::Forbidden("no".into()));
        assert_eq!(err.message, "no");
        assert!(code_of(&err).contains("forbidden"));
    }

    #[test]
    fn internal_errors_stay_opaque_in_graphql_too() {
        let err = to_gql(ProxyError::Internal(anyhow::anyhow!("secret detail")));
        assert_eq!(err.message, "internal proxy error");
        assert!(!err.message.contains("secret detail"));
        assert!(code_of(&err).contains("internal"));
    }

    #[test]
    fn graphql_input_maps_onto_the_same_request_type_rest_uses() {
        let input = CreateVoucherInput {
            name: "Guest".into(),
            count: 3,
            time_limit_minutes: 480,
            authorized_guest_limit: 2,
            data_usage_limit_m_bytes: Some(1024),
            rx_rate_limit_kbps: Some(500),
            tx_rate_limit_kbps: Some(600),
        };
        let req: CreateVoucherRequest = input.into();
        assert_eq!(req.name, "Guest");
        assert_eq!(req.count, 3);
        assert_eq!(req.data_usage_limit_m_bytes, Some(1024));
        assert_eq!(req.tx_rate_limit_kbps, Some(600));
    }

    #[test]
    fn the_input_object_round_trips_through_graphql_values() {
        // `to_value` is part of the InputObject contract — it is what GraphQL
        // uses to echo an input back in errors and introspection defaults — so
        // it should survive a round trip rather than merely compile.
        use async_graphql::InputType;

        let input = CreateVoucherInput {
            name: "Guest".into(),
            count: 2,
            time_limit_minutes: 480,
            authorized_guest_limit: 3,
            data_usage_limit_m_bytes: Some(2048),
            rx_rate_limit_kbps: None,
            tx_rate_limit_kbps: None,
        };

        let back = CreateVoucherInput::parse(Some(input.to_value()))
            .expect("an input object must parse back from its own value");
        assert_eq!(back.name, "Guest");
        assert_eq!(back.count, 2);
        assert_eq!(back.time_limit_minutes, 480);
        assert_eq!(back.authorized_guest_limit, 3);
        assert_eq!(back.data_usage_limit_m_bytes, Some(2048));
        assert_eq!(back.rx_rate_limit_kbps, None);

        // The input carries a guest-facing label, so make sure debug output
        // stays a plain struct dump and does not acquire any redaction the
        // caller might mistake for a secret being handled.
        assert!(format!("{back:?}").contains("Guest"));
    }

    #[test]
    fn describes_documents_without_recording_them() {
        // Variables can carry guest names, so the audit line gets shape only.
        let q = describe("query { info { name } }");
        assert!(q.contains("query"));
        let m = describe("  mutation { createVouchers(input: {name: \"Alice Smith\"}) { id } }");
        assert!(m.contains("mutation"));
        assert!(!m.contains("Alice"));
    }

    #[test]
    fn the_sdl_is_generated_and_names_the_roots() {
        let text = sdl();
        assert!(text.contains("type Query"));
        assert!(text.contains("type Mutation"));
    }
}
