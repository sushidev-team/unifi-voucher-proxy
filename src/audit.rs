use std::time::Duration;

/// One line per request, emitted on the `audit` target.
///
/// The point of an audit log here is answering "what did that app actually do
/// to my controller" months later, so it records the acting token, the
/// operation, and the outcome — and never the token value, the upstream API
/// key, or voucher codes.
pub struct AuditRecord<'a> {
    pub token: &'a str,
    pub action: &'a str,
    pub site: Option<&'a str>,
    pub target: Option<&'a str>,
    pub count: Option<u32>,
    pub status: u16,
    pub outcome: &'a str,
    pub elapsed: Duration,
}

impl AuditRecord<'_> {
    pub fn emit(&self) {
        // Resolved before the macro rather than inside it. `tracing` only
        // evaluates field expressions when a subscriber is listening, which
        // makes them invisible to coverage and awkward to reason about; these
        // are four trivial reads, so computing them unconditionally costs
        // nothing and keeps the record's shape obvious.
        let site = self.site.unwrap_or("-");
        let target_id = self.target.unwrap_or("-");
        let count = self.count.unwrap_or(0);
        let elapsed_ms = self.elapsed.as_millis() as u64;

        tracing::info!(
            target: "audit",
            token = self.token,
            action = self.action,
            site,
            target_id,
            count,
            status = self.status,
            outcome = self.outcome,
            elapsed_ms,
            "request"
        );
    }
}

/// Audit entry for a request that never got as far as identifying a caller.
pub fn rejected(action: &str, reason: &str, status: u16) {
    tracing::warn!(
        target: "audit",
        token = "-",
        action = action,
        outcome = reason,
        status = status,
        "rejected"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The audit path must never panic — it runs on every request, including
    /// the ones that are already going wrong.
    ///
    /// A subscriber has to be active for this to test anything: `tracing`
    /// macros do not evaluate their field expressions when nothing is
    /// listening, so without one the `unwrap_or` fallbacks below never run.
    #[test]
    fn emits_records_with_and_without_optional_fields() {
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_test_writer()
                .finish(),
        );
        // A callsite that was first reached with no subscriber installed caches
        // "nobody is interested" globally, and a thread-local default does not
        // invalidate that. Without this the macro below would still skip its
        // field expressions.
        tracing::callsite::rebuild_interest_cache();

        AuditRecord {
            token: "phone",
            action: "vouchers:create",
            site: Some("default"),
            target: Some("v1"),
            count: Some(3),
            status: 200,
            outcome: "ok",
            elapsed: Duration::from_millis(12),
        }
        .emit();

        AuditRecord {
            token: "phone",
            action: "sites:list",
            site: None,
            target: None,
            count: None,
            status: 403,
            outcome: "forbidden",
            elapsed: Duration::ZERO,
        }
        .emit();

        rejected("/some/path", "unknown_token", 401);
    }
}
