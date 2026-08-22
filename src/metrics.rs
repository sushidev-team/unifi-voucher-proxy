use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

/// Counters exposed at `/metrics` in Prometheus text format.
///
/// Hand-rolled rather than pulled from a metrics crate: the whole surface is
/// four counters and a histogram-less latency sum, and a dependency that pulls
/// in a registry, exporters and a background task would be more machinery than
/// the thing being measured.
///
/// Label values are bounded by construction — token names and actions both come
/// from configuration or from a fixed set — so the map cannot grow without
/// bound the way a naive `path` label would.
#[derive(Debug, Default)]
pub struct Metrics {
    requests: RwLock<BTreeMap<(String, String, String), u64>>,
    vouchers_created: RwLock<BTreeMap<String, u64>>,
    upstream_latency_ms_total: AtomicU64,
    upstream_calls: AtomicU64,
    reloads: AtomicU64,
    reload_failures: AtomicU64,
}

impl Metrics {
    /// One completed request: which token, which action, how it ended.
    pub fn record_request(&self, token: &str, action: &str, outcome: &str) {
        let key = (token.to_string(), action.to_string(), outcome.to_string());
        *self
            .requests
            .write()
            .expect("metrics poisoned")
            .entry(key)
            .or_insert(0) += 1;
    }

    /// Vouchers actually issued — the number that matters for a hotspot, and
    /// the one worth alerting on if it spikes.
    pub fn record_vouchers_created(&self, token: &str, count: u32) {
        *self
            .vouchers_created
            .write()
            .expect("metrics poisoned")
            .entry(token.to_string())
            .or_insert(0) += u64::from(count);
    }

    pub fn record_upstream(&self, elapsed_ms: u64) {
        self.upstream_latency_ms_total
            .fetch_add(elapsed_ms, Ordering::Relaxed);
        self.upstream_calls.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_reload(&self, ok: bool) {
        if ok {
            self.reloads.fetch_add(1, Ordering::Relaxed);
        } else {
            self.reload_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Renders the Prometheus exposition format.
    pub fn render(&self, version: &str, tokens_configured: usize) -> String {
        let mut out = String::new();

        out.push_str("# HELP uvp_build_info Version of the running proxy.\n");
        out.push_str("# TYPE uvp_build_info gauge\n");
        out.push_str(&format!("uvp_build_info{{version=\"{version}\"}} 1\n"));

        out.push_str(
            "# HELP uvp_tokens_configured Number of client tokens in the active config.\n",
        );
        out.push_str("# TYPE uvp_tokens_configured gauge\n");
        out.push_str(&format!("uvp_tokens_configured {tokens_configured}\n"));

        out.push_str("# HELP uvp_requests_total Requests by token, action and outcome.\n");
        out.push_str("# TYPE uvp_requests_total counter\n");
        for ((token, action, outcome), n) in self.requests.read().expect("metrics poisoned").iter()
        {
            out.push_str(&format!(
                "uvp_requests_total{{token=\"{}\",action=\"{}\",outcome=\"{}\"}} {n}\n",
                escape(token),
                escape(action),
                escape(outcome)
            ));
        }

        out.push_str("# HELP uvp_vouchers_created_total Vouchers issued through the proxy.\n");
        out.push_str("# TYPE uvp_vouchers_created_total counter\n");
        for (token, n) in self
            .vouchers_created
            .read()
            .expect("metrics poisoned")
            .iter()
        {
            out.push_str(&format!(
                "uvp_vouchers_created_total{{token=\"{}\"}} {n}\n",
                escape(token)
            ));
        }

        let calls = self.upstream_calls.load(Ordering::Relaxed);
        let total_ms = self.upstream_latency_ms_total.load(Ordering::Relaxed);
        out.push_str("# HELP uvp_upstream_seconds_total Time spent waiting on the controller.\n");
        out.push_str("# TYPE uvp_upstream_seconds_total counter\n");
        out.push_str(&format!(
            "uvp_upstream_seconds_total {:.3}\n",
            total_ms as f64 / 1000.0
        ));
        out.push_str("# HELP uvp_upstream_calls_total Calls made to the controller.\n");
        out.push_str("# TYPE uvp_upstream_calls_total counter\n");
        out.push_str(&format!("uvp_upstream_calls_total {calls}\n"));

        out.push_str("# HELP uvp_config_reloads_total Successful SIGHUP reloads.\n");
        out.push_str("# TYPE uvp_config_reloads_total counter\n");
        out.push_str(&format!(
            "uvp_config_reloads_total {}\n",
            self.reloads.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP uvp_config_reload_failures_total Reloads rejected for a bad config.\n",
        );
        out.push_str("# TYPE uvp_config_reload_failures_total counter\n");
        out.push_str(&format!(
            "uvp_config_reload_failures_total {}\n",
            self.reload_failures.load(Ordering::Relaxed)
        ));

        out
    }
}

/// Prometheus label values escape backslash, quote and newline — and nothing
/// else. Token names are operator-chosen, so this is not theoretical.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_requests_per_label_set() {
        let m = Metrics::default();
        m.record_request("phone", "vouchers:create", "ok");
        m.record_request("phone", "vouchers:create", "ok");
        m.record_request("phone", "vouchers:create", "forbidden");
        m.record_request("display", "vouchers:list", "ok");

        let out = m.render("1.2.3", 2);
        assert!(out.contains(
            "uvp_requests_total{token=\"phone\",action=\"vouchers:create\",outcome=\"ok\"} 2"
        ));
        assert!(out.contains(
            "uvp_requests_total{token=\"phone\",action=\"vouchers:create\",outcome=\"forbidden\"} 1"
        ));
        assert!(out.contains(
            "uvp_requests_total{token=\"display\",action=\"vouchers:list\",outcome=\"ok\"} 1"
        ));
    }

    #[test]
    fn sums_vouchers_rather_than_counting_calls() {
        // One request for five vouchers is five vouchers, not one.
        let m = Metrics::default();
        m.record_vouchers_created("phone", 5);
        m.record_vouchers_created("phone", 2);
        assert!(m
            .render("v", 1)
            .contains("uvp_vouchers_created_total{token=\"phone\"} 7"));
    }

    #[test]
    fn reports_build_info_and_token_count() {
        let out = Metrics::default().render("9.9.9", 3);
        assert!(out.contains("uvp_build_info{version=\"9.9.9\"} 1"));
        assert!(out.contains("uvp_tokens_configured 3"));
    }

    #[test]
    fn converts_upstream_latency_to_seconds() {
        let m = Metrics::default();
        m.record_upstream(1500);
        m.record_upstream(500);
        let out = m.render("v", 0);
        assert!(out.contains("uvp_upstream_seconds_total 2.000"), "{out}");
        assert!(out.contains("uvp_upstream_calls_total 2"));
    }

    #[test]
    fn counts_reloads_and_their_failures_separately() {
        let m = Metrics::default();
        m.record_reload(true);
        m.record_reload(false);
        m.record_reload(true);
        let out = m.render("v", 0);
        assert!(out.contains("uvp_config_reloads_total 2"));
        assert!(out.contains("uvp_config_reload_failures_total 1"));
    }

    #[test]
    fn escapes_label_values_so_a_token_name_cannot_break_the_format() {
        let m = Metrics::default();
        m.record_request("we\"ird\\name", "a", "ok");
        let out = m.render("v", 1);
        assert!(out.contains(r#"token="we\"ird\\name""#), "{out}");
    }

    #[test]
    fn renders_valid_exposition_syntax() {
        let m = Metrics::default();
        m.record_request("phone", "sites:list", "ok");
        for line in m.render("1.0.0", 1).lines() {
            if line.starts_with('#') {
                assert!(
                    line.starts_with("# HELP ") || line.starts_with("# TYPE "),
                    "unexpected comment: {line}"
                );
            } else {
                // Every sample line must end in a numeric value.
                let value = line.rsplit(' ').next().unwrap();
                assert!(value.parse::<f64>().is_ok(), "not a sample: {line}");
            }
        }
    }
}
