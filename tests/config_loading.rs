//! Configuration loading and validation.
//!
//! The validation rules here are a security control in their own right: a
//! config that "mostly works" but silently grants more than intended is exactly
//! the failure this project exists to prevent, so every refusal is asserted.

use std::sync::{Mutex, MutexGuard, OnceLock};

use tempfile::TempDir;
use unifi_voucher_proxy::config::{Config, Limits, Scope};

/// `Config::load` reads process environment, which is global. Every test that
/// loads takes this lock so a stray `UVP_*` from one cannot leak into another.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

const VALID_HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZQ$aGFzaHZhbHVlaGVyZWFiY2RlZmdoaWprbG1ub3A";

fn write(contents: &str) -> (TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, contents).unwrap();
    (dir, path)
}

fn minimal() -> String {
    format!(
        r#"
[controller]
host = "192.168.1.1"
api_key = "real-key"

[[tokens]]
name = "phone"
hash = "{VALID_HASH}"
"#
    )
}

fn load(contents: &str) -> anyhow::Result<Config> {
    let _guard = env_lock();
    let (_dir, path) = write(contents);
    Config::load(Some(&path))
}

// --- the happy path --------------------------------------------------------

#[test]
fn a_minimal_config_loads_with_sensible_defaults() {
    let cfg = load(&minimal()).unwrap();
    assert_eq!(cfg.controller.host, "192.168.1.1");
    assert_eq!(cfg.controller.api_key.expose(), "real-key");
    assert_eq!(cfg.server.bind.to_string(), "0.0.0.0:8080");
    assert_eq!(cfg.server.max_body_bytes, 65536);
    assert!(!cfg.server.graphql_playground);
    assert_eq!(cfg.limits.max_vouchers_per_request, 10);
    assert_eq!(cfg.limits.rate_limit_per_minute, 60);

    // A token with no explicit grants gets every site and every scope, which is
    // why the server warns about `sites = ["*"]` on startup.
    let t = &cfg.tokens[0];
    assert_eq!(t.sites, vec!["*"]);
    assert_eq!(t.scopes.len(), 4);
    assert!(t.allows_site("anything"));
    assert!(t.has_scope(Scope::VouchersRevoke));
}

#[test]
fn a_full_config_round_trips() {
    let cfg = load(&format!(
        r#"
[server]
bind = "127.0.0.1:9000"
upstream_timeout = "30s"
max_body_bytes = 4096
graphql_playground = true

[controller]
host = "https://unifi.lan:8443"
api_key = "k"

[controller.tls]
fingerprint_sha256 = "{fp}"

[limits]
max_vouchers_per_request = 5
max_validity_minutes = 600
rate_limit_per_minute = 30

[[tokens]]
name = "display"
hash = "{VALID_HASH}"
sites = ["site-a", "site-b"]
scopes = ["vouchers:read"]
max_vouchers_per_request = 2
max_validity_minutes = 120
rate_limit_per_minute = 5
"#,
        fp = "a".repeat(64)
    ))
    .unwrap();

    assert_eq!(cfg.server.bind.to_string(), "127.0.0.1:9000");
    assert_eq!(cfg.server.upstream_timeout.as_secs(), 30);
    assert!(cfg.server.graphql_playground);
    assert_eq!(cfg.controller.tls.fingerprint_sha256.unwrap().len(), 64);

    let t = &cfg.tokens[0];
    assert!(t.allows_site("site-a"));
    assert!(!t.allows_site("site-c"));
    assert!(t.has_scope(Scope::VouchersRead));
    assert!(!t.has_scope(Scope::VouchersCreate));
}

#[test]
fn the_environment_supplies_the_key_so_the_file_need_not() {
    let _guard = env_lock();
    let (_dir, path) = write(&format!(
        r#"
[controller]
host = "192.168.1.1"
api_key = ""

[[tokens]]
name = "phone"
hash = "{VALID_HASH}"
"#
    ));

    // Without the variable the same file is refused...
    assert!(Config::load(Some(&path)).is_err());

    std::env::set_var("UVP_CONTROLLER__API_KEY", "from-the-environment");
    std::env::set_var("UVP_SERVER__BIND", "127.0.0.1:7777");
    let cfg = Config::load(Some(&path)).unwrap();
    std::env::remove_var("UVP_CONTROLLER__API_KEY");
    std::env::remove_var("UVP_SERVER__BIND");

    assert_eq!(cfg.controller.api_key.expose(), "from-the-environment");
    // ...and the environment also wins over what the file did say.
    assert_eq!(cfg.server.bind.to_string(), "127.0.0.1:7777");
}

// --- refusals --------------------------------------------------------------

#[test]
fn a_missing_file_is_named() {
    let _guard = env_lock();
    let err = Config::load(Some(std::path::Path::new("/nonexistent/config.toml"))).unwrap_err();
    assert!(err.to_string().contains("config file not found"));
}

#[test]
fn an_empty_api_key_is_refused() {
    let err = load(&minimal().replace(r#"api_key = "real-key""#, r#"api_key = """#)).unwrap_err();
    assert!(err.to_string().contains("api_key is empty"));
}

#[test]
fn a_config_without_tokens_is_refused() {
    let err = load(
        r#"
[controller]
host = "192.168.1.1"
api_key = "k"
"#,
    )
    .unwrap_err();
    // A proxy that trusts nobody is useless; one that is misread as trusting
    // everybody is dangerous. Either way it should not start.
    assert!(err.to_string().contains("no tokens configured"));
}

#[test]
fn a_nameless_token_is_refused() {
    let err = load(&minimal().replace(r#"name = "phone""#, r#"name = "  ""#)).unwrap_err();
    assert!(err.to_string().contains("non-empty name"));
}

#[test]
fn a_plaintext_token_in_the_hash_field_is_refused() {
    // The mistake this catches: pasting the token instead of its hash, which
    // would work fine and store a live credential in the config file.
    let err = load(&minimal().replace(VALID_HASH, "uvp_thisIsTheRawToken")).unwrap_err();
    assert!(err.to_string().contains("not an Argon2 PHC string"));
}

#[test]
fn a_token_without_scopes_is_refused() {
    let err = load(&format!("{}\nscopes = []\n", minimal())).unwrap_err();
    assert!(err.to_string().contains("no scopes"));
}

#[test]
fn pinning_and_skipping_verification_at_once_is_refused() {
    let err = load(&format!(
        "{}\n[controller.tls]\nfingerprint_sha256 = \"{}\"\ninsecure_skip_verify = true\n",
        minimal(),
        "a".repeat(64)
    ))
    .unwrap_err();
    assert!(err.to_string().contains("not both"));
}

#[test]
fn an_unrecognised_key_is_refused_rather_than_ignored() {
    // A typo in a security setting must not be silently dropped: someone who
    // writes `insecure_skip_verifiy = false` should hear about it.
    let err = load(&format!("{}\nunexpected_option = 1\n", minimal())).unwrap_err();
    assert!(err.to_string().contains("invalid configuration"));
}

// --- effective limits ------------------------------------------------------

#[test]
fn a_token_may_tighten_a_limit_but_never_raise_it() {
    let cfg = load(&format!(
        r#"
[controller]
host = "h"
api_key = "k"

[limits]
max_vouchers_per_request = 5
max_validity_minutes = 600
rate_limit_per_minute = 30

[[tokens]]
name = "tighter"
hash = "{VALID_HASH}"
max_vouchers_per_request = 2
max_validity_minutes = 60
rate_limit_per_minute = 10

[[tokens]]
name = "greedy"
hash = "{VALID_HASH}"
max_vouchers_per_request = 999
max_validity_minutes = 99999
rate_limit_per_minute = 9999
"#
    ))
    .unwrap();

    let tighter = &cfg.tokens[0];
    assert_eq!(tighter.effective_max_vouchers(&cfg.limits), 2);
    assert_eq!(tighter.effective_max_validity(&cfg.limits), 60);
    assert_eq!(tighter.effective_rate_limit(&cfg.limits), 10);

    let greedy = &cfg.tokens[1];
    assert_eq!(greedy.effective_max_vouchers(&cfg.limits), 5);
    assert_eq!(greedy.effective_max_validity(&cfg.limits), 600);
    assert_eq!(greedy.effective_rate_limit(&cfg.limits), 30);
}

#[test]
fn an_unlimited_global_rate_lets_a_token_set_its_own() {
    let cfg = load(&format!(
        r#"
[controller]
host = "h"
api_key = "k"

[limits]
rate_limit_per_minute = 0

[[tokens]]
name = "capped"
hash = "{VALID_HASH}"
rate_limit_per_minute = 7

[[tokens]]
name = "uncapped"
hash = "{VALID_HASH}"
"#
    ))
    .unwrap();

    assert_eq!(cfg.tokens[0].effective_rate_limit(&cfg.limits), 7);
    assert_eq!(cfg.tokens[1].effective_rate_limit(&cfg.limits), 0);
}

#[test]
fn scopes_have_stable_wire_names() {
    // These strings appear in config files and in GraphQL responses, so they
    // are API surface, not an implementation detail.
    assert_eq!(Scope::SitesRead.as_str(), "sites:read");
    assert_eq!(Scope::VouchersRead.as_str(), "vouchers:read");
    assert_eq!(Scope::VouchersCreate.as_str(), "vouchers:create");
    assert_eq!(Scope::VouchersRevoke.as_str(), "vouchers:revoke");
}

#[test]
fn default_limits_are_the_documented_ones() {
    let d = Limits::default();
    assert_eq!(d.max_vouchers_per_request, 10);
    assert_eq!(d.max_validity_minutes, 43200);
    assert_eq!(d.rate_limit_per_minute, 60);
}

#[test]
fn scope_names_in_config_match_the_names_everywhere_else() {
    // Regression guard: these were once derived by a serde rename convention
    // and came out as `vouchers-read`, so every documented config was
    // unloadable. The config spelling and `as_str()` must stay identical.
    for scope in [
        Scope::SitesRead,
        Scope::VouchersRead,
        Scope::VouchersCreate,
        Scope::VouchersRevoke,
    ] {
        let cfg = load(&format!(
            r#"
[controller]
host = "h"
api_key = "k"

[[tokens]]
name = "t"
hash = "{VALID_HASH}"
scopes = ["{}"]
"#,
            scope.as_str()
        ))
        .unwrap_or_else(|e| panic!("scope {:?} did not load from config: {e}", scope));
        assert_eq!(cfg.tokens[0].scopes, vec![scope]);
    }
}

#[test]
fn a_config_can_come_entirely_from_the_environment() {
    // The container deployment shape: no file mounted at all.
    let _guard = env_lock();
    std::env::set_var("UVP_CONTROLLER__HOST", "10.0.0.1");
    std::env::set_var("UVP_CONTROLLER__API_KEY", "k");
    let result = Config::load(None);
    std::env::remove_var("UVP_CONTROLLER__HOST");
    std::env::remove_var("UVP_CONTROLLER__API_KEY");

    // Tokens cannot be expressed as environment variables, so this must still
    // fail — loudly, and for the right reason.
    let err = result.unwrap_err();
    assert!(err.to_string().contains("no tokens configured"), "{err}");
}
