use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use password_hash::rand_core::OsRng;
use password_hash::{PasswordHashString, SaltString};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::config::TokenConfig;

/// Prefix on generated tokens so a leaked one is recognisable in a log or a
/// secret scanner.
const TOKEN_PREFIX: &str = "uvp_";

/// Mints a fresh client token and its Argon2id hash.
pub fn generate_token() -> Result<(String, String)> {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let token = format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
    let hash = hash_token(&token)?;
    Ok((token, hash))
}

/// Minimum estimated entropy for a self-chosen key, in bits.
///
/// 80 bits is far past anything guessable online, while still allowing a
/// memorable four-or-five-word passphrase. Generated tokens carry 256.
const MIN_ENTROPY_BITS: f64 = 80.0;

/// Judges a self-chosen API key and explains itself when it says no.
///
/// Custom keys are supported because operators often have their own secret
/// management, but an API key in front of a UniFi console is not a place for
/// `letmein`. The estimate is the classic pool-size model, deliberately
/// pessimistic, plus a distinct-character floor so that a long run of one
/// character cannot score well.
pub fn assess_strength(token: &str) -> Result<f64, String> {
    let len = token.chars().count();
    if len < 16 {
        return Err(format!(
            "too short: {len} characters, at least 16 are required"
        ));
    }

    let mut pool = 0u32;
    if token.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if token.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if token.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if token.chars().any(|c| !c.is_ascii_alphanumeric()) {
        pool += 33;
    }

    let distinct = token
        .chars()
        .collect::<std::collections::HashSet<_>>()
        .len();
    if distinct < 8 {
        return Err(format!(
            "only {distinct} distinct characters — a repetitive key is weak however long it is"
        ));
    }

    let bits = (len as f64) * (pool as f64).log2();
    if bits < MIN_ENTROPY_BITS {
        return Err(format!(
            "roughly {bits:.0} bits of entropy, {MIN_ENTROPY_BITS:.0} are required — make it longer or mix in more character classes"
        ));
    }
    Ok(bits)
}

pub fn hash_token(token: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(token.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("failed to hash token: {e}"))?
        .to_string())
}

/// Verifies presented tokens against the configured Argon2id hashes.
///
/// Argon2 is intentionally slow, which is right for the failure path but would
/// add tens of milliseconds to every legitimate request. Successful
/// verifications are therefore memoised under a SHA-256 of the presented token;
/// the cache is bounded by the number of configured tokens because failures are
/// never cached, so a flood of invalid tokens still pays full Argon2 cost.
pub struct Authenticator {
    /// Each token with its hash already parsed. Parsing at construction means a
    /// malformed hash is a startup failure rather than a per-request branch
    /// that can never be exercised or tested.
    tokens: Vec<(Arc<TokenConfig>, PasswordHashString)>,
    cache: Mutex<HashMap<[u8; 32], usize>>,
}

impl Authenticator {
    pub fn new(tokens: &[TokenConfig]) -> Result<Self> {
        let parsed = tokens
            .iter()
            .map(|t| {
                let hash = PasswordHash::new(&t.hash)
                    .map_err(|e| anyhow::anyhow!("token '{}' has an unparsable hash: {e}", t.name))?
                    .serialize();
                Ok((Arc::new(t.clone()), hash))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            tokens: parsed,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Returns the matching token config, or `None` if the value is unknown.
    pub fn authenticate(&self, presented: &str) -> Option<Arc<TokenConfig>> {
        if presented.is_empty() {
            return None;
        }
        let key: [u8; 32] = Sha256::digest(presented.as_bytes()).into();

        if let Some(&idx) = self.cache.lock().expect("auth cache poisoned").get(&key) {
            return self.tokens.get(idx).map(|(t, _)| Arc::clone(t));
        }

        // No early exit: every candidate is checked so the time taken does not
        // depend on which token happened to match.
        let mut found = None;
        for (idx, (_, hash)) in self.tokens.iter().enumerate() {
            if Argon2::default()
                .verify_password(presented.as_bytes(), &hash.password_hash())
                .is_ok()
                && found.is_none()
            {
                found = Some(idx);
            }
        }

        let idx = found?;
        self.cache
            .lock()
            .expect("auth cache poisoned")
            .insert(key, idx);
        self.tokens.get(idx).map(|(t, _)| Arc::clone(t))
    }
}

impl std::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authenticator")
            .field("tokens", &self.tokens.len())
            .finish_non_exhaustive()
    }
}

/// Checks a token against a hash. Used by `hash-token`'s own tests and by
/// anyone wanting to confirm a stored hash still matches their key.
pub fn verify_pair(token: &str, hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(hash).map_err(|e| anyhow::anyhow!("bad hash: {e}"))?;
    Ok(Argon2::default()
        .verify_password(token.as_bytes(), &parsed)
        .is_ok())
}

/// Reads the client token from the request headers.
///
/// `X-API-KEY` is what the UniFi Integration API itself uses, so drop-in
/// clients need no changes; `Authorization: Bearer` is accepted for everything
/// else.
pub fn token_from_headers(headers: &axum::http::HeaderMap) -> Option<&str> {
    if let Some(v) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        if !v.is_empty() {
            return Some(v);
        }
    }
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| !v.is_empty())
}

pub fn load_hash_check(hash: &str) -> Result<()> {
    PasswordHash::new(hash)
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("not a valid Argon2 PHC string")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Scope;

    fn token_config(name: &str, hash: String) -> TokenConfig {
        TokenConfig {
            name: name.to_string(),
            hash,
            sites: vec!["*".into()],
            scopes: vec![Scope::VouchersRead],
            max_vouchers_per_request: None,
            max_validity_minutes: None,
            rate_limit_per_minute: None,
        }
    }

    #[test]
    fn generated_tokens_verify_against_their_hash() {
        let (token, hash) = generate_token().unwrap();
        assert!(token.starts_with(TOKEN_PREFIX));
        assert!(verify_pair(&token, &hash).unwrap());
        assert!(!verify_pair("uvp_wrong", &hash).unwrap());
    }

    #[test]
    fn authenticates_known_tokens_and_rejects_others() {
        let (alpha, alpha_hash) = generate_token().unwrap();
        let (beta, beta_hash) = generate_token().unwrap();
        let auth = Authenticator::new(&[
            token_config("alpha", alpha_hash),
            token_config("beta", beta_hash),
        ])
        .unwrap();

        assert_eq!(auth.authenticate(&alpha).unwrap().name, "alpha");
        assert_eq!(auth.authenticate(&beta).unwrap().name, "beta");
        // Second lookup goes through the cache and must agree.
        assert_eq!(auth.authenticate(&alpha).unwrap().name, "alpha");
        assert!(auth.authenticate("uvp_nope").is_none());
        assert!(auth.authenticate("").is_none());
    }

    #[test]
    fn failed_lookups_do_not_grow_the_cache() {
        let (token, hash) = generate_token().unwrap();
        let auth = Authenticator::new(&[token_config("only", hash)]).unwrap();
        for i in 0..20 {
            assert!(auth.authenticate(&format!("uvp_bogus{i}")).is_none());
        }
        assert_eq!(auth.cache.lock().unwrap().len(), 0);
        assert!(auth.authenticate(&token).is_some());
        assert_eq!(auth.cache.lock().unwrap().len(), 1);
    }

    #[test]
    fn accepts_a_reasonable_custom_key() {
        assert!(assess_strength("Kj8#mQp2vN9xL4wR7tZ").is_ok());
        assert!(assess_strength("correct-horse-battery-staple-42").is_ok());
        assert!(assess_strength(&generate_token().unwrap().0).is_ok());
    }

    #[test]
    fn refuses_keys_that_are_not_worth_having() {
        for weak in [
            "short",                      // too short
            "letmein123",                 // too short
            "aaaaaaaaaaaaaaaaaaaaaaaaaa", // repetitive
            "abababababababababab",       // few distinct characters
            "passwordpassword",           // 16 chars, lowercase only -> ~75 bits
        ] {
            assert!(
                assess_strength(weak).is_err(),
                "{weak:?} should have been refused"
            );
        }
    }

    #[test]
    fn custom_keys_hash_and_authenticate_like_generated_ones() {
        let custom = "Kj8#mQp2vN9xL4wR7tZ";
        let hash = hash_token(custom).unwrap();
        let auth = Authenticator::new(&[token_config("custom", hash)]).unwrap();
        assert_eq!(auth.authenticate(custom).unwrap().name, "custom");
        assert!(auth.authenticate("Kj8#mQp2vN9xL4wR7tY").is_none());
    }

    #[test]
    fn refuses_a_key_with_enough_variety_but_too_little_length() {
        // 16 distinct lowercase characters: passes the distinct-character
        // floor, still only ~75 bits, so the entropy rule must catch it.
        let err = assess_strength("abcdefghijklmnop").unwrap_err();
        assert!(err.contains("bits of entropy"), "{err}");
    }

    #[test]
    fn the_authenticator_does_not_print_its_tokens() {
        let (_, hash) = generate_token().unwrap();
        let auth = Authenticator::new(&[token_config("secretive", hash)]).unwrap();
        let rendered = format!("{auth:?}");
        assert!(rendered.contains("Authenticator"));
        assert!(rendered.contains('1'), "should report how many, not which");
        assert!(!rendered.contains("secretive") && !rendered.contains("argon2"));
    }

    #[test]
    fn a_malformed_hash_fails_at_construction_not_at_request_time() {
        let err = Authenticator::new(&[token_config("broken", "not-a-hash".into())]).unwrap_err();
        assert!(err.to_string().contains("unparsable hash"));
    }

    #[test]
    fn load_hash_check_accepts_real_hashes_and_rejects_the_rest() {
        let (_, hash) = generate_token().unwrap();
        assert!(load_hash_check(&hash).is_ok());
        assert!(load_hash_check("uvp_raw_token").is_err());
    }

    #[test]
    fn verify_pair_reports_a_bad_hash_rather_than_a_bad_match() {
        assert!(verify_pair("anything", "not-a-phc-string").is_err());
    }

    #[test]
    fn an_empty_x_api_key_falls_through_to_the_bearer_header() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-api-key", "".parse().unwrap());
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer fallback".parse().unwrap(),
        );
        assert_eq!(token_from_headers(&headers), Some("fallback"));

        // An empty Bearer is not a token either.
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer ".parse().unwrap(),
        );
        assert_eq!(token_from_headers(&headers), None);

        // Nor is a non-Bearer scheme.
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Basic abc".parse().unwrap(),
        );
        assert_eq!(token_from_headers(&headers), None);
    }

    #[test]
    fn reads_both_header_styles() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-api-key", "abc".parse().unwrap());
        assert_eq!(token_from_headers(&headers), Some("abc"));

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer xyz".parse().unwrap(),
        );
        assert_eq!(token_from_headers(&headers), Some("xyz"));

        assert_eq!(token_from_headers(&axum::http::HeaderMap::new()), None);
    }
}
