use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::config::TlsConfig;

/// SHA-256 of a DER-encoded certificate, lowercase hex.
pub fn fingerprint(cert: &CertificateDer<'_>) -> String {
    hex::encode(Sha256::digest(cert.as_ref()))
}

/// Accepts `AB:CD:...`, `sha256:abcd...` and plain hex, case-insensitively.
pub fn normalize_fingerprint(raw: &str) -> Result<String> {
    let cleaned: String = raw
        .trim()
        .trim_start_matches("sha256:")
        .trim_start_matches("SHA256:")
        .chars()
        .filter(|c| !matches!(c, ':' | ' ' | '-'))
        .collect::<String>()
        .to_ascii_lowercase();
    if cleaned.len() != 64 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "not a SHA-256 certificate fingerprint (expected 64 hex characters, got {})",
            cleaned.len()
        ));
    }
    Ok(cleaned)
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

/// Verifies the leaf certificate by exact SHA-256 match and nothing else.
///
/// Chain, expiry and hostname are deliberately not checked: a UniFi console
/// ships a self-signed certificate that fails all three, yet pinning its exact
/// bytes still yields a channel an on-path attacker cannot take over. Swapping
/// the console legitimately means re-pinning, which is the intended friction.
#[derive(Debug)]
struct PinnedVerifier {
    /// Every fingerprint that counts as "this is the controller". Usually one.
    expected: Vec<String>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let actual = fingerprint(end_entity);
        // Length-equal hex strings; a plain comparison leaks no useful timing
        // signal because the expected values are not secrets.
        if self.expected.contains(&actual) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(format!(
                "controller certificate fingerprint mismatch: pinned {}, presented {}",
                self.expected.join(" or "),
                actual
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Accepts everything and records what it saw. Used by `insecure_skip_verify`
/// and by the `fetch-fingerprint` subcommand.
#[derive(Debug)]
struct CapturingVerifier {
    seen: Arc<Mutex<Option<String>>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        *self.seen.lock().expect("fingerprint mutex poisoned") = Some(fingerprint(end_entity));
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Builds the rustls config for talking to the controller.
///
/// Three modes, in order of preference:
///   1. `fingerprint_sha256` set — pin the leaf certificate.
///   2. neither set — ordinary WebPKI verification, which works only if the
///      console has a real certificate. This is the secure default and fails
///      loudly on a stock self-signed console.
///   3. `insecure_skip_verify` — accept anything, for first-run discovery only.
pub fn client_config(cfg: &TlsConfig) -> Result<ClientConfig> {
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("failed to select TLS protocol versions")?;

    if let Some(raw) = &cfg.fingerprint_sha256 {
        let expected = raw
            .iter()
            .map(|r| {
                normalize_fingerprint(r).context("controller.tls.fingerprint_sha256 is not usable")
            })
            .collect::<Result<Vec<_>>>()?;
        return Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedVerifier { expected, provider }))
            .with_no_client_auth());
    }

    if cfg.insecure_skip_verify {
        return Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(CapturingVerifier {
                seen: Arc::new(Mutex::new(None)),
                provider,
            }))
            .with_no_client_auth());
    }

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Ok(builder.with_root_certificates(roots).with_no_client_auth())
}

/// Opens a throwaway TLS connection and returns the leaf fingerprint. Powers
/// `unifi-voucher-proxy fetch-fingerprint`, so nobody has to hand-drive openssl.
pub async fn probe_fingerprint(url: &str, timeout: std::time::Duration) -> Result<String> {
    let seen = Arc::new(Mutex::new(None));
    let provider = provider();
    let tls = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("failed to select TLS protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CapturingVerifier {
            seen: Arc::clone(&seen),
            provider,
        }))
        .with_no_client_auth();

    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .timeout(timeout)
        .build()
        .context("failed to build probe client")?;

    // The response itself is irrelevant — the handshake is what we came for, so
    // a 401 or 404 is just as good as a 200.
    let _ = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("could not open a TLS connection to {url}"))?;

    let captured = seen.lock().expect("fingerprint mutex poisoned").clone();
    captured.ok_or_else(|| anyhow!("connection succeeded but no certificate was presented"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_the_common_fingerprint_spellings() {
        let want = "a".repeat(64);
        assert_eq!(normalize_fingerprint(&want.to_uppercase()).unwrap(), want);
        assert_eq!(
            normalize_fingerprint(&format!("sha256:{want}")).unwrap(),
            want
        );
        let colonized = want
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(normalize_fingerprint(&colonized).unwrap(), want);
    }

    #[test]
    fn rejects_things_that_are_not_fingerprints() {
        assert!(normalize_fingerprint("deadbeef").is_err());
        assert!(normalize_fingerprint(&"z".repeat(64)).is_err());
        assert!(normalize_fingerprint("").is_err());
    }
}
