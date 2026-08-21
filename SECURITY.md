# Security

## What this proxy is for

A UniFi Network Integration API key carries the full rights of the admin
account that created it, and Ubiquiti provides no way to scope one down to a
subset of endpoints. So handing that key to any third-party app means handing
over the console.

This proxy is the scope that UniFi does not offer. The key lives on hardware you
control; clients get their own tokens that can do nothing but manage hotspot
vouchers on the sites you name.

## Threat model

**Defended against**

- *A compromised or malicious client.* A client token cannot reach any endpoint
  other than the four voucher operations, on any site outside its allowlist,
  beyond its scopes, or above its quotas. This is enforced by routing (there is
  no catch-all forwarder) and by the type system (`Upstream` exposes named
  operations only, not a generic "proxy this path" method).
- *A stolen client token.* It is limited to that token's grants, appears in the
  audit log under its own name, and is revoked by deleting one config entry.
- *A stolen config file.* Tokens are stored as Argon2id hashes, not plaintext.
  The controller key is not in the file at all if you pass it via the
  environment, as the example config recommends.
- *An on-path attacker on your LAN.* With `fingerprint_sha256` set, the proxy
  talks only to the exact certificate you pinned. A device that ARP-spoofs the
  controller's address gets a failed handshake instead of your API key.
- *Path traversal and parameter smuggling.* Site and voucher ids are validated
  against a strict alphabet; request bodies are parsed into a closed struct and
  re-serialised, so no field the proxy does not understand ever reaches the
  controller.
- *Credential leakage through logs.* The API key is wrapped in a type whose
  `Debug` and `Display` render `***`. Audit records carry the token *name*,
  never its value, and never voucher codes.

**Not defended against**

- *Anyone who can read the proxy's memory or its environment.* The key is
  plaintext in RAM by necessity. Run the proxy on a host you trust.
- *A malicious controller.* If the console itself is compromised, this changes
  nothing. Redirects are disabled so it cannot bounce the key elsewhere, but
  that is the limit.
- *Transport between client and proxy.* The proxy speaks plain HTTP and expects
  to sit behind your own TLS terminator, or on a network segment you trust. On
  an untrusted network, put it behind a reverse proxy with a real certificate.
- *Denial of service.* Per-token rate limits exist to bound accidental
  hammering and to make a stolen token less useful. They are not DoS protection.

## Reporting a vulnerability

Mail **security@getvouchers.app** with details and, if you have one, a
reproduction. Please do not open a public issue for anything exploitable. We
aim to acknowledge within 72 hours.

## Verifying what you run

The point of this project is that you do not have to trust us:

- Read `src/routes.rs` — every reachable path is in one `router()` function.
- Read `src/upstream.rs` — every call the proxy can make to your controller is a
  named method there. There is no dynamic path forwarding.
- Run `cargo test` — `tests/proxy.rs` asserts the refusals end to end against a
  stubbed controller, including that blocked requests produce no upstream
  traffic at all.
- Build the image yourself: `docker build -t unifi-voucher-proxy .`
