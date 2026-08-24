# unifi-voucher-proxy

For https://getvouchers.app

**The API-key scope that UniFi does not give you.**

A UniFi Network Integration API key inherits every right of the admin that
created it, and Ubiquiti offers no way to restrict one to a subset of endpoints.
So "just give the voucher app an API key" means handing that app your whole
console — which is a perfectly reasonable thing to refuse.

This proxy is the missing scope. Run it on hardware you control. It holds the
real key; clients get their own tokens that can do exactly four things, on the
sites you name, within the quotas you set, with every call written to an audit
log.

```
  voucher app ──[ proxy token ]──▶  unifi-voucher-proxy  ──[ real API key ]──▶  UniFi console
                                    scopes · site allowlist
                                    quotas · request policy · audit log
```

- **Rust**, no runtime dependencies, ~5 MB `scratch` container.
- **REST** (drop-in compatible with the UniFi Integration API) **and GraphQL**.
- **Certificate pinning** upstream, so nobody on your LAN can impersonate the
  console and collect the key.
- **Argon2id-hashed client tokens** — a stolen config file is not a working
  credential.
- Everything the proxy can do to your controller is a named method in one
  ~120-line file. Read it in five minutes.

---

## Quick start

```sh
# 1. Get the image (or build it yourself — see "Verify what you run")
docker pull ghcr.io/sushidev-team/unifi-voucher-proxy:latest

# 2. Learn your console's certificate fingerprint
docker run --rm ghcr.io/sushidev-team/unifi-voucher-proxy \
  fetch-fingerprint --host 192.168.1.1

# 3. Mint a token for your first client
docker run --rm ghcr.io/sushidev-team/unifi-voucher-proxy \
  hash-token --name reception-iphone
```

Write `config.toml` from the snippets those two commands printed
(see [`config.example.toml`](config.example.toml) for the full set of options):

```toml
[controller]
host = "192.168.1.1"
# api_key comes from the environment — see compose.yaml

[controller.tls]
fingerprint_sha256 = "3b7c…"     # from `fetch-fingerprint`

[limits]
max_vouchers_per_request = 10
max_validity_minutes = 43200
rate_limit_per_minute = 60

[[tokens]]
name = "reception-iphone"
hash = "$argon2id$v=19$…"         # from `hash-token`
sites = ["*"]
scopes = ["sites:read", "vouchers:read", "vouchers:create", "vouchers:revoke"]
```

Then:

```sh
echo "UNIFI_API_KEY=your-real-unifi-key" > .env
docker compose up -d
docker compose exec unifi-voucher-proxy /usr/local/bin/unifi-voucher-proxy check-config
```

`check-config` prints exactly what each token may do — worth reading once before
you point anything at it.

---

## Using it

Point your voucher app at the **proxy** instead of the console, with the
**proxy token** instead of the API key. The paths are identical to the UniFi
Integration API, so nothing else changes:

| | |
|---|---|
| Host | `http://proxy-host:8080` instead of `https://192.168.1.1` |
| Key | your `uvp_…` token instead of the UniFi API key |

### REST

```
GET    /proxy/network/integration/v1/sites
GET    /proxy/network/integration/v1/sites/{site}/hotspot/vouchers
POST   /proxy/network/integration/v1/sites/{site}/hotspot/vouchers
DELETE /proxy/network/integration/v1/sites/{site}/hotspot/vouchers/{id}

GET    /proxy/info      what this token may do
GET    /healthz         liveness, no auth
```

Every other path answers `403`, and produces no traffic to your controller at
all.

### GraphQL

`POST /graphql`, same `X-API-KEY` header. `GET /graphql/schema` returns the SDL;
set `graphql_playground = true` under `[server]` to also serve GraphiQL at
`GET /graphql`.

```graphql
query WhatMayIDo {
  info { name sites scopes maxVouchersPerRequest maxValidityMinutes }
}

query Existing {
  vouchers(siteId: "default") {
    id code name timeLimitMinutes authorizedGuestCount expired expiresAt
  }
}

mutation Issue {
  createVouchers(
    siteId: "default"
    input: { name: "Guest", count: 5, timeLimitMinutes: 480, authorizedGuestLimit: 2 }
  ) { id code expiresAt }
}

mutation Revoke {
  revokeVoucher(siteId: "default", voucherId: "abc123") { id revoked }
}
```

Errors carry `extensions.code` (`forbidden`, `rate_limited`, `bad_request`, …)
and `extensions.status`, so clients can branch without parsing messages.

The GraphQL layer adds no reach: it runs through the same scopes, site
allowlist, quotas and request policy, charges quota per upstream call so one
document cannot fan out for free, bounds query depth and complexity, and does
not accept batched documents. `tests/graphql.rs` asserts each of those.

---

## Rate limiting

Two budgets, and they answer different questions.

`limits.rate_limit_per_minute` is per token and bounds load on the console. A
token may tighten it, never raise it.

`limits.rate_limit_per_ip_per_minute` is per client IP and is charged *before*
authentication, defaulting to 120. Checking a token costs a full Argon2 hash
against every configured hash and a wrong token is deliberately never cached, so
without it anyone who can reach the port decides how much CPU the machine
spends. That means **a client can see a 429 before its token is even looked at**
— worth knowing when a device reports being throttled and its own quota looks
untouched.

It keys on the peer address and deliberately ignores `X-Forwarded-For`, which
anyone can set. Behind a reverse proxy every client shares one address, so let
that proxy own this limit and set `0` here.

## Tokens

```sh
# generate one (256 bits, printed once)
unifi-voucher-proxy hash-token --name lobby-display

# or bring your own key, without putting it in your shell history
printf %s "$MY_KEY" | unifi-voucher-proxy hash-token --name lobby-display --stdin
```

Self-chosen keys are checked for strength (≥16 characters, ≥8 distinct, ≥80 bits
estimated entropy) and refused if weak — `--allow-weak` overrides. Only the
Argon2id hash goes in the config; the key itself is never stored.

**Scopes:** `sites:read`, `vouchers:read`, `vouchers:create`, `vouchers:revoke`.

A read-only lobby display, for instance:

```toml
[[tokens]]
name = "lobby-display"
hash = "$argon2id$…"
sites = ["66c2f1e9-4b3a-4f21-9d0e-1a2b3c4d5e6f"]
scopes = ["vouchers:read"]
rate_limit_per_minute = 10
```

A token restricted to one site cannot even see that the others exist —
`GET /sites` and the `sites` query both filter to its allowlist.

Revoking a token is deleting its `[[tokens]]` block and restarting. Its name
appears on every line it caused in the audit log.

---

## Metrics and reloading

Prometheus metrics are served on a listener of their own, and only if you ask
for one:

```toml
[server]
metrics_bind = "0.0.0.0:9090"
```

They live on a separate socket because the labels carry token names, which are
chosen to identify devices — the exposition is an inventory of the premises and
of who does what. Keeping it off the main port means who may read it is a
published port rather than another credential, and the client tokens stay
limited to the four voucher scopes. In a container, publish it narrowly:

```yaml
ports:
  - "8080:8080"
  - "127.0.0.1:9090:9090"
```

`SIGHUP` re-reads the config file: tokens can be added or revoked without
dropping the connections of the ones that still work. A config that fails to
load is rejected and the running one keeps serving, so a typo costs a log line
rather than the service.

```sh
docker compose kill -s HUP unifi-voucher-proxy
```

## Certificate pinning

UniFi consoles ship a self-signed certificate, so ordinary verification always
fails and most tools respond by turning verification off entirely. That leaves
the API key exposed to anyone who can ARP-spoof the console's address — on a
guest network, that is a meaningful set of people.

Pin it instead:

```sh
unifi-voucher-proxy fetch-fingerprint --host 192.168.1.1
```

and put the result in `controller.tls.fingerprint_sha256`. The proxy will then
talk only to that exact certificate. If you re-provision the console, the
handshake fails loudly until you re-pin — which is the correct behaviour, since
that event and an attack look the same from here.

More than one certificate can be legitimate: UniFi OS serves a different leaf
depending on the name it is reached by, and a planned rotation means the old and
the new one are both valid for a while. The field takes a list for that:

```toml
fingerprint_sha256 = ["064d0b67…", "54071a43…"]
```

Every entry is still an exact pin — a list widens *which* certificates count,
never *whether* they are checked, and a malformed entry is refused at startup
rather than carried by the good ones. Only add a fingerprint you have verified
belongs to your console.

`insecure_skip_verify` exists for first-run discovery, warns on every start, and
should not survive setup. If you have weighed that and want the reminder out of
your log, `silence_insecure_warning = true` silences it — and nothing else:
`check-config` still reports `INSECURE`, so one command always tells the truth.

---

## Verify what you run

The whole point is that you do not have to take our word for any of this.

```sh
git clone https://github.com/sushidev-team/unifi-voucher-proxy
cd unifi-voucher-proxy
cargo test            # includes the end-to-end refusal tests
docker build -t unifi-voucher-proxy .
```

Released images — the version tags and `latest` — are built with
`PROFILE=dist`, which adds fat LTO for a roughly 2.6 MB smaller binary. Branch
and `sha-` images use the default `release` profile, which skips the LTO link
and builds much faster. To reproduce the bytes behind a release tag, and so the
attestation below, pass it:

```sh
docker build --build-arg PROFILE=dist -t unifi-voucher-proxy .
```

- [`src/routes.rs`](src/routes.rs) — every path the proxy serves, in one function.
- [`src/upstream.rs`](src/upstream.rs) — every call it can make to your
  controller. Named methods only; there is no generic path forwarder, so
  "forward anything" is not a bug that can be introduced by misconfiguration.
- [`tests/proxy.rs`](tests/proxy.rs) — asserts that blocked requests produce
  **zero** upstream traffic, that the real key never appears in a client
  response, and that presenting the real key to the proxy does not authenticate.
- [`SECURITY.md`](SECURITY.md) — threat model, including what this does *not*
  protect against.

Published images carry build provenance attestation:

```sh
gh attestation verify oci://ghcr.io/sushidev-team/unifi-voucher-proxy:latest \
  --repo sushidev-team/unifi-voucher-proxy
```

---

## Before you need this

Worth knowing: a UniFi API key inherits the role of the admin that created it.
If you make a **limited local admin** (Site Admin, or View Only for read-only
use) and generate the key under that account, the key is already narrowed — and
a dedicated site for guest WiFi narrows it further.

That is free and worth doing regardless. This proxy is for when you want the
scope to be *yours*: enforced by software you run and can read, rather than by
a role model you do not control.

---

## Configuration reference

See [`config.example.toml`](config.example.toml). Every value can also come from
the environment with a `UVP_` prefix and `__` between levels, which is how the
controller key should be supplied:

```sh
UVP_CONTROLLER__API_KEY=…
UVP_CONTROLLER__HOST=192.168.1.1
UVP_SERVER__BIND=0.0.0.0:8080
UVP_LOG=unifi_voucher_proxy=debug,audit=info
UVP_LOG_FORMAT=json
```

## Commands

| | |
|---|---|
| `serve` | run the proxy (default) |
| `hash-token` | mint or hash a client token |
| `fetch-fingerprint` | read the console's certificate fingerprint |
| `check-config` | validate config and print what it grants |
| `healthcheck` | probe a running instance (used by the container healthcheck) |

## License

MIT
