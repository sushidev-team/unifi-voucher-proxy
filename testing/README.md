# Local end-to-end testing

```sh
cargo build --bin unifi-voucher-proxy
cargo build --features testing --bin fake-controller
./testing/e2e.sh
```

Starts a fake UniFi console, points a real proxy at it and runs ~32 checks
through both REST and GraphQL: the allowlist, authentication, per-token scopes
and site limits, request policy, and that neither the controller key nor a
client token ever reaches the audit log.

Set `SP=/some/dir` to keep the generated config, tokens and logs.

## Why a fake and not a real controller

The Integration API is a UniFi OS feature. A Docker `unifi-network-application`
is the Network application without UniFi OS, so it has no
`/proxy/network/integration/v1` and no API keys at all — it cannot exercise what
the proxy does.

A real console can, but will not produce a 401, a timeout or a certificate
change on request, and every run leaves real vouchers behind.

The fake serves a self-signed certificate, so certificate pinning is exercised
rather than skipped, and reproduces the response quirks that have each cost a
bug: `POST` answers `{"vouchers": […]}` while `GET` answers `{"data": […]}`, and
vouchers carry no `expiresAt`.

## Why it is a separate binary

`cargo build` produces exactly one binary. The proxy's claim is that it only
ever forwards four named calls; a demo mode inside it would make that claim
conditional and, misconfigured, would hand out voucher codes that do not work.

    cargo run --features testing --bin fake-controller -- --help

`--always-401`, `--delay-ms` and `--api-key` cover the upstream failure paths.
