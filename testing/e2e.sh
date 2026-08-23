#!/usr/bin/env bash
# Live end-to-end check of unifi-voucher-proxy against the real controller.
# Requires UVP_CONTROLLER__API_KEY in the environment. Prints no secrets.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
# Set SP to keep the config, tokens and logs around for inspection.
SP="${SP:-$(mktemp -d)}"
BIN="$ROOT/target/debug/unifi-voucher-proxy"
FAKE="$ROOT/target/debug/fake-controller"

if [ ! -x "$BIN" ] || [ ! -x "$FAKE" ]; then
  echo "build them first:"
  echo "  cargo build --bin unifi-voucher-proxy"
  echo "  cargo build --features testing --bin fake-controller"
  exit 1
fi

# A fake console rather than a real one: the Integration API is a UniFi OS
# feature, so a Docker unifi-network-application does not have it, and a real
# console will not produce a 401 or a timeout on request.
"$FAKE" --bind 127.0.0.1:18443 >"$SP/fake.log" 2>&1 &
FAKE_PID=$!
trap 'kill $FAKE_PID 2>/dev/null' EXIT
for _ in $(seq 1 40); do grep -q fingerprint "$SP/fake.log" && break; sleep 0.25; done

# A stale fake from an earlier run keeps the port, the new one dies, and the
# config ends up pinned to a certificate nothing is serving — which surfaces
# much later as an unhelpful "upstream unreachable".
if grep -q "Address already in use" "$SP/fake.log"; then
  echo "port 18443 is taken — something else is listening:"
  lsof -nP -iTCP:18443 -sTCP:LISTEN 2>/dev/null | tail -n +2
  exit 1
fi

FINGERPRINT=$(grep -oE "fingerprint  [0-9a-f]{64}" "$SP/fake.log" | cut -d" " -f3)
[ -n "$FINGERPRINT" ] || { echo "the fake console did not start; see $SP/fake.log"; exit 1; }
export UVP_CONTROLLER__API_KEY=test-api-key

"$BIN" hash-token --name e2e-test    >"$SP/t1" 2>/dev/null
"$BIN" hash-token --name e2e-readonly >"$SP/t2" 2>/dev/null
grep -oE "uvp_[A-Za-z0-9_-]+" "$SP/t1" | head -1 > "$SP/proxy_token"
grep -oE "uvp_[A-Za-z0-9_-]+" "$SP/t2" | head -1 > "$SP/proxy_token_ro"

cat > "$SP/e2e-config.toml" <<CFG
[server]
bind = "127.0.0.1:18099"

[controller]
host = "https://127.0.0.1:18443"
api_key = ""

[controller.tls]
fingerprint_sha256 = "$FINGERPRINT"

[limits]
max_vouchers_per_request = 2
max_validity_minutes = 43200
rate_limit_per_minute = 0

[[tokens]]
name = "e2e-test"
hash = "$(grep -oE '\$argon2[^"]+' "$SP/t1" | head -1)"
sites = ["*"]
scopes = ["sites:read", "vouchers:read", "vouchers:create", "vouchers:revoke"]

[[tokens]]
name = "e2e-readonly"
hash = "$(grep -oE '\$argon2[^"]+' "$SP/t2" | head -1)"
sites = ["no-such-site"]
scopes = ["vouchers:read"]
CFG
BASE=http://127.0.0.1:18099
API=$BASE/proxy/network/integration/v1
TOKEN=$(cat "$SP/proxy_token")
RO_TOKEN=$(cat "$SP/proxy_token_ro")
pass=0; fail=0

ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31m✗\033[0m %s — %s\n' "$1" "$2"; fail=$((fail+1)); }
check(){ # check <desc> <expected-status> <actual-status>
  [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected HTTP $2, got $3"; }

status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
body()   { curl -s "$@"; }

echo "▶ starting proxy"
# JSON logs: the pretty format puts ANSI escapes between a field name and
# its value, so asserting on it means grepping through escape codes.
UVP_LOG_FORMAT=json "$BIN" serve --config "$SP/e2e-config.toml" >"$SP/proxy.log" 2>&1 &
PROXY=$!
trap 'kill $PROXY $FAKE_PID 2>/dev/null' EXIT
for _ in $(seq 1 40); do
  [ "$(status $BASE/healthz)" = "200" ] && break; sleep 0.25
done

echo
echo "── reachability ──"
check "/healthz answers without a token" 200 "$(status $BASE/healthz)"

echo
echo "── authentication ──"
check "no token is refused"        401 "$(status $API/sites)"
check "an invalid token is refused" 401 "$(status -H "X-API-KEY: uvp_not-a-real-token" $API/sites)"
check "the controller's own key does not open the proxy" 401 \
      "$(status -H "X-API-KEY: $UVP_CONTROLLER__API_KEY" $API/sites)"

echo
echo "── the allowlist ──"
for p in \
  "sites/default/devices" "sites/default/clients" "sites/default/firewall/rules" \
  "sites/default/hotspot/guests"; do
  check "blocked: /$p" 403 "$(status -H "X-API-KEY: $TOKEN" "$API/$p")"
done
check "blocked: classic API"  403 "$(status -H "X-API-KEY: $TOKEN" "$BASE/proxy/network/api/s/default/rest/wlanconf")"
check "blocked: /api/self"    403 "$(status -H "X-API-KEY: $TOKEN" "$BASE/api/self")"
check "blocked: PUT on an allowed path" 403 "$(status -X PUT -H "X-API-KEY: $TOKEN" "$API/sites")"

echo
echo "── REST end to end ──"
SITES=$(body -H "X-API-KEY: $TOKEN" $API/sites)
SITE=$(echo "$SITES" | python3 -c 'import sys,json; d=json.load(sys.stdin); print((d.get("data") or [{}])[0].get("id",""))' 2>/dev/null)
[ -n "$SITE" ] && ok "listed sites from the controller (site id resolved)" \
               || bad "listing sites" "no site id in response"

CREATED=$(body -X POST -H "X-API-KEY: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"proxy-e2e","count":1,"timeLimitMinutes":60,"authorizedGuestLimit":1}' \
  "$API/sites/$SITE/hotspot/vouchers")
VID=$(echo "$CREATED" | python3 -c '
import sys,json
d=json.load(sys.stdin)
rows = d.get("vouchers") or d.get("data") or []
print(rows[0]["id"] if rows else "")' 2>/dev/null)
[ -n "$VID" ] && ok "created a real voucher through the proxy" \
              || bad "creating a voucher" "$(echo "$CREATED" | head -c 160)"

LISTED=$(body -H "X-API-KEY: $TOKEN" "$API/sites/$SITE/hotspot/vouchers")
echo "$LISTED" | grep -q "proxy-e2e" && ok "the new voucher appears in the list" \
                                     || bad "listing vouchers" "created voucher not found"

echo
echo "── request policy ──"
check "count above the token's ceiling is refused" 403 \
  "$(status -X POST -H "X-API-KEY: $TOKEN" -H 'Content-Type: application/json' \
     -d '{"name":"nope","count":5,"timeLimitMinutes":60}' "$API/sites/$SITE/hotspot/vouchers")"
check "an unknown field in the body is refused" 400 \
  "$(status -X POST -H "X-API-KEY: $TOKEN" -H 'Content-Type: application/json' \
     -d '{"name":"nope","count":1,"timeLimitMinutes":60,"adminOverride":true}' "$API/sites/$SITE/hotspot/vouchers")"
check "a traversing site id is refused" 400 \
  "$(status -H "X-API-KEY: $TOKEN" "$API/sites/..%2F..%2Fapi%2Fself/hotspot/vouchers")"

echo
echo "── the restricted token ──"
check "read-only token cannot create" 403 \
  "$(status -X POST -H "X-API-KEY: $RO_TOKEN" -H 'Content-Type: application/json' \
     -d '{"name":"nope","count":1,"timeLimitMinutes":60}' "$API/sites/$SITE/hotspot/vouchers")"
check "read-only token cannot revoke" 403 \
  "$(status -X DELETE -H "X-API-KEY: $RO_TOKEN" "$API/sites/$SITE/hotspot/vouchers/$VID")"
check "site-scoped token cannot reach another site" 403 \
  "$(status -H "X-API-KEY: $RO_TOKEN" "$API/sites/$SITE/hotspot/vouchers")"

echo
echo "── GraphQL ──"
gql() { body -X POST -H "X-API-KEY: $1" -H 'Content-Type: application/json' \
        -d "{\"query\":$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$2")}" $BASE/graphql; }

gql "$TOKEN" '{ info { name scopes maxVouchersPerRequest } }' | grep -q '"e2e-test"' \
  && ok "info reports the token" || bad "graphql info" "unexpected response"
gql "$TOKEN" "{ vouchers(siteId: \"$SITE\") { id code name } }" | grep -q 'proxy-e2e' \
  && ok "graphql lists the voucher created over REST" || bad "graphql vouchers" "voucher not found"

GID=$(gql "$TOKEN" "mutation { createVouchers(siteId: \"$SITE\", input: {name: \"proxy-e2e-gql\", count: 1, timeLimitMinutes: 60}) { id } }" \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print((d.get("data") or {}).get("createVouchers",[{}])[0].get("id",""))' 2>/dev/null)
[ -n "$GID" ] && ok "created a real voucher over GraphQL" || bad "graphql create" "no id returned"

gql "$TOKEN" '{ vouchers(siteId: "../../api/self") { id } }' | grep -q 'bad_request' \
  && ok "graphql enforces id validation too" || bad "graphql id validation" "not refused"
gql "$RO_TOKEN" "mutation { createVouchers(siteId: \"$SITE\", input: {name: \"x\", count: 1, timeLimitMinutes: 60}) { id } }" \
  | grep -q 'forbidden' && ok "graphql enforces scopes too" || bad "graphql scopes" "not refused"

echo
echo "── cleanup ──"
for id in "$VID" "$GID"; do
  [ -n "$id" ] && check "revoked $id" 200 \
    "$(status -X DELETE -H "X-API-KEY: $TOKEN" "$API/sites/$SITE/hotspot/vouchers/$id")"
done
REMAIN=$(body -H "X-API-KEY: $TOKEN" "$API/sites/$SITE/hotspot/vouchers" | grep -c "proxy-e2e" || true)
[ "$REMAIN" = "0" ] && ok "no test vouchers left" \
                    || bad "cleanup" "$REMAIN still present"

echo
echo "── audit log ──"
# JSON log lines, so the assertion is on a field rather than on text that
# happens to have ANSI escapes between the field name and its value.
grep -q '"action":"vouchers:create"' "$SP/proxy.log" && ok "creations are audited" || bad "audit" "no create line"
grep -q '"outcome":"blocked_' "$SP/proxy.log" && ok "blocked attempts are audited" || bad "audit" "no blocked line"
if grep -qF "$UVP_CONTROLLER__API_KEY" "$SP/proxy.log"; then
  bad "the controller key stayed out of the log" "FOUND IN LOG"
else ok "the controller key never appears in the log"; fi
if grep -qF "$TOKEN" "$SP/proxy.log"; then
  bad "client tokens stayed out of the log" "FOUND IN LOG"
else ok "client tokens never appear in the log"; fi

echo
printf '\033[1m%d passed, %d failed\033[0m\n' "$pass" "$fail"
exit $((fail > 0))
