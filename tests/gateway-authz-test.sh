#!/usr/bin/env bash
# Kong app-ingress gateway contract (Week 2), enforced so a later edit cannot quietly
# widen an agent's reach or leak a token.
#
# Two layers. The STATIC checks read the committed policy and compose and lock the
# durable invariants that make the gateway safe: loopback-only publish, TLS-only edge,
# an ACL guard on every resource route (and none on the token mint), no enforcement-free
# oauth2 scopes, pinned images, and secrets kept out of git. They run without a live
# stack. The LIVE checks prove the authorization boundary against the running gateway and
# Juice Shop: a read-scoped agent reaches a public read route and is refused an admin one,
# with probe-admin as the positive control that proves the admin route is not simply dead,
# and no bearer token in the audit stream. Live checks skip if the stack is down, unless
# REQUIRE_KONG=1 turns a skip into a failure.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="$REPO_ROOT/infra/kong/docker-compose.yml"
TMPL="$REPO_ROOT/infra/kong/kong.declarative.yml.tmpl"
RENDER="$REPO_ROOT/infra/kong/render-config.sh"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/infra/.env}"
BASE="${KONG_PROXY:-https://127.0.0.1:18443}"
REQUIRE_KONG="${REQUIRE_KONG:-0}"
SKIP_KONG_LIVE="${SKIP_KONG_LIVE:-0}"

PASS=0; FAIL=0; SKIP=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
skip() { printf '  \033[33mSKIP\033[0m %s\n' "$1"; SKIP=$((SKIP+1)); }
sect() { printf '\n== %s ==\n' "$1"; }

[ -f "$COMPOSE" ] || { echo "missing $COMPOSE" >&2; exit 2; }
[ -f "$TMPL" ]    || { echo "missing $TMPL" >&2; exit 2; }

# ---------------------------------------------------------------------------
sect "static: the edge is loopback-only and TLS-only"

# Every published port binds 127.0.0.1 — never 0.0.0.0. Parsed (not grepped): a binding
# written "8443:8443" has no host IP, so Docker binds 0.0.0.0, and a line-regex that expects
# three colon groups would skip it and pass vacuously.
if python3 - "$COMPOSE" <<'PY'
import sys, yaml
c = yaml.safe_load(open(sys.argv[1]))
bad = []
for name, svc in (c.get("services") or {}).items():
    for p in (svc.get("ports") or []):
        if not str(p).startswith("127.0.0.1:"):
            bad.append(f"{name}: {p}")
if bad:
    sys.stderr.write("\n".join(bad) + "\n"); sys.exit(1)
sys.exit(0)
PY
then ok "all published ports bind 127.0.0.1"
else bad "a published port is not bound to 127.0.0.1"
fi

# The proxy listener is ssl and there is no plaintext :8000 proxy.
if grep -q 'KONG_PROXY_LISTEN:.*8443 ssl' "$COMPOSE" && ! grep -qE 'KONG_PROXY_LISTEN:.*8000([^0-9]|$)' "$COMPOSE"; then
  ok "proxy listener is TLS-only (8443 ssl, no plaintext 8000)"
else
  bad "proxy listener is not TLS-only"
fi

# The Kong database publishes no port. Parsed precisely (the service name also appears
# in depends_on blocks, which defeats a line-scan).
if python3 - "$COMPOSE" <<'PY'
import sys, yaml
c = yaml.safe_load(open(sys.argv[1]))
svc = (c.get("services") or {}).get("kong-database") or {}
sys.exit(1 if svc.get("ports") else 0)
PY
then ok "the kong database publishes no port"
else bad "the kong database publishes a port"
fi

sect "static: images are pinned by digest"
if grep -E '^\s*image:' "$COMPOSE" | grep -vq '@sha256:'; then
  bad "an image is not pinned by @sha256"; grep -E '^\s*image:' "$COMPOSE" | grep -v '@sha256:' >&2
else
  ok "every image is pinned by @sha256"
fi

# ---------------------------------------------------------------------------
sect "static: authorization policy is fail-closed and honest"

# Render with non-secret dummy values; verify the new executor placeholder is substituted and a
# missing value fails without echoing any supplied value.
render_tmp="$(mktemp -d)"; render_sentinel="$(mktemp)"; trap 'rm -rf "$render_tmp"; rm -f "$render_sentinel"' EXIT
printf 'caller-owned-rendered-config\n' >"$render_sentinel"
cat >"$render_tmp/env" <<'EOF'
KONG_PROVISION_KEY=dummy-provision
AGENT_RECON_SECRET=dummy-recon
PROBE_ADMIN_SECRET=dummy-probe
SENTINEL_CHARTER_EXECUTOR_SECRET=dummy-executor
SENTINEL_CHARTER_EXECUTOR_API_KEY=dummy-executor-api-key
EOF
if ENV_FILE="$render_tmp/env" OUT="$render_tmp/kong.rendered.yml" bash "$RENDER" >/dev/null 2>"$render_tmp/render.err" \
  && ! grep -qE '\$\{[A-Z_]' "$render_tmp/kong.rendered.yml" \
  && [ "$(cat "$render_sentinel")" = 'caller-owned-rendered-config' ] \
  && ! grep -q 'dummy-executor' "$render_tmp/render.err"; then
  ok "Kong renderer substitutes executor secret without unresolved placeholders or echo"
else bad "Kong renderer did not safely substitute executor secret"; fi
sed -i '/SENTINEL_CHARTER_EXECUTOR_API_KEY/d' "$render_tmp/env"
if ! ENV_FILE="$render_tmp/env" OUT="$render_tmp/missing.yml" bash "$RENDER" >"$render_tmp/missing.out" 2>"$render_tmp/missing.err" \
  && grep -q 'required Kong configuration is invalid' "$render_tmp/missing.err" \
  && ! grep -q 'dummy-' "$render_tmp/missing.err"; then
  ok "Kong renderer fails missing executor secret without echoing secret values"
else bad "Kong renderer missing-secret failure is unsafe"; fi

render_marker="$render_tmp/evaluated"
cat >"$render_tmp/env" <<EOF
KONG_PROVISION_KEY=\$(touch $render_marker)
AGENT_RECON_SECRET=dummy-recon
PROBE_ADMIN_SECRET=dummy-probe
SENTINEL_CHARTER_EXECUTOR_SECRET=dummy-executor
SENTINEL_CHARTER_EXECUTOR_API_KEY=dummy-executor-api-key
EOF
if ENV_FILE="$render_tmp/env" OUT="$render_tmp/literal.yml" bash "$RENDER" >/dev/null 2>"$render_tmp/literal.err" \
  && [ ! -e "$render_marker" ]; then
  ok "Kong renderer treats shell-looking secret values as data"
else bad "Kong renderer evaluated private environment content"; fi

# The template is checked in and must carry NO real secret — only ${PLACEHOLDER}s.
if grep -E 'client_secret:|provision_key:' "$TMPL" | grep -vqE '\$\{[A-Z_]+\}'; then
  bad "the committed template contains a non-placeholder secret"
  grep -nE 'client_secret:|provision_key:' "$TMPL" | grep -vE '\$\{[A-Z_]+\}' >&2
else
  ok "committed template holds only placeholder secrets"
fi

keyauth_report="$(python3 - "$TMPL" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
plugins = d.get("plugins") or []
api_key_functions = {
    p.get("route"): p.get("config", {}).get("access")
    for p in plugins
    if p.get("name") == "pre-function"
}
routes = {
    route["name"]: route
    for service in d.get("services") or []
    for route in service.get("routes") or []
}
route_shapes = all(
    routes.get(name, {}).get("paths") == [gateway_path] and routes[name].get("strip_path") is False
    for name, gateway_path in {
        "charter-search": "/sentinel-charter/rest/products/search",
        "charter-basket-write": "/sentinel-charter/rest/basket",
    }.items()
)
transformers = {
    plugin.get("route"): plugin.get("config", {})
    for plugin in plugins
    if plugin.get("name") == "request-transformer"
}
expected_transformers = {
    "charter-search": {
        "remove": {"headers": ["X-Sentinel-API-Key"]},
        "replace": {"uri": "/rest/products/search"},
    },
    "charter-basket-write": {
        "remove": {"headers": ["X-Sentinel-API-Key"]},
        "replace": {"uri": "/rest/basket"},
    },
}
expected_api_key_function = (
    'local key = kong.request.get_header("X-Sentinel-API-Key")\n'
    'if type(key) ~= "string" or key ~= "${SENTINEL_CHARTER_EXECUTOR_API_KEY}" then\n'
    '  return kong.response.exit(401)\n'
    'end\n'
    'ngx.req.clear_header("X-Sentinel-API-Key")\n'
)
print(
    "ROUTES " + ",".join(sorted(route for route, access in api_key_functions.items()
                                if access == [expected_api_key_function]))
)
print("PREFIX " + ("yes" if route_shapes else "no"))
print("TRANSFORM " + ("yes" if transformers == expected_transformers else "no"))
PY
)"
grep -Fxq 'ROUTES charter-basket-write,charter-search' <<<"$keyauth_report" \
  && ok "charter routes require and pre-log redact the dedicated API-key credential" \
  || bad "charter API-key route policy is missing or unsafe"
grep -Fxq 'PREFIX yes' <<<"$keyauth_report" \
  && ok "charter executor routes use a distinct exact gateway prefix" \
  || bad "charter executor route prefix is missing or not exact"
grep -Fxq 'TRANSFORM yes' <<<"$keyauth_report" \
  && ok "charter routes redact the API key and restore exact upstream paths" \
  || bad "charter route redaction or upstream path transform is missing"

# hide_credentials strips the token before proxy and before the audit serializer.
grep -q 'hide_credentials: true' "$TMPL" && ok "oauth2 hide_credentials is true" \
  || bad "oauth2 hide_credentials is not true"

# Short token TTL bounds blast radius.
grep -qE 'token_expiration: 300\b' "$TMPL" && ok "token_expiration is 300s" \
  || bad "token_expiration is not 300s"

# No enforcement-free scopes: Kong OSS cannot bind a scope to a consumer, so a scope
# list would advertise a permission the gateway does not enforce. Authorization is ACL.
if grep -qE '^\s*(scopes:|mandatory_scope:)' "$TMPL"; then
  bad "oauth2 declares scopes/mandatory_scope — Kong OSS does not enforce these per consumer"
else
  ok "no enforcement-free oauth2 scopes (authorization is ACL groups)"
fi

# Every resource route is guarded by an ACL; the token mint route is NOT (it must be
# reachable unauthenticated to issue a token). Parsed from the plugins list so the check
# actually sees which routes ACL targets, rather than grepping for a string that may not
# exist in the form assumed.
acl_report="$(python3 - "$TMPL" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
acl_routes = {p.get("route") for p in (d.get("plugins") or []) if p.get("name") == "acl"}
resource = ["public-read", "charter-search", "authenticated-read", "admin-read", "basket-write", "charter-basket-write"]
for r in resource:
    print(("GUARDED " if r in acl_routes else "UNGUARDED ") + r)
print("TOKENACL " + ("yes" if "oauth-token" in acl_routes else "no"))
PY
)"
while read -r verdict route; do
  case "$verdict" in
    GUARDED)   ok "resource route '$route' has an ACL guard" ;;
    UNGUARDED) bad "resource route '$route' has no ACL guard" ;;
    TOKENACL)  [ "$route" = "no" ] && ok "the token mint route has no ACL guard" \
                                   || bad "the token mint route has an ACL guard (must be reachable unauthenticated)" ;;
  esac
done <<<"$acl_report"

# The token mint route matches ONLY the exact mint endpoint (anchored regex), not a broad
# /oauth prefix that would proxy arbitrary app paths past the ACLs.
if grep -qE '^\s*-\s*~/oauth/oauth2/token\$' "$TMPL"; then
  ok "token route path is anchored to the mint endpoint (no /oauth prefix)"
else
  bad "token route is not anchored — a broad /oauth prefix is an ACL-escape surface"
fi

# agent-recon holds ONLY read-public; it must not be a member of read-admin or write-*.
if awk '/username: agent-recon/{f=1} f&&/group:/{print} /oauth2_credentials:/{if(f)exit}' "$TMPL" | grep -qE 'read-admin|write-'; then
  bad "agent-recon is a member of a privileged group in the policy"
else
  ok "agent-recon holds only read-public in the policy"
fi

# The charter executor is a separate local identity, never an agent grant. It has only the two
# fixed-route ACL groups; approval remains executor-side rather than a Kong claim.
executor_groups="$(awk '/username: sentinel-charter-executor/{f=1} f&&/group:/{print} /oauth2_credentials:/{if(f)exit}' "$TMPL")"
if grep -q 'charter-read' <<<"$executor_groups" && grep -q 'write-basket' <<<"$executor_groups" \
  && ! grep -qE 'read-admin|read-authenticated' <<<"$executor_groups" \
  && grep -q 'SENTINEL_CHARTER_EXECUTOR_SECRET' "$TMPL"; then
  ok "charter executor has dedicated charter-read/write-basket OAuth identity"
else
  bad "charter executor identity is missing or over-privileged"
fi

# ---------------------------------------------------------------------------
sect "live: authorization boundary against the running gateway"

reach() { curl -sk --max-time 5 -o /dev/null -w '%{http_code}' "$BASE/rest/products/search?q=probe" 2>/dev/null; }
if [ "$SKIP_KONG_LIVE" = "1" ]; then
  skip "live Kong checks explicitly skipped"
elif [ "$(reach)" = "000" ]; then
  msg="gateway not reachable at $BASE"
  if [ "$REQUIRE_KONG" = "1" ]; then bad "$msg (REQUIRE_KONG=1)"; else skip "$msg"; fi
else
  if [ -z "${AGENT_RECON_SECRET:-}" ] || [ -z "${PROBE_ADMIN_SECRET:-}" ] || [ -z "${KONG_PROVISION_KEY:-}" ] \
      || [ -z "${SENTINEL_CHARTER_EXECUTOR_SECRET:-}" ] || [ -z "${SENTINEL_CHARTER_EXECUTOR_API_KEY:-}" ]; then
    if [ "$REQUIRE_KONG" = "1" ]; then bad "injected live-test secrets are unavailable"; else skip "injected live-test secrets are unavailable"; fi
  else
    # Values must be injected by a secret manager or caller; never source the
    # private env file just to run a test.
    mint() { curl -sk --max-time 5 -X POST "$BASE/oauth/oauth2/token" -H 'Content-Type: application/json' \
      --data "{\"client_id\":\"$1\",\"client_secret\":\"$2\",\"grant_type\":\"client_credentials\"}" \
      | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null; }
    code() { curl -sk --max-time 5 -o /dev/null -w '%{http_code}' "$@"; }

    RT="$(mint agent-recon "${AGENT_RECON_SECRET:-}")"
    PT="$(mint probe-admin "${PROBE_ADMIN_SECRET:-}")"
    ET="$(mint sentinel-charter-executor "${SENTINEL_CHARTER_EXECUTOR_SECRET:-}")"

    [ -n "$RT" ] && ok "agent-recon mints a client-credentials token" || bad "agent-recon could not mint a token"
    [ -n "$PT" ] && ok "probe-admin mints a client-credentials token" || bad "probe-admin could not mint a token"
    [ -n "$ET" ] && ok "charter executor mints its dedicated client-credentials token" || bad "charter executor could not mint a token"

    # The core boundary: read-scoped agent reaches read, is refused admin and writes.
    c="$(code "$BASE/rest/products/search?q=apple" -H "Authorization: Bearer $RT")"
    [ "$c" = "200" ] && ok "agent-recon -> GET /rest/products/search = 200" || bad "agent-recon read route = $c (want 200)"

    c="$(code "$BASE/rest/admin/application-version" -H "Authorization: Bearer $RT")"
    [ "$c" = "403" ] && ok "agent-recon -> GET /rest/admin/application-version = 403" || bad "agent-recon admin route = $c (want 403)"

    c="$(code -X POST "$BASE/rest/basket" -H "Authorization: Bearer $RT")"
    [ "$c" = "403" ] && ok "agent-recon -> POST /rest/basket = 403" || bad "agent-recon state-change = $c (want 403)"

    c="$(code "$BASE/sentinel-charter/rest/products/search?q=apple" -H "Authorization: Bearer $ET")"
    [ "$c" = "401" ] && ok "charter executor without API key -> 401" || bad "charter executor OAuth-only request = $c (want 401)"
    c="$(code "$BASE/sentinel-charter/rest/products/search?q=apple" -H "X-Sentinel-API-Key: ${SENTINEL_CHARTER_EXECUTOR_API_KEY:-}")"
    [ "$c" = "401" ] && ok "charter executor API-key-only request -> 401" || bad "charter executor API-key-only request = $c (want 401)"
    c="$(code "$BASE/sentinel-charter/rest/products/search?q=apple" -H "Authorization: Bearer $ET" -H "X-Sentinel-API-Key: ${SENTINEL_CHARTER_EXECUTOR_API_KEY:-}")"
    [ "$c" = "200" ] && ok "charter executor OAuth plus API key -> GET search = 200" || bad "charter executor combined credentials = $c (want 200)"

    # Positive control: the admin route is NOT simply dead — probe-admin reaches it. This
    # is what makes agent-recon's 403 a genuine authorization decision, not a broken route.
    c="$(code "$BASE/rest/admin/application-version" -H "Authorization: Bearer $PT")"
    [ "$c" = "200" ] && ok "probe-admin -> GET /rest/admin/application-version = 200 (route is live)" || bad "probe-admin admin route = $c (want 200)"

    # AuthN and authZ are distinct denials: no token is 401, wrong group is 403.
    c="$(code "$BASE/rest/products/search?q=apple")"
    [ "$c" = "401" ] && ok "no token -> 401 (authentication)" || bad "no token = $c (want 401)"
    c="$(code "$BASE/rest/products/search?q=apple" -H "Authorization: Bearer deadbeef")"
    [ "$c" = "401" ] && ok "bogus token -> 401" || bad "bogus token = $c (want 401)"

    # ACL-escape regression: the token route must not double as an open proxy. A forbidden
    # path prefixed with /oauth (or the /oauth2/... variant) must match no route (404), never
    # reach the app. Before the anchored-regex fix these returned app codes (401/500/200),
    # proving agent-recon could bypass every per-route ACL for POST.
    c="$(code -X POST "$BASE/oauth/rest/basket" -H "Authorization: Bearer $RT")"
    [ "$c" = "404" ] && ok "no ACL-escape: POST /oauth/rest/basket -> 404" || bad "ACL-escape via token route: POST /oauth/rest/basket = $c (want 404)"
    c="$(code -X POST "$BASE/oauth2/token/rest/basket" -H "Authorization: Bearer $RT")"
    [ "$c" = "404" ] && ok "no ACL-escape: POST /oauth2/token/rest/basket -> 404" || bad "ACL-escape via /oauth2 prefix: POST /oauth2/token/rest/basket = $c (want 404)"

    # The audit stream records the request but never the bearer token or provision key.
    if docker ps --filter name=sentinel-kong --format '{{.Names}}' | grep -qx sentinel-kong 2>/dev/null; then
      LOG="$(docker logs sentinel-kong 2>/dev/null)"
      # Herestrings, not echo|grep: under `set -o pipefail`, grep -q closes the pipe on a
      # match and the upstream echo takes SIGPIPE, failing the pipeline despite the match.
      if grep -qE '^\{' <<<"$LOG" && grep -q '"request"' <<<"$LOG" && grep -q '"response"' <<<"$LOG"; then
        ok "audit stream emits structured JSON request records"
      else
        bad "audit stream has no structured request records"
      fi
      if [ -n "$RT" ] && grep -qF "$RT" <<<"$LOG"; then bad "a bearer token appears in the audit stream"; else ok "no bearer token in the audit stream"; fi
      if [ -n "${KONG_PROVISION_KEY:-}" ] && grep -qF "$KONG_PROVISION_KEY" <<<"$LOG"; then bad "the provision key appears in the audit stream"; else ok "no provision key in the audit stream"; fi
      # The client_secret travels only in the token-request BODY, which file-log does not
      # serialize (it logs headers + metadata, not bodies), so it is not asserted here; the
      # absence of body logging is the control that keeps it out.
      if [ -n "${AGENT_RECON_SECRET:-}" ] && grep -qF "$AGENT_RECON_SECRET" <<<"$LOG"; then bad "a client secret appears in the audit stream"; else ok "no client secret in the audit stream"; fi
      if [ -n "${SENTINEL_CHARTER_EXECUTOR_API_KEY:-}" ] && grep -qF "$SENTINEL_CHARTER_EXECUTOR_API_KEY" <<<"$LOG"; then bad "an API key appears in the audit stream"; else ok "no API key in the audit stream"; fi
    else
      skip "sentinel-kong container not found for audit-log inspection"
    fi
  fi
fi

# ---------------------------------------------------------------------------
printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ]
