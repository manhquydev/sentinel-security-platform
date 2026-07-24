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
ENV_FILE="${ENV_FILE:-$REPO_ROOT/infra/.env}"
BASE="${KONG_PROXY:-https://127.0.0.1:18443}"
REQUIRE_KONG="${REQUIRE_KONG:-0}"

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

# The template is checked in and must carry NO real secret — only ${PLACEHOLDER}s.
if grep -E 'client_secret:|provision_key:' "$TMPL" | grep -vqE '\$\{[A-Z_]+\}'; then
  bad "the committed template contains a non-placeholder secret"
  grep -nE 'client_secret:|provision_key:' "$TMPL" | grep -vE '\$\{[A-Z_]+\}' >&2
else
  ok "committed template holds only placeholder secrets"
fi

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
resource = ["public-read", "authenticated-read", "admin-read", "basket-write"]
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

# ---------------------------------------------------------------------------
sect "live: authorization boundary against the running gateway"

reach() { curl -sk --max-time 5 -o /dev/null -w '%{http_code}' "$BASE/rest/products/search?q=probe" 2>/dev/null; }
if [ "$(reach)" = "000" ]; then
  msg="gateway not reachable at $BASE"
  if [ "$REQUIRE_KONG" = "1" ]; then bad "$msg (REQUIRE_KONG=1)"; else skip "$msg"; fi
else
  if [ ! -f "$ENV_FILE" ]; then
    if [ "$REQUIRE_KONG" = "1" ]; then bad "no $ENV_FILE for client secrets"; else skip "no $ENV_FILE for client secrets"; fi
  else
    # shellcheck disable=SC1090
    set -a; . "$ENV_FILE"; set +a
    mint() { curl -sk --max-time 5 -X POST "$BASE/oauth/oauth2/token" -H 'Content-Type: application/json' \
      --data "{\"client_id\":\"$1\",\"client_secret\":\"$2\",\"grant_type\":\"client_credentials\"}" \
      | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null; }
    code() { curl -sk --max-time 5 -o /dev/null -w '%{http_code}' "$@"; }

    RT="$(mint agent-recon "${AGENT_RECON_SECRET:-}")"
    PT="$(mint probe-admin "${PROBE_ADMIN_SECRET:-}")"

    [ -n "$RT" ] && ok "agent-recon mints a client-credentials token" || bad "agent-recon could not mint a token"
    [ -n "$PT" ] && ok "probe-admin mints a client-credentials token" || bad "probe-admin could not mint a token"

    # The core boundary: read-scoped agent reaches read, is refused admin and writes.
    c="$(code "$BASE/rest/products/search?q=apple" -H "Authorization: Bearer $RT")"
    [ "$c" = "200" ] && ok "agent-recon -> GET /rest/products/search = 200" || bad "agent-recon read route = $c (want 200)"

    c="$(code "$BASE/rest/admin/application-version" -H "Authorization: Bearer $RT")"
    [ "$c" = "403" ] && ok "agent-recon -> GET /rest/admin/application-version = 403" || bad "agent-recon admin route = $c (want 403)"

    c="$(code -X POST "$BASE/rest/basket" -H "Authorization: Bearer $RT")"
    [ "$c" = "403" ] && ok "agent-recon -> POST /rest/basket = 403" || bad "agent-recon state-change = $c (want 403)"

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
    else
      skip "sentinel-kong container not found for audit-log inspection"
    fi
  fi
fi

# ---------------------------------------------------------------------------
printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ]
