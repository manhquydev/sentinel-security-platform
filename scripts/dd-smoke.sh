#!/usr/bin/env bash
# Acceptance check for the DefectDojo standup (plan-02 P1).
#
# Asserts the guarantees the phase actually claims, not just "the API answered":
#   - the CI token authenticates and is scoped to one product
#   - DD_DEBUG is off and no crypto key is a published default
#   - the database connection is genuinely TLS, and plaintext is refused
#   - BOTH dedup dictionaries parse AND every key resolves to a registered
#     scan_type (a typo silently falls back to that parser's default, which is
#     the failure this check exists to catch)
#   - an async import reaches a terminal state before anything is asserted on it
#
# Exits non-zero on the first failed assertion.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/infra/.env}"
DD_URL="${DD_URL:-http://localhost:8080}"
APP_CONTAINER="${APP_CONTAINER:-dd-uwsgi}"
DB_CONTAINER="${DB_CONTAINER:-dd-postgres}"

# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

PASS=0; FAIL=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
sect() { printf '\n== %s ==\n' "$1"; }

jget() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)" 2>/dev/null; }

# ---------------------------------------------------------------------------
sect "authentication"

ADMIN_TOKEN=$(curl -sS -X POST "$DD_URL/api/v2/api-token-auth/" -H "Content-Type: application/json" \
  -d "$(python3 -c "import json,os;print(json.dumps({'username':os.environ['DD_ADMIN_USER'],'password':os.environ['DD_ADMIN_PASSWORD']}))")" \
  | jget "d['token']")
[ -n "$ADMIN_TOKEN" ] && ok "admin token issued" || { bad "admin auth failed"; exit 1; }

CI_TOKEN=$(curl -sS -X POST "$DD_URL/api/v2/api-token-auth/" -H "Content-Type: application/json" \
  -d "$(python3 -c "import json,os;print(json.dumps({'username':os.environ['DD_SERVICE_ACCOUNT_USER'],'password':os.environ['DD_SERVICE_ACCOUNT_PASSWORD']}))")" \
  | jget "d['token']")
[ -n "$CI_TOKEN" ] && ok "CI service-account token issued" || bad "CI service-account auth failed"

capi() { curl -sS -H "Authorization: Token $CI_TOKEN" "$@"; }
code() { curl -sS -o /dev/null -w '%{http_code}' "$@"; }

# ---------------------------------------------------------------------------
sect "data model"

PROD_NAME=$(capi "$DD_URL/api/v2/products/1/" | jget "d['name']")
[ "$PROD_NAME" = "$DD_PRODUCT" ] && ok "product 1 readable ($PROD_NAME)" || bad "product 1 not readable as CI (got '$PROD_NAME')"

ENG_NAME=$(capi "$DD_URL/api/v2/engagements/1/" | jget "d['name']")
[ "$ENG_NAME" = "$DD_ENGAGEMENT" ] && ok "engagement 1 readable ($ENG_NAME)" || bad "engagement 1 not readable"

# ---------------------------------------------------------------------------
sect "least privilege"

C=$(code -X DELETE "$DD_URL/api/v2/products/1/" -H "Authorization: Token $CI_TOKEN")
[ "$C" = "403" ] && ok "CI token cannot delete its own product (403)" || bad "CI token DELETE product returned $C, expected 403"

IS_PRIV=$(docker exec "$APP_CONTAINER" python manage.py shell --no-imports -c "
from dojo.models import Dojo_User
u=Dojo_User.objects.get(username='$DD_SERVICE_ACCOUNT_USER')
print('yes' if (u.is_superuser or u.is_staff) else 'no')" 2>/dev/null | tail -1)
[ "$IS_PRIV" = "no" ] && ok "CI account is neither superuser nor staff" || bad "CI account is privileged ($IS_PRIV)"

SCOPE=$(docker exec "$APP_CONTAINER" python manage.py shell --no-imports -c "
from dojo.models import Product, Product_Type, Dojo_User
u=Dojo_User.objects.get(username='$DD_SERVICE_ACCOUNT_USER')
print(Product.objects.filter(authorized_users=u).count() + Product_Type.objects.filter(authorized_users=u).count())" 2>/dev/null | tail -1)
[ "$SCOPE" = "1" ] && ok "CI account scoped to exactly one product" || bad "CI account has $SCOPE grants, expected 1"

# ---------------------------------------------------------------------------
sect "hardening"

DBG=$(docker exec "$APP_CONTAINER" python manage.py shell --no-imports -c "
from django.conf import settings
print(settings.DEBUG)" 2>/dev/null | tail -1)
[ "$DBG" = "False" ] && ok "DD_DEBUG is False" || bad "DD_DEBUG is '$DBG'"

for VAR in DD_SECRET_KEY DD_CREDENTIAL_AES_256_KEY; do
    VAL="${!VAR}"
    case "$VAL" in
        ""|"."|'hhZCp@D28z!n@NED*yB!ROMt+WzsY*iq'|'&91a*agLqesc*0DJ+2*bAbsUZfR*4nLw')
            bad "$VAR is a published default" ;;
        *) [ "${#VAL}" -ge 16 ] && ok "$VAR is non-default (${#VAL} chars)" || bad "$VAR too short" ;;
    esac
done

# The guard is the control; prove it still refuses a known-bad key rather than
# trusting that it was wired in.
GUARD=$(docker exec -e DD_SECRET_KEY=. -e DD_CREDENTIAL_AES_256_KEY=. "$APP_CONTAINER" /dd-boot-guard.sh 2>&1; echo "rc=$?")
case "$GUARD" in *"rc=78"*) ok "boot guard rejects a published default key (exit 78)" ;;
                  *) bad "boot guard did not reject default keys: $GUARD" ;; esac

# ---------------------------------------------------------------------------
sect "database TLS"

SSL=$(docker exec "$APP_CONTAINER" python manage.py shell --no-imports -c "
from django.db import connection
with connection.cursor() as c:
    c.execute('SELECT ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()')
    print('%s %s' % c.fetchone())" 2>/dev/null | tail -1)
case "$SSL" in True*) ok "app->db connection is TLS ($SSL)" ;;
                *) bad "app->db connection is not TLS (got '$SSL')" ;; esac

PLAIN=$(docker exec -e PGPASSWORD="$DD_DATABASE_PASSWORD" -e PGSSLMODE=disable "$DB_CONTAINER" \
    psql -h 127.0.0.1 -U "$DD_DATABASE_USER" -d "$DD_DATABASE_NAME" -Atc 'SELECT 1' 2>&1 | tail -1)
case "$PLAIN" in *"no encryption"*|*"rejects"*) ok "plaintext connections are refused by pg_hba" ;;
                  *) bad "plaintext connection was not refused (got '$PLAIN')" ;; esac

# ---------------------------------------------------------------------------
sect "deduplication config"

REGISTERED=$(curl -sS -H "Authorization: Token $ADMIN_TOKEN" "$DD_URL/api/v2/test_types/?limit=1000" \
    | python3 -c "import sys,json;print('\n'.join(t['name'] for t in json.load(sys.stdin)['results']))")

check_dedup() {
    local var="$1" kind="$2"
    local raw
    raw=$(docker exec "$APP_CONTAINER" printenv "$var" 2>/dev/null)
    if [ -z "$raw" ]; then bad "$var is not set in the container"; return; fi
    if ! echo "$raw" | python3 -c "import sys,json;json.load(sys.stdin)" 2>/dev/null; then
        bad "$var is not valid JSON"; return
    fi
    ok "$var parses as JSON"
    local keys unknown=0
    keys=$(echo "$raw" | python3 -c "import sys,json;print('\n'.join(json.load(sys.stdin).keys()))")
    while IFS= read -r k; do
        [ -n "$k" ] || continue
        if ! grep -Fxq "$k" <<<"$REGISTERED"; then
            bad "$kind key '$k' is not a registered scan_type (would silently fall back to defaults)"
            unknown=1
        fi
    done <<<"$keys"
    [ "$unknown" -eq 0 ] && ok "$kind keys all resolve against /api/v2/test_types/"
}

check_dedup DD_DEDUPLICATION_ALGORITHM_PER_PARSER "algorithm"
check_dedup DD_HASHCODE_FIELDS_PER_SCANNER "hashcode-fields"

# The whole point of setting the fields variable is overriding non-endpoint
# defaults for the endpoint-based scanners.
for S in "ZAP Scan" "Nuclei Scan"; do
    HAS=$(docker exec "$APP_CONTAINER" python manage.py shell --no-imports -c "
from django.conf import settings
print('endpoints' in settings.HASHCODE_FIELDS_PER_SCANNER.get('$S', []))" 2>/dev/null | tail -1)
    [ "$HAS" = "True" ] && ok "'$S' hashes on endpoints (default overridden)" || bad "'$S' does not hash on endpoints"
done

# ---------------------------------------------------------------------------
sect "async import reaches a terminal state"

TMPF=$(mktemp /tmp/dd-smoke-XXXX.json)
printf '{"findings":[{"title":"dd-smoke probe","severity":"Info","description":"transient P1 smoke finding","date":"%s"}]}' "$(date +%F)" > "$TMPF"

RESP=$(curl -sS -w "\n%{http_code}" -X POST "$DD_URL/api/v2/import-scan/" \
    -H "Authorization: Token $CI_TOKEN" \
    -F "scan_type=Generic Findings Import" -F "engagement=1" -F "file=@$TMPF")
HTTP=$(tail -1 <<<"$RESP"); TEST_ID=$(head -n -1 <<<"$RESP" | jget "d.get('test','')")
rm -f "$TMPF"

[ "$HTTP" = "201" ] && ok "CI token can import (201, test $TEST_ID)" || bad "import returned $HTTP"

if [ -n "$TEST_ID" ]; then
    TERMINAL=""
    for _ in $(seq 1 30); do
        N=$(capi "$DD_URL/api/v2/test_imports/?test=$TEST_ID" | jget "d['count']")
        if [ "${N:-0}" -ge 1 ]; then TERMINAL="yes"; break; fi
        sleep 1
    done
    [ -n "$TERMINAL" ] && ok "import reached a terminal state within 30s" \
                       || bad "import never reached a terminal state (celery worker stuck?)"

    # Leave no residue in the baseline engagement.
    docker exec "$APP_CONTAINER" python manage.py shell --no-imports -c "
from dojo.models import Test
Test.objects.filter(pk=$TEST_ID).delete()" >/dev/null 2>&1 && ok "smoke finding cleaned up" || bad "cleanup failed"
fi

# ---------------------------------------------------------------------------
sect "deduplication actually runs"

# Everything above proves the dedup CONFIG is loaded. That is not the same as
# dedup happening, and the difference is not academic: this suite passed 22/22
# while no deduplication whatsoever was taking place, because
# System_Settings.enable_deduplication was False and celery was silently
# consuming nothing. The only check that catches that class of failure is
# importing a duplicate and asserting it gets flagged.

DEDUP_ON=$(docker exec "$APP_CONTAINER" python manage.py shell --no-imports -c "
from dojo.models import System_Settings
print(System_Settings.objects.get(no_cache=True).enable_deduplication)" 2>/dev/null | tail -1)
[ "$DEDUP_ON" = "True" ] && ok "enable_deduplication is on" \
    || bad "enable_deduplication is '$DEDUP_ON' - dedup config is inert (run dd-bootstrap.sh)"

# Celery must genuinely drain the queue. A worker can report "ready" and answer
# `inspect ping` while never polling the task queue at all - that is exactly what
# valkey 9.1.0 did here.
QUEUE_BEFORE=$(docker exec "${BROKER_CONTAINER:-dd-redis}" redis-cli -n 0 LLEN celery 2>/dev/null || echo "?")

DUPF=$(mktemp /tmp/dd-smoke-dup-XXXX.json)
cat > "$DUPF" <<EOF
{"results":[{"check_id":"dd-smoke.dedup-probe","path":"smoke/probe.py",
 "start":{"line":1,"col":1},"end":{"line":1,"col":9},
 "extra":{"message":"dedup probe","severity":"INFO","metadata":{"cwe":["CWE-89"]}}}]}
EOF

DUP_TESTS=""
for _ in 1 2; do
    RESP=$(curl -sS -X POST "$DD_URL/api/v2/import-scan/" -H "Authorization: Token $CI_TOKEN" \
        -F "scan_type=Semgrep JSON Report" -F "engagement=1" -F "file=@$DUPF")
    DUP_TESTS="$DUP_TESTS $(jget "d.get('test','')" <<<"$RESP")"
    sleep 8
done
rm -f "$DUPF"

QUEUE_AFTER=$(docker exec "${BROKER_CONTAINER:-dd-redis}" redis-cli -n 0 LLEN celery 2>/dev/null || echo "?")
if [ "$QUEUE_AFTER" = "0" ] || [ "$QUEUE_AFTER" -le "${QUEUE_BEFORE:-0}" ] 2>/dev/null; then
    ok "celery drains its queue (depth $QUEUE_BEFORE -> $QUEUE_AFTER)"
else
    bad "celery queue is growing ($QUEUE_BEFORE -> $QUEUE_AFTER) - worker is not consuming tasks"
fi

FLAGGED=$(docker exec "$APP_CONTAINER" python manage.py shell --no-imports -c "
from dojo.models import Finding
print(Finding.objects.filter(title='dd-smoke.dedup-probe', duplicate=True).count())" 2>/dev/null | tail -1)
[ "${FLAGGED:-0}" -ge 1 ] && ok "reimported finding is flagged duplicate (behaviour, not config)" \
    || bad "identical finding imported twice was NOT flagged duplicate - dedup is not running"

docker exec "$APP_CONTAINER" python manage.py shell --no-imports -c "
from dojo.models import Test
Test.objects.filter(pk__in=[t for t in '$DUP_TESTS'.split() if t]).delete()" >/dev/null 2>&1 \
    && ok "dedup probe cleaned up" || bad "dedup probe cleanup failed"

# ---------------------------------------------------------------------------
printf '\n----------------------------------------\n'
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
