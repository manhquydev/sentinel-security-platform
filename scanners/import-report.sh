#!/usr/bin/env bash
# Import a SANITIZED scanner report into DefectDojo.
#   import-report.sh <scan_type> <sanitized_file> [test_title]
#
# Uses reimport-scan (idempotent: repeated imports update the same Test instead
# of duplicating). The caller is responsible for having run redact-report.sh
# first — this script imports whatever file it is given; it does not sanitize.
#
# Environment:
#   DD_API_TOKEN         A pre-issued Product-scoped token. PREFERRED. When set,
#                        no credential file is read and no password exchange
#                        happens, so CI holds exactly one secret. Without it this
#                        script must source ENV_FILE, which carries the AES
#                        credential key and the database password — secrets that
#                        have no business on a CI runner.
#   ENV_FILE             Credential fallback (default infra/.env). Read ONLY when
#                        DD_API_TOKEN is unset.
#   DD_URL               DefectDojo base URL (default http://localhost:8080).
#   PRODUCT_NAME         Overrides the value in ENV_FILE. The caller always wins:
#   ENGAGEMENT_NAME      both are captured BEFORE the env file is sourced, because
#                        `set -a; . env` would otherwise silently overwrite a
#                        caller-supplied engagement and land the import in the
#                        baseline instead of where it was addressed.
#   CLOSE_OLD_FINDINGS   true|false. DEFAULT false, deliberately.
#
# On close_old_findings: DefectDojo mitigates every finding absent from the
# report. That is correct ONLY when the scan is known to have reached its target.
# A scanner pointed at an empty directory, or run while the target was restarting,
# exits 0 with an empty report and would close the entire baseline as "remediated"
# in one call. This script cannot tell those apart — only the caller knows whether
# the scan produced proof of contact — so the default is the safe one and the
# caller must opt in.
#
# stdout: the full reimport response JSON. `statistics` and `deduplication_complete`
#         are the fields a completeness gate needs; earlier versions printed only
#         the test id and threw the rest away.
set -euo pipefail

scan_type="${1:?scan_type required (exact DefectDojo name, e.g. 'Trivy Scan')}"
file="${2:?sanitized report file required}"
test_title="${3:-${scan_type}}"

[ -s "$file" ] || { echo "import-report: empty/missing file: $file" >&2; exit 2; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
DD_URL="${DD_URL:-http://localhost:8080}"
CLOSE_OLD_FINDINGS="${CLOSE_OLD_FINDINGS:-false}"
case "$CLOSE_OLD_FINDINGS" in
  true|false) ;;
  *) echo "import-report: CLOSE_OLD_FINDINGS must be true or false, got '$CLOSE_OLD_FINDINGS'" >&2; exit 2 ;;
esac

# Capture caller intent before anything can overwrite it.
caller_product="${PRODUCT_NAME:-}"
caller_engagement="${ENGAGEMENT_NAME:-}"
API_TOKEN="${DD_API_TOKEN:-}"

if [ -z "$API_TOKEN" ]; then
  ENV_FILE="${ENV_FILE:-$REPO_ROOT/infra/.env}"
  # shellcheck disable=SC1090
  set -a; . "$ENV_FILE"; set +a
fi

PRODUCT_NAME="${caller_product:-${DD_PRODUCT:-}}"
ENGAGEMENT_NAME="${caller_engagement:-${DD_ENGAGEMENT:-}}"
[ -n "$PRODUCT_NAME" ]    || { echo "import-report: PRODUCT_NAME unset (no caller value, none in env file)" >&2; exit 2; }
[ -n "$ENGAGEMENT_NAME" ] || { echo "import-report: ENGAGEMENT_NAME unset (no caller value, none in env file)" >&2; exit 2; }

# curl -F treats a value starting with @ or < as a file to read, so a name derived
# from a branch or any other outside input could exfiltrate a file into DefectDojo
# as a form field. Every non-file field below uses --form-string, which never
# interprets its value; this check additionally keeps routing names sane.
for pair in "product:$PRODUCT_NAME" "engagement:$ENGAGEMENT_NAME" "test_title:$test_title"; do
  case "${pair#*:}" in
    *[!A-Za-z0-9._\ -]*) echo "import-report: illegal character in ${pair%%:*} name: '${pair#*:}'" >&2; exit 2 ;;
  esac
done

CFG="$(mktemp)"; chmod 600 "$CFG"
trap 'rm -f "$CFG"' EXIT

if [ -z "$API_TOKEN" ]; then
  # Credentials stay OFF the process argv (visible in `ps aux` on a shared host):
  # the password goes to curl via stdin, the issued token via a mode-600 config.
  API_TOKEN="$(printf '{"username":"%s","password":"%s"}' "$DD_SERVICE_ACCOUNT_USER" "$DD_SERVICE_ACCOUNT_PASSWORD" \
    | curl -sS -X POST "$DD_URL/api/v2/api-token-auth/" \
        -H 'Content-Type: application/json' --data @- \
    | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("token",""))
except Exception: print("")')"
  [ -n "$API_TOKEN" ] || { echo "import-report: service-account auth failed (bad credentials or DD unreachable)" >&2; exit 3; }
fi
printf 'header = "Authorization: Token %s"\n' "$API_TOKEN" > "$CFG"

# deduplication_execution_mode=async_wait: parsing is inline in this request, but
# deduplication post-processing defaults to fire-and-forget, so without this the
# returned statistics describe a pre-deduplication state and any assertion made
# on them races the worker. Measured at ~2.5s for a 221-finding import against a
# 60s budget, so waiting is close to free.
resp="$(curl -sS -w '\n%{http_code}' -X POST "$DD_URL/api/v2/reimport-scan/" \
  --config "$CFG" \
  --form-string "scan_type=$scan_type" \
  --form-string "product_name=$PRODUCT_NAME" \
  --form-string "engagement_name=$ENGAGEMENT_NAME" \
  --form-string "auto_create_context=true" \
  --form-string "test_title=$test_title" \
  --form-string "active=true" \
  --form-string "verified=false" \
  --form-string "close_old_findings=$CLOSE_OLD_FINDINGS" \
  --form-string "deduplication_execution_mode=async_wait" \
  -F "file=@${file}")"

code="$(printf '%s' "$resp" | tail -n1)"
body="$(printf '%s' "$resp" | sed '$d')"
if [ "$code" != "201" ] && [ "$code" != "200" ]; then
  echo "import-report: reimport failed HTTP $code: $(printf '%s' "$body" | head -c 300)" >&2
  exit 4
fi

summary="$(printf '%s' "$body" | python3 -c 'import sys,json
try: d = json.load(sys.stdin)
except Exception: d = {}
print("%s %s" % (d.get("test") or d.get("test_id") or "?", d.get("deduplication_complete")))')"
echo "import-report: $scan_type -> test=${summary% *} dedup_complete=${summary#* } close_old=$CLOSE_OLD_FINDINGS (HTTP $code)" >&2
printf '%s\n' "$body"
