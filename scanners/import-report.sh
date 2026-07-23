#!/usr/bin/env bash
# Import a SANITIZED scanner report into DefectDojo P1 (phase-03).
#   import-report.sh <scan_type> <sanitized_file> [test_title]
#
# Uses reimport-scan (idempotent: repeated imports update the same Test instead
# of duplicating) into the P1 Product-scoped Writer service account's engagement.
# The caller is responsible for having run redact-report.sh first — this script
# imports whatever file it is given; it does not re-sanitize.
#
# Prints the DefectDojo test id on stdout (for P4's import-specific async poll).
set -euo pipefail

scan_type="${1:?scan_type required (exact DefectDojo name, e.g. 'Trivy Scan')}"
file="${2:?sanitized report file required}"
test_title="${3:-${scan_type}}"

[ -s "$file" ] || { echo "import-report: empty/missing file: $file" >&2; exit 2; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/infra/.env}"
DD_URL="${DD_URL:-http://localhost:8080}"
# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

# Product + engagement identified BY NAME (from P1 .env). reimport-scan needs
# product_name/engagement_name to resolve or auto-create the test the first time
# a given test_title is seen; an engagement id alone yields HTTP 400
# "product_name parameter missing" when the test does not yet exist.
PRODUCT_NAME="${PRODUCT_NAME:-$DD_PRODUCT}"
ENGAGEMENT_NAME="${ENGAGEMENT_NAME:-$DD_ENGAGEMENT}"

# Keep credentials OFF the process argv (visible in `ps aux` on a shared runner).
# Password goes to curl via stdin (--data @-); the issued token goes back to curl
# via a mode-600 --config file, never as a -H argument.
CFG="$(mktemp)"; BODY="$(mktemp)"; chmod 600 "$CFG" "$BODY"
trap 'rm -f "$CFG" "$BODY"' EXIT

# Product-scoped Writer service-account token (NOT admin). Body via stdin.
CI_TOKEN="$(printf '{"username":"%s","password":"%s"}' "$DD_SERVICE_ACCOUNT_USER" "$DD_SERVICE_ACCOUNT_PASSWORD" \
  | curl -sS -X POST "$DD_URL/api/v2/api-token-auth/" \
      -H 'Content-Type: application/json' --data @- \
  | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("token",""))
except Exception: print("")')"
[ -n "$CI_TOKEN" ] || { echo "import-report: service-account auth failed (bad credentials or DD unreachable)" >&2; exit 3; }

# Token in a --config file (mode 600), not on argv.
printf 'header = "Authorization: Token %s"\n' "$CI_TOKEN" > "$CFG"

# auto_create_context finds-or-creates the test within the named product/
# engagement, giving true reimport idempotency (repeat imports update the same
# Test instead of duplicating).
resp="$(curl -sS -w '\n%{http_code}' -X POST "$DD_URL/api/v2/reimport-scan/" \
  --config "$CFG" \
  -F "scan_type=$scan_type" \
  -F "product_name=$PRODUCT_NAME" \
  -F "engagement_name=$ENGAGEMENT_NAME" \
  -F "auto_create_context=true" \
  -F "test_title=$test_title" \
  -F "active=true" -F "verified=false" \
  -F "close_old_findings=true" \
  -F "file=@${file}")"

code="$(printf '%s' "$resp" | tail -n1)"
body="$(printf '%s' "$resp" | sed '$d')"
if [ "$code" != "201" ] && [ "$code" != "200" ]; then
  echo "import-report: reimport failed HTTP $code: $(printf '%s' "$body" | head -c 300)" >&2
  exit 4
fi

test_id="$(printf '%s' "$body" | python3 -c 'import sys,json
try: d=json.load(sys.stdin)
except Exception: d={}
print(d.get("test") or d.get("test_id") or "")')"
echo "import-report: $scan_type -> test=$test_id (HTTP $code)" >&2
printf '%s\n' "$test_id"
