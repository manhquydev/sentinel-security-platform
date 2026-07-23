#!/usr/bin/env bash
# Import-path safety contract (phase-02).
#
# These assertions cover the ways an unattended scheduler can quietly destroy the
# lake through import-report.sh. Each one failed against the previous version:
#
#   1. close_old_findings was hardcoded true, so any scan that produced an empty
#      report closed the whole baseline as "remediated".
#   2. `set -a; . infra/.env` overwrote a caller-supplied engagement, landing a
#      scan in the baseline instead of where the caller addressed it.
#   3. Every field went through `curl -F`, which reads a file when the value
#      starts with @ or <.
#   4. Authentication required the env file, which carries the AES credential key
#      and the database password — secrets a CI runner should never hold.
#   5. The response was reduced to a test id, discarding the statistics a
#      completeness gate is built on.
#
# Requires a running DefectDojo and infra/.env (for the service account only).
# Imports are idempotent reimports into the existing baseline with
# close_old_findings=false, so running this suite cannot mutate finding state.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMPORT="$REPO_ROOT/scanners/import-report.sh"
REPORT="$REPO_ROOT/scanners/out/trivy.san.json"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
sect(){ printf '\n== %s ==\n' "$1"; }

[ -s "$REPORT" ] || { echo "missing $REPORT — run redact-report.sh first" >&2; exit 2; }
# shellcheck disable=SC1091
set -a; . "$REPO_ROOT/infra/.env"; set +a

sect "close_old_findings defaults to false (an empty report must not mitigate a baseline)"
resp="$WORK/default.json"
if "$IMPORT" "Trivy Scan" "$REPORT" "Trivy Scan" >"$resp" 2>/dev/null; then
  got="$(python3 -c 'import sys,json; print(json.load(open(sys.argv[1])).get("close_old_findings"))' "$resp")"
  [ "$got" = "False" ] && ok "close_old_findings=False when unset" || bad "close_old_findings=$got when unset (want False)"
else
  bad "import with defaults failed"
fi

sect "the caller's engagement survives the env file (it used to be silently overwritten)"
printf 'DD_PRODUCT=%s\nDD_ENGAGEMENT=engagement-that-must-not-be-used\n' "$DD_PRODUCT" > "$WORK/decoy.env"
resp="$WORK/engagement.json"
if ENV_FILE="$WORK/decoy.env" ENGAGEMENT_NAME="$DD_ENGAGEMENT" \
   DD_SERVICE_ACCOUNT_USER="$DD_SERVICE_ACCOUNT_USER" DD_SERVICE_ACCOUNT_PASSWORD="$DD_SERVICE_ACCOUNT_PASSWORD" \
   "$IMPORT" "Trivy Scan" "$REPORT" "Trivy Scan" >"$resp" 2>/dev/null; then
  got="$(python3 -c 'import sys,json; print(json.load(open(sys.argv[1])).get("engagement_name"))' "$resp")"
  [ "$got" = "$DD_ENGAGEMENT" ] && ok "caller engagement reached the API ($got)" \
                                || bad "engagement was overwritten: got '$got', want '$DD_ENGAGEMENT'"
else
  bad "import with a caller engagement override failed"
fi

sect "curl -F file-read vectors are rejected before they reach the wire"
for probe in '@/etc/passwd' '</etc/passwd' 'name;rm -rf /'; do
  if ENGAGEMENT_NAME="$probe" "$IMPORT" "Trivy Scan" "$REPORT" >/dev/null 2>&1; then
    bad "accepted a dangerous engagement name: $probe"
  else
    ok "rejected engagement name: $probe"
  fi
done
if TITLE_PROBE='@/etc/hostname' "$IMPORT" "Trivy Scan" "$REPORT" '@/etc/hostname' >/dev/null 2>&1; then
  bad "accepted a dangerous test_title"
else
  ok "rejected a dangerous test_title"
fi

sect "a pre-issued token needs no credential file (CI must not hold the AES key)"
tok="$(printf '{"username":"%s","password":"%s"}' "$DD_SERVICE_ACCOUNT_USER" "$DD_SERVICE_ACCOUNT_PASSWORD" \
  | curl -sS -X POST "${DD_URL:-http://localhost:8080}/api/v2/api-token-auth/" \
      -H 'Content-Type: application/json' --data @- \
  | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))')"
if [ -z "$tok" ]; then
  bad "could not issue a service-account token"
else
  resp="$WORK/token.json"
  if env -i PATH="$PATH" HOME="$HOME" \
        DD_API_TOKEN="$tok" PRODUCT_NAME="$DD_PRODUCT" ENGAGEMENT_NAME="$DD_ENGAGEMENT" \
        ENV_FILE=/nonexistent/must-not-be-read \
        "$IMPORT" "Trivy Scan" "$REPORT" "Trivy Scan" >"$resp" 2>/dev/null; then
    ok "imported with DD_API_TOKEN and an unreadable ENV_FILE"
  else
    bad "token-only import failed (it must not need the env file)"
  fi
fi

sect "the response carries what a completeness gate needs"
resp="$WORK/stats.json"
if "$IMPORT" "Trivy Scan" "$REPORT" "Trivy Scan" >"$resp" 2>/dev/null; then
  python3 - "$resp" <<'PY' && ok "statistics + deduplication_complete present" || bad "response is missing gate inputs"
import json, sys
d = json.load(open(sys.argv[1]))
stats = d.get("statistics") or {}
# delta is absent on the FIRST import into a new test (only "after" exists), so a
# gate must branch on that; here the baseline test already exists.
assert "after" in stats, "statistics.after missing"
assert "delta" in stats, "statistics.delta missing on a reimport"
assert d.get("deduplication_complete") is True, "deduplication_complete not True under async_wait"
PY
else
  bad "import for the statistics check failed"
fi

printf '\n== summary ==\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
