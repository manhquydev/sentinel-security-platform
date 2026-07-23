#!/usr/bin/env bash
# Verify the DefectDojo lake matches its recorded baseline. READ-ONLY: it queries
# the lake and never writes, so it is safe to run standalone or as an
# ExecStartPost after a scan.
#
#   verify-lake.sh
#
# Three checks, all fail-closed:
#   1. The engagement contains EXACTLY the scan_types the baseline names — no
#      missing source, no extra or rogue test. Drift outside the listed types is
#      still drift.
#   2. Each source's active, non-duplicate finding count equals the baseline
#      EXACTLY. The scan target is pinned by @sha256 and the rulesets by checksum,
#      so the count cannot legitimately move — any drift is a defect, not a
#      tolerance to absorb. A deliberate pin bump re-records the baseline.
#   3. The most recent import per source is not older than MAX_IMPORT_AGE_SECONDS.
#      Reported always; fatal only when that variable is set, because "fresh" has
#      no meaning until a scheduler defines a cadence.
#
# Deduplication idempotency (the lake not inflating when the same finding arrives
# twice) is proven behaviourally by dd-smoke.sh, not re-proven here — doing it by
# reimport would make a "verification" step write to the lake, which it must not.
#
# Environment:
#   BASELINE                path to the baseline json (default infra/defectdojo/lake-baseline.json)
#   DD_API_TOKEN            preferred; else infra/.env service account is used
#   DD_URL                  default http://localhost:8080
#   MAX_IMPORT_AGE_SECONDS  make check 3 fatal above this age
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
DD_URL="${DD_URL:-http://localhost:8080}"
BASELINE="${BASELINE:-$REPO_ROOT/infra/defectdojo/lake-baseline.json}"

[ -r "$BASELINE" ] || { echo "verify-lake: cannot read baseline $BASELINE" >&2; exit 2; }

PASS=0; FAIL=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
sect(){ printf '\n== %s ==\n' "$1"; }

# Auth: a pre-issued token, else the service account. Read-only work, so the
# least-privileged credential is enough.
if [ -n "${DD_API_TOKEN:-}" ]; then
  TOKEN="$DD_API_TOKEN"
else
  # shellcheck disable=SC1091
  set -a; . "$REPO_ROOT/infra/.env"; set +a
  TOKEN="$(printf '{"username":"%s","password":"%s"}' "$DD_SERVICE_ACCOUNT_USER" "$DD_SERVICE_ACCOUNT_PASSWORD" \
    | curl -sS -X POST "$DD_URL/api/v2/api-token-auth/" -H 'Content-Type: application/json' --data @- \
    | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))')"
fi
[ -n "$TOKEN" ] || { echo "verify-lake: authentication failed" >&2; exit 3; }

api() { curl -sS -H "Authorization: Token $TOKEN" "$@"; }
urlq() { python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$1"; }

ENGAGEMENT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["engagement"])' "$BASELINE")"

ENG_ID="$(api "$DD_URL/api/v2/engagements/?name=$(urlq "$ENGAGEMENT")" \
  | python3 -c 'import sys,json; r=json.load(sys.stdin)["results"]; print(r[0]["id"] if r else "")')"
[ -n "$ENG_ID" ] || { echo "verify-lake: engagement '$ENGAGEMENT' not found" >&2; exit 4; }

# scan_type -> test id, and the full list of scan_types actually in the engagement.
declare -A TEST_OF
ENG_TYPES="$(api "$DD_URL/api/v2/tests/?engagement=$ENG_ID&limit=1000" \
  | python3 -c 'import sys,json
seen=[]
for t in json.load(sys.stdin)["results"]:
    seen.append(t.get("scan_type"))
print("\n".join(seen))')"
while IFS=$'\t' read -r st tid; do TEST_OF["$st"]="$tid"; done < <(
  api "$DD_URL/api/v2/tests/?engagement=$ENG_ID&limit=1000" \
    | python3 -c 'import sys,json
for t in json.load(sys.stdin)["results"]:
    print("%s\t%s" % (t.get("scan_type"), t["id"]))')

mapfile -t SCAN_TYPES < <(python3 -c 'import json,sys; [print(k) for k in json.load(open(sys.argv[1]))["expected"]]' "$BASELINE")

sect "the engagement contains exactly the baseline's scan_types"
# Two-way set comparison so a missing source AND a rogue extra test both fail.
mismatch="$(python3 -c '
import json, sys
want = set(json.load(open(sys.argv[1]))["expected"])
have_list = [s for s in sys.argv[2].splitlines() if s]
have = set(have_list)
dupes = len(have_list) != len(have)
missing = want - have
extra = have - want
out = []
if missing: out.append("missing: " + ", ".join(sorted(missing)))
if extra:   out.append("extra: " + ", ".join(sorted(extra)))
if dupes:   out.append("two tests share a scan_type")
print(" | ".join(out))' "$BASELINE" "$ENG_TYPES")"
[ -z "$mismatch" ] && ok "engagement scan_types match the baseline set" || bad "engagement drift — $mismatch"

active_count() { api "$DD_URL/api/v2/findings/?test=$1&active=true&duplicate=false&limit=1" | python3 -c 'import sys,json; print(json.load(sys.stdin)["count"])'; }

sect "each source matches the recorded baseline exactly"
for st in "${SCAN_TYPES[@]}"; do
  want="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["expected"][sys.argv[2]])' "$BASELINE" "$st")"
  tid="${TEST_OF[$st]:-}"
  if [ -z "$tid" ]; then bad "$st: no test in engagement $ENG_ID"; continue; fi
  got="$(active_count "$tid")"
  [ "$got" = "$want" ] && ok "$st: $got active (baseline $want)" || bad "$st: $got active, baseline $want"
done

sect "most recent import per source is fresh"
now="$(date +%s)"
for st in "${SCAN_TYPES[@]}"; do
  tid="${TEST_OF[$st]:-}"; [ -n "$tid" ] || continue
  ts="$(api "$DD_URL/api/v2/test_imports/?test=$tid&limit=1" | python3 -c 'import sys,json
r=json.load(sys.stdin)["results"]
print(r[0]["created"] if r else "")')"
  if [ -z "$ts" ]; then bad "$st: no import history"; continue; fi
  # A malformed timestamp must report cleanly, not abort the loop under set -e.
  age="$(python3 -c 'import sys,datetime
try:
    t=datetime.datetime.fromisoformat(sys.argv[1].replace("Z","+00:00"))
    if t.tzinfo is None: t=t.replace(tzinfo=datetime.timezone.utc)
    print(int(sys.argv[2]) - int(t.timestamp()))
except Exception:
    print("")' "$ts" "$now")"
  if [ -z "$age" ]; then bad "$st: unparseable import timestamp '$ts'"; continue; fi
  human="$(python3 -c 'import sys; print("%dh%02dm" % divmod(int(sys.argv[1])//60,60))' "$age")"
  if [ -n "${MAX_IMPORT_AGE_SECONDS:-}" ] && [ "$age" -gt "$MAX_IMPORT_AGE_SECONDS" ]; then
    bad "$st: last import $human ago exceeds MAX_IMPORT_AGE_SECONDS=$MAX_IMPORT_AGE_SECONDS"
  else
    ok "$st: last import $human ago"
  fi
done

printf '\n== summary ==\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
