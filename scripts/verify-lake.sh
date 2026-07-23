#!/usr/bin/env bash
# Verify the DefectDojo lake matches its recorded baseline. READ-ONLY: it queries
# the lake and never writes, so it is safe to run standalone or as an
# ExecStartPost after a scan.
#
#   verify-lake.sh
#
# The baseline names one or more Products (docs/decisions/0007: a Product is
# exactly one application). Each Product is checked independently, and a
# problem with one Product does not stop the others from being checked — a
# multi-Product report is more useful than an early abort.
#
# Per Product, four checks, all fail-closed:
#   0. The Product exists in DefectDojo. A baseline naming a Product nobody has
#      created yet is drift, not a null result to skip past.
#   1. The engagement contains EXACTLY the scan_types the baseline names for
#      that Product — no missing source, no extra or rogue test. Drift outside
#      the listed types is still drift.
#   2. Each source's active, non-duplicate finding count equals the baseline
#      EXACTLY. The scan target is pinned by @sha256 and the rulesets by
#      checksum, so the count cannot legitimately move — any drift is a
#      defect, not a tolerance to absorb. A deliberate pin bump re-records the
#      baseline.
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

# Baseline accessors. Each takes the product's index in the baseline's
# products[] array so one file can describe any number of Products.
product_count() { python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["products"]))' "$BASELINE"; }
product_name()  { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["products"][int(sys.argv[2])]["product"])' "$BASELINE" "$1"; }
product_engagement() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["products"][int(sys.argv[2])]["engagement"])' "$BASELINE" "$1"; }
product_scan_types() { python3 -c 'import json,sys; [print(k) for k in json.load(open(sys.argv[1]))["products"][int(sys.argv[2])]["expected"]]' "$BASELINE" "$1"; }
product_expected_count() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["products"][int(sys.argv[2])]["expected"][sys.argv[3]])' "$BASELINE" "$1" "$2"; }

active_count() { api "$DD_URL/api/v2/findings/?test=$1&active=true&duplicate=false&limit=1" | python3 -c 'import sys,json; print(json.load(sys.stdin)["count"])'; }

# Check one Product against the baseline. Never aborts the whole script — a
# problem with one Product must not hide the state of the others.
check_product() { # <index>
  local idx="$1" pname pengagement p_id eng_id eng_types mismatch now
  pname="$(product_name "$idx")"
  pengagement="$(product_engagement "$idx")"

  sect "product '$pname' / engagement '$pengagement'"

  p_id="$(api "$DD_URL/api/v2/products/?name=$(urlq "$pname")" \
    | python3 -c 'import sys,json; r=json.load(sys.stdin)["results"]; print(r[0]["id"] if r else "")')"
  if [ -z "$p_id" ]; then
    bad "product '$pname' not found in DefectDojo"
    return
  fi

  eng_id="$(api "$DD_URL/api/v2/engagements/?product=$p_id&name=$(urlq "$pengagement")" \
    | python3 -c 'import sys,json; r=json.load(sys.stdin)["results"]; print(r[0]["id"] if r else "")')"
  if [ -z "$eng_id" ]; then
    bad "engagement '$pengagement' not found in product '$pname' ($p_id)"
    return
  fi

  local -A test_of
  eng_types="$(api "$DD_URL/api/v2/tests/?engagement=$eng_id&limit=1000" \
    | python3 -c 'import sys,json
for t in json.load(sys.stdin)["results"]:
    print(t.get("scan_type"))')"
  while IFS=$'\t' read -r st tid; do test_of["$st"]="$tid"; done < <(
    api "$DD_URL/api/v2/tests/?engagement=$eng_id&limit=1000" \
      | python3 -c 'import sys,json
for t in json.load(sys.stdin)["results"]:
    print("%s\t%s" % (t.get("scan_type"), t["id"]))')

  mapfile -t scan_types < <(product_scan_types "$idx")

  # Two-way set comparison so a missing source AND a rogue extra test both fail.
  mismatch="$(python3 -c '
import sys
want = set(l for l in sys.argv[1].splitlines() if l)
have_list = [s for s in sys.argv[2].splitlines() if s]
have = set(have_list)
dupes = len(have_list) != len(have)
missing = want - have
extra = have - want
out = []
if missing: out.append("missing: " + ", ".join(sorted(missing)))
if extra:   out.append("extra: " + ", ".join(sorted(extra)))
if dupes:   out.append("two tests share a scan_type")
print(" | ".join(out))' "$(printf '%s\n' "${scan_types[@]}")" "$eng_types")"
  [ -z "$mismatch" ] && ok "engagement scan_types match the baseline set" || bad "engagement drift — $mismatch"

  for st in "${scan_types[@]}"; do
    local want got tid
    want="$(product_expected_count "$idx" "$st")"
    tid="${test_of[$st]:-}"
    if [ -z "$tid" ]; then bad "$st: no test in engagement $eng_id"; continue; fi
    got="$(active_count "$tid")"
    [ "$got" = "$want" ] && ok "$st: $got active (baseline $want)" || bad "$st: $got active, baseline $want"
  done

  now="$(date +%s)"
  for st in "${scan_types[@]}"; do
    local tid ts age human
    tid="${test_of[$st]:-}"; [ -n "$tid" ] || continue
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
}

n="$(product_count)"
[ "$n" -gt 0 ] || { echo "verify-lake: baseline lists zero products" >&2; exit 2; }
for ((i = 0; i < n; i++)); do
  check_product "$i"
done

printf '\n== summary ==\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
