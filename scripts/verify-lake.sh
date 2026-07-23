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
# multi-Product report is more useful than an early abort. Every DefectDojo
# query this script makes is wrapped so a transport failure (DD unreachable,
# timeout) or a parse failure (malformed/unexpected JSON) reports a clean
# "could not verify" line and moves on, instead of an uncaught traceback that
# kills the whole run.
#
# Two lake-wide checks run once, before any Product is inspected, because a
# per-Product baseline entry cannot see what it was never told to look for:
#   L1. Every Product that exists in DefectDojo is named in the baseline. A
#       baseline that only lists some Products is drift by omission — a
#       Product DefectDojo actually holds, that nobody described, is exactly
#       as much a lake-integrity failure as a wrong finding count.
#   L2. No active finding anywhere in the lake points into a scoring corpus
#       (docs/decisions/0007: OWASP Benchmark and similar corpora do not
#       belong in a lake of staging applications). This is instance-wide, not
#       scoped to baseline Products, so it also catches a corpus finding
#       hiding in a Product nobody declared.
#
# Per Product, checks are all fail-closed:
#   0. The Product exists in DefectDojo. A baseline naming a Product nobody has
#      created yet is drift, not a null result to skip past.
#   1. The named engagement exists, AND no other engagement exists in that
#      Product. auto_create_context=true on import means a typo'd engagement
#      name silently creates a sibling engagement inside an authorized
#      Product; that sibling's findings are otherwise checked by nothing, so
#      its mere existence is drift.
#   2. The engagement contains EXACTLY the scan_types the baseline names for
#      that Product — no missing source, no extra or rogue test. Drift outside
#      the listed types is still drift.
#   3. Each source's active, non-duplicate finding count equals the baseline
#      EXACTLY. The scan target is pinned by @sha256 and the rulesets by
#      checksum, so the count cannot legitimately move — any drift is a
#      defect, not a tolerance to absorb. A deliberate pin bump re-records the
#      baseline.
#   4. The most recent import per source is not older than MAX_IMPORT_AGE_SECONDS.
#      Fatal by default (see the constant below) — a freshness check that can
#      never fire is not a check.
#
# Deduplication idempotency (the lake not inflating when the same finding arrives
# twice) is proven behaviourally by dd-smoke.sh, not re-proven here — doing it by
# reimport would make a "verification" step write to the lake, which it must not.
#
# Environment:
#   BASELINE                path to the baseline json (default infra/defectdojo/lake-baseline.json)
#   DD_API_TOKEN            preferred; else infra/.env service account is used
#   DD_URL                  default http://localhost:8080
#   MAX_IMPORT_AGE_SECONDS  overrides the freshness threshold (see default below)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
DD_URL="${DD_URL:-http://localhost:8080}"
BASELINE="${BASELINE:-$REPO_ROOT/infra/defectdojo/lake-baseline.json}"

# infra/systemd/sentinel-scan*.timer runs both writers OnCalendar=daily with
# RandomizedDelaySec=1h, so two consecutive successful imports can legitimately
# land up to ~25h apart. 36h (1.5x the daily cadence) absorbs that jitter on
# both the previous and current firing without flapping, while still failing
# if an entire scheduled day was missed — the exact staleness this check
# exists to catch. `:-` applies the default for both "unset" and "set to
# empty", so a caller cannot accidentally disable the check by blanking the
# variable; override with an explicit larger number to loosen it.
MAX_IMPORT_AGE_SECONDS="${MAX_IMPORT_AGE_SECONDS:-129600}"

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

# --locator-scheme: report how the lake spells the locators of one scan type, so a
# caller can refuse an import that would re-key every finding it touches. Read-only
# like everything else here, and it prints one word rather than joining the pass/fail
# report — it answers a question, it does not assert anything.
#
# The scan type must be isolated by its test_type id, not by test__test_type__name:
# DefectDojo does not register that name lookup as a finding filter, so passing it is
# silently ignored and the query returns EVERY active finding regardless of scan type.
# Reading paths across all types then reports whichever scheme any type happens to use
# (a single absolute Trivy path makes a fully-relative Semgrep lake read "absolute"),
# which is the exact false answer this probe exists to prevent. Resolve the name to its
# id first, exact-match, and filter on that.
if [ "${1:-}" = "--locator-scheme" ]; then
  scan_type="${REPORT_SCAN_TYPE:?REPORT_SCAN_TYPE required}"
  enc="$(printf '%s' "$scan_type" | sed 's/ /%20/g')"
  tt_id="$(api "$DD_URL/api/v2/test_types/?name=$enc" | python3 -c '
import json, os, sys
try:
    rows = json.load(sys.stdin).get("results") or []
except Exception:
    raise SystemExit(0)
want = os.environ["REPORT_SCAN_TYPE"]
m = [r for r in rows if r.get("name") == want]
print(m[0]["id"] if m else "")')"
  [ -n "$tt_id" ] || { echo "unknown"; exit 0; }
  api "$DD_URL/api/v2/findings/?limit=100&active=true&test__test_type=$tt_id" \
    | python3 -c '
import json, sys
try:
    rows = json.load(sys.stdin).get("results") or []
except Exception:
    print("unknown"); raise SystemExit(0)
paths = [r.get("file_path") or "" for r in rows]
paths = [p for p in paths if p]
print("absolute" if any(p.startswith("/") for p in paths)
      else "relative" if paths else "empty")'
  exit 0
fi
urlq() { python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$1"; }

# Baseline accessors. Each takes the product's index in the baseline's
# products[] array so one file can describe any number of Products.
product_count() { python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["products"]))' "$BASELINE"; }
product_name()  { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["products"][int(sys.argv[2])]["product"])' "$BASELINE" "$1"; }
product_engagement() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["products"][int(sys.argv[2])]["engagement"])' "$BASELINE" "$1"; }
product_scan_types() { python3 -c 'import json,sys; [print(k) for k in json.load(open(sys.argv[1]))["products"][int(sys.argv[2])]["expected"]]' "$BASELINE" "$1"; }
product_expected_count() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["products"][int(sys.argv[2])]["expected"][sys.argv[3]])' "$BASELINE" "$1" "$2"; }
all_baseline_products() { python3 -c 'import json,sys
for p in json.load(open(sys.argv[1]))["products"]:
    print(p["product"])' "$BASELINE"; }

# Every DefectDojo-facing accessor below funnels its parsing through this
# idiom: on any transport failure (curl returns empty/garbage on a network
# error) or parse failure (non-JSON body, missing key, wrong shape), it prints
# __ERROR__ instead of raising. A raised exception here would still not kill
# the script (callers invoke check_product/global checks via `fn || bad ...`,
# which fully suspends `set -e` for everything the call runs — verified: a
# failing command inside such a call does not abort the function early or the
# script), but it would dump a raw traceback into the middle of a report meant
# to read as a clean summary. __ERROR__ turns that into one readable FAIL line.
active_count() {
  api "$DD_URL/api/v2/findings/?test=$1&active=true&duplicate=false&limit=1" | python3 -c '
import sys, json
try:
    print(json.load(sys.stdin)["count"])
except Exception:
    print("__ERROR__")
'
}

# Truncation guard shared by the two lake-wide list checks: DefectDojo's list
# endpoints paginate, and silently checking only the first page would turn a
# "could not verify" into a false PASS on a lake bigger than one page — worse
# than no check at all. Prints one of: __ERROR__ | __TRUNCATED__\t<n>\t<total> | the payload.
paged_list_or_marker() { # <extractor-python-body-as-heredoc-on-stdin> reads JSON on stdin
  python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    results = d.get("results", [])
    total = d.get("count", len(results))
    if total > len(results):
        print("__TRUNCATED__\t%d\t%d" % (len(results), total))
        raise SystemExit
    exec(sys.argv[1])
except SystemExit:
    raise
except Exception:
    print("__ERROR__")
' "$1"
}

report_list_marker() { # <marker> <what> -> prints a bad() message and returns 0 if marker was an error; 1 otherwise
  case "$1" in
    __ERROR__)
      bad "could not read $2 from DefectDojo (transport or parse error)"; return 0 ;;
    __TRUNCATED__*)
      local fetched total
      IFS=$'\t' read -r _ fetched total <<<"$1"
      bad "could not verify $2 — only fetched $fetched of $total (raise the page size)"; return 0 ;;
    *) return 1 ;;
  esac
}

# L1: every Product DefectDojo actually holds must be named in the baseline.
# check_product() below proves a baseline-named Product exists; this proves
# the converse — that nothing exists which the baseline does not name. Without
# this, a baseline naming only one Product passes cleanly forever no matter
# how many other Products accumulate in the lake.
check_lake_coverage() {
  local have mismatch
  have="$(api "$DD_URL/api/v2/products/?limit=1000" | paged_list_or_marker '
for p in results:
    print(p.get("name",""))')"
  report_list_marker "$have" "the Product list" && return
  mapfile -t want < <(all_baseline_products)
  mismatch="$(python3 -c '
import sys
want = set(l for l in sys.argv[1].splitlines() if l)
have = set(l for l in sys.argv[2].splitlines() if l)
extra = have - want
if extra:
    print("undeclared Product(s) exist in DefectDojo: " + ", ".join(sorted(extra)))
' "$(printf '%s\n' "${want[@]}")" "$have")"
  [ -z "$mismatch" ] && ok "no undeclared Products exist in DefectDojo" || bad "$mismatch"
}

# L2: docs/decisions/0007's "a Product is one application; scoring corpora do
# not belong in the lake" invariant, checked here (what the scheduler
# actually runs) rather than only in tests/verify-lake-test.sh (what a human
# runs on demand). Instance-wide, not scoped to baseline Products, so it also
# catches a corpus finding sitting inside an undeclared Product.
check_no_corpus_findings() {
  local hits
  hits="$(api "$DD_URL/api/v2/findings/?active=true&limit=1000" | paged_list_or_marker '
n = sum(1 for f in results if "targets/owasp-benchmark" in (f.get("file_path") or ""))
print(n)')"
  report_list_marker "$hits" "active findings" && return
  [ "$hits" = "0" ] && ok "no active finding points into a scoring corpus" \
    || bad "$hits active finding(s) point into a scoring corpus (targets/owasp-benchmark)"
}

# Check one Product against the baseline. Never aborts the whole script — a
# problem with one Product must not hide the state of the others.
check_product() { # <index>
  local idx="$1" pname pengagement p_id eng_id now
  pname="$(product_name "$idx")"
  pengagement="$(product_engagement "$idx")"

  sect "product '$pname' / engagement '$pengagement'"

  p_id="$(api "$DD_URL/api/v2/products/?name=$(urlq "$pname")" | python3 -c '
import sys, json
try:
    r = json.load(sys.stdin)["results"]
    print(r[0]["id"] if r else "")
except Exception:
    print("__ERROR__")
')"
  if [ "$p_id" = "__ERROR__" ]; then
    bad "product '$pname': could not read the Product list from DefectDojo (transport or parse error)"
    return
  fi
  if [ -z "$p_id" ]; then
    bad "product '$pname' not found in DefectDojo"
    return
  fi

  # Every engagement in the Product, not just the one named by the baseline —
  # otherwise a sibling engagement created by a typo'd auto-create import is
  # invisible to this script, and nothing else checks it either.
  local eng_rows
  eng_rows="$(api "$DD_URL/api/v2/engagements/?product=$p_id&limit=1000" | python3 -c '
import sys, json
try:
    for e in json.load(sys.stdin)["results"]:
        print("%s\t%s" % (e["id"], e.get("name","")))
except Exception:
    print("__ERROR__")
')"
  if [ "$eng_rows" = "__ERROR__" ]; then
    bad "product '$pname': could not read engagements from DefectDojo (transport or parse error)"
    return
  fi

  eng_id=""
  while IFS=$'\t' read -r eid ename; do
    [ -n "$eid" ] || continue
    if [ "$ename" = "$pengagement" ] && [ -z "$eng_id" ]; then eng_id="$eid"; fi
  done <<<"$eng_rows"
  if [ -z "$eng_id" ]; then
    bad "engagement '$pengagement' not found in product '$pname' ($p_id)"
    return
  fi

  local eng_mismatch
  eng_mismatch="$(python3 -c '
import sys
want = sys.argv[1]
have = [l.split("\t", 1)[1] for l in sys.argv[2].splitlines() if l and "\t" in l]
extra = sorted(set(have) - {want})
if extra:
    print("extra engagement(s) in product " + repr(sys.argv[3]) + ": " + ", ".join(extra))
' "$pengagement" "$eng_rows" "$pname")"
  [ -z "$eng_mismatch" ] && ok "product '$pname' has no undeclared engagements" || bad "$eng_mismatch"

  # One fetch of the engagement's tests backs both the scan_type set-mismatch
  # check and the scan_type -> test id map the count/freshness checks use.
  local test_rows
  test_rows="$(api "$DD_URL/api/v2/tests/?engagement=$eng_id&limit=1000" | python3 -c '
import sys, json
try:
    for t in json.load(sys.stdin)["results"]:
        print("%s\t%s" % (t.get("scan_type", ""), t["id"]))
except Exception:
    print("__ERROR__")
')"
  if [ "$test_rows" = "__ERROR__" ]; then
    bad "product '$pname': could not read tests for engagement '$pengagement' (transport or parse error)"
    return
  fi

  local -A test_of=()
  while IFS=$'\t' read -r st tid; do
    [ -n "$st" ] || continue
    test_of["$st"]="$tid"
  done <<<"$test_rows"

  mapfile -t scan_types < <(product_scan_types "$idx")
  local eng_types
  eng_types="$(printf '%s\n' "$test_rows" | cut -f1 | grep -v '^$' || true)"

  # Two-way set comparison so a missing source AND a rogue extra test both fail.
  local mismatch
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
    if [ "$got" = "__ERROR__" ]; then
      bad "$st: could not read the finding count from DefectDojo (transport or parse error)"
      continue
    fi
    [ "$got" = "$want" ] && ok "$st: $got active (baseline $want)" || bad "$st: $got active, baseline $want"
  done

  now="$(date +%s)"
  for st in "${scan_types[@]}"; do
    local tid ts age human
    tid="${test_of[$st]:-}"; [ -n "$tid" ] || continue
    ts="$(api "$DD_URL/api/v2/test_imports/?test=$tid&limit=1" | python3 -c '
import sys, json
try:
    r = json.load(sys.stdin)["results"]
    print(r[0]["created"] if r else "")
except Exception:
    print("__ERROR__")
')"
    if [ "$ts" = "__ERROR__" ]; then bad "$st: could not read import history from DefectDojo (transport or parse error)"; continue; fi
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
    if [ "$age" -gt "$MAX_IMPORT_AGE_SECONDS" ]; then
      bad "$st: last import $human ago exceeds MAX_IMPORT_AGE_SECONDS=$MAX_IMPORT_AGE_SECONDS"
    else
      ok "$st: last import $human ago"
    fi
  done
}

n="$(product_count)"
[ "$n" -gt 0 ] || { echo "verify-lake: baseline lists zero products" >&2; exit 2; }

sect "lake coverage"
check_lake_coverage || bad "lake coverage check aborted unexpectedly (see above)"
check_no_corpus_findings || bad "scoring-corpus check aborted unexpectedly (see above)"

for ((i = 0; i < n; i++)); do
  check_product "$i" || bad "product index $i: check aborted unexpectedly (see above)"
done

printf '\n== summary ==\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
