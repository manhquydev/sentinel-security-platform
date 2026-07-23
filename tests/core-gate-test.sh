#!/usr/bin/env bash
# Completeness gate and close-decision contract (phase-03).
#
# These two guards are the ones that corrupt the lake QUIETLY rather than loudly,
# so both are locked here before the orchestrator exists.
#
#   1. The gate must not false-fail a normal reimport. Deduplication makes
#      created==0 with everything in untouched, so a gate written as
#      `created == reported` fails every run after the first. The predictable
#      response to a gate that always fails is to relax it until it detects
#      nothing, which is worse than having no gate at all.
#
#   2. The gate must not false-PASS. DefectDojo returns no delta on the first
#      import into a new test (only `after`), and the deduplication step is
#      asynchronous by default — statistics read before it finishes describe a
#      state that is about to change.
#
#   3. A zero-finding report must never close existing findings. A scanner
#      pointed at an empty directory exits 0 with an empty report, and closing on
#      that mitigates a whole baseline as "remediated" in one call.
#
# These run entirely against stubbed DefectDojo responses — no live instance, no
# imports, no finding state touched.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE="$REPO_ROOT/scripts/scan-and-import.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
sect(){ printf '\n== %s ==\n' "$1"; }

# A DefectDojo reimport response with the given per-action totals.
mk_resp() { # <file> <created> <closed> <reactivated> <untouched> [dedup_complete]
  local f="$1" c="$2" cl="$3" r="$4" u="$5" dd="${6:-true}"
  python3 - "$f" "$c" "$cl" "$r" "$u" "$dd" <<'PY'
import json, sys
f, c, cl, r, u, dd = sys.argv[1:7]
def block(n): return {"total": {"total": int(n)}}
json.dump({
    "test": 70,
    "deduplication_complete": dd == "true",
    "statistics": {
        "before": {"total": {"total": 0}},
        "delta": {"created": block(c), "closed": block(cl),
                  "reactivated": block(r), "untouched": block(u)},
        "after": {"total": {"total": int(c) + int(u)}},
    },
}, open(f, "w"))
PY
}

# A first-import response: DefectDojo omits delta entirely and returns only `after`.
mk_first_resp() { # <file> <after_total> [dedup_complete]
  python3 - "$1" "$2" "${3:-true}" <<'PY'
import json, sys
f, after, dd = sys.argv[1:4]
json.dump({"test": 99, "deduplication_complete": dd == "true",
           "statistics": {"after": {"total": {"total": int(after)}}}}, open(f, "w"))
PY
}

mk_status() { # <file> <status> <reported> <contact_proven>
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import json, sys
f, st, rep, cp = sys.argv[1:5]
json.dump({"tool": "semgrep", "status": st, "exit": 0, "reported": int(rep),
           "contact_proven": cp == "true", "detail": "stub"}, open(f, "w"))
PY
}

gate() { "$CORE" gate "$1" "$2" >/dev/null 2>&1; }

sect "the gate must not false-fail a deduplicated reimport"
mk_resp "$WORK/dedup.json" 0 0 0 221
if gate "$WORK/dedup.json" 221; then
  ok "created=0 untouched=221 vs reported=221 passes"
else
  bad "a normal reimport was rejected (this is the gate-always-fails trap)"
fi

# Present-in-report buckets (created + reactivated + untouched) sum to reported;
# closed is a separate quantity and must not enter the comparison.
mk_resp "$WORK/mixed.json" 3 2 1 217
if gate "$WORK/mixed.json" 221; then
  ok "created=3 reactivated=1 untouched=217 (=221) passes with closed=2 alongside"
else
  bad "a mixed delta whose present buckets sum to reported was rejected"
fi

sect "a genuine remediation (closed>0) must PASS — closed findings are absent from the report"
# The report shrank by one because a finding was fixed; DefectDojo mitigates it
# into `closed`. The three still-present findings are untouched. reported=3.
mk_resp "$WORK/remediate.json" 0 1 0 3
if gate "$WORK/remediate.json" 3; then
  ok "created=0 closed=1 untouched=3 vs reported=3 passes"
else
  bad "a real remediation was rejected — this is the false-fail that trains people to disable the gate"
fi

sect "a run that matched nothing but closed everything must FAIL"
# Nothing in the report matched an existing finding, yet four were closed. If the
# gate summed closed it would read 4==4 and pass while the import was nonsense.
mk_resp "$WORK/allclosed.json" 0 4 0 0
if gate "$WORK/allclosed.json" 4; then
  bad "accepted created=0 untouched=0 closed=4 against reported=4 (summing closed hides a broken import)"
else
  ok "closed=4 with nothing matched is rejected against reported=4"
fi

sect "the gate must fail on a real mismatch"
mk_resp "$WORK/short.json" 0 0 0 14
if gate "$WORK/short.json" 21; then
  bad "accepted parsed=14 against reported=21 (silent partial import)"
else
  ok "parsed=14 vs reported=21 is rejected"
fi

sect "a first import returns no delta and must still be gated"
mk_first_resp "$WORK/first.json" 221
if gate "$WORK/first.json" 221; then
  ok "first import gated on statistics.after"
else
  bad "first import rejected — delta is absent by design on a new test"
fi

mk_first_resp "$WORK/firstbad.json" 200
if gate "$WORK/firstbad.json" 221; then
  bad "accepted after=200 against reported=221 on a first import"
else
  ok "first import mismatch is rejected"
fi

sect "unfinished deduplication must not be read as success"
mk_resp "$WORK/racing.json" 0 0 0 221 false
if gate "$WORK/racing.json" 221; then
  bad "accepted a response with deduplication_complete=false"
else
  ok "deduplication_complete=false is rejected"
fi

sect "a validated zero-finding scan is a pass, not a failure"
mk_resp "$WORK/empty.json" 0 0 0 0
if gate "$WORK/empty.json" 0; then
  ok "reported=0 parsed=0 passes"
else
  bad "a clean scan was treated as a gate failure"
fi

sect "close_old_findings is granted only by proof, never by default"
mk_status "$WORK/good.json" ok 221 true
[ "$("$CORE" decide "$WORK/good.json" 2>/dev/null)" = "true" ] \
  && ok "ok + contact proven + findings -> close" \
  || bad "a healthy scan was denied close_old_findings"

mk_status "$WORK/zero.json" ok 0 true
[ "$("$CORE" decide "$WORK/zero.json" 2>/dev/null)" = "false" ] \
  && ok "zero-finding report -> do NOT close" \
  || bad "a zero-finding report would close the baseline"

mk_status "$WORK/nocontact.json" ok 221 false
[ "$("$CORE" decide "$WORK/nocontact.json" 2>/dev/null)" = "false" ] \
  && ok "contact not proven -> do NOT close" \
  || bad "a scan with no proof of contact would close the baseline"

mk_status "$WORK/err.json" error 221 true
[ "$("$CORE" decide "$WORK/err.json" 2>/dev/null)" = "false" ] \
  && ok "status=error -> do NOT close" \
  || bad "a failed scan would close the baseline"

sect "malformed input fails closed"
echo 'not json' > "$WORK/junk.json"
if gate "$WORK/junk.json" 221; then bad "accepted unparseable response"; else ok "unparseable response rejected"; fi
[ "$("$CORE" decide "$WORK/junk.json" 2>/dev/null)" = "false" ] \
  && ok "unparseable status -> do NOT close" \
  || bad "unparseable status did not fail closed"

sect "a re-keying import may not close findings"
# DefectDojo identifies a Semgrep finding by file_path + line + vuln_id_from_tool. A
# scanner that starts spelling paths differently re-keys everything it reports, and a
# close-enabled import then records a remediation for each old finding. The active count
# does not move, so the exact-match drift check is structurally blind to it.
for case in "relative absolute true" "absolute absolute false" "relative relative false" "empty absolute false"; do
  set -- $case
  got="$("$CORE" rekey "$1" "$2" 2>/dev/null)"
  [ "$got" = "$3" ] \
    && ok "incoming=$1 lake=$2 -> suppress closing: $3" \
    || bad "incoming=$1 lake=$2 expected $3, got '$got'"
done
grep -q -- '--locator-scheme' "$REPO_ROOT/scripts/verify-lake.sh" \
  && ok "the lake's own locator scheme is readable, read-only" \
  || bad "no way to read the lake's locator scheme"

printf '\n== summary ==\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
