#!/usr/bin/env bash
# Scanner status-sidecar contract (phase-03).
#
# The orchestrator keys on `<raw>.status.json`, not on wrapper exit codes, because
# the four wrappers overload their exit-code namespace. These assertions pin the
# schema and the three properties the orchestrator relies on:
#   - the sidecar exists even when the wrapper failed, so "ran and failed" is
#     distinguishable from "never ran";
#   - `reported` is the RAW finding count, with 0 a valid clean result and -1 the
#     unparseable sentinel that forces status error;
#   - `contact_proven` is true only when the wrapper positively reached its target.
#
# Uses /bin/true as a stand-in scanner where a real scan would be slow; the
# control flow under test is the wrapper's, not the scanner's.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SC="$REPO_ROOT/scanners"
WRITE="$SC/write-status.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
sect(){ printf '\n== %s ==\n' "$1"; }

field() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2]))' "$1" "$2" 2>/dev/null; }

# The committed fixtures are the report corpus here, not scanners/out/*, because
# those are gitignored working artifacts that any real core run overwrites — a
# test must not depend on the residue of a previous scan.
FIX="$REPO_ROOT/tests/fixtures"

sect "the sidecar has every field, correctly typed"
cp "$FIX/semgrep-planted-secret.json" "$WORK/s.json"
"$WRITE" semgrep "$WORK/s.json" ok true 0 "detail here"
sidecar="$WORK/s.json.status.json"
if [ -s "$sidecar" ]; then
  python3 - "$sidecar" <<'PY' && ok "schema well-formed and typed" || bad "schema malformed"
import json, sys
d = json.load(open(sys.argv[1]))
assert d["tool"] == "semgrep"
assert d["status"] in ("ok", "error")
assert isinstance(d["exit"], int)
assert isinstance(d["reported"], int)
assert isinstance(d["contact_proven"], bool)
assert isinstance(d["detail"], str)
PY
else
  bad "no sidecar written"
fi

sect "reported matches an independent count of the raw report"
# Expected counts are computed from the fixtures, not hardcoded, so a fixture
# edit cannot silently desynchronise the assertion. jq/python count the same way
# the sidecar must.
count_expected() { # <tool> <file>
  case "$1" in
    semgrep) python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1])).get("results") or []))' "$2" ;;
    trivy)   python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(sum(len(r.get(k) or []) for r in (d.get("Results") or []) for k in ("Secrets","Misconfigurations","Vulnerabilities")))' "$2" ;;
    nuclei)  awk 'NF{n++} END{print n+0}' "$2" ;;
    zap)     python3 -c 'import sys,xml.etree.ElementTree as ET;print(sum(1 for _ in ET.parse(sys.argv[1]).getroot().iter("alertitem")))' "$2" ;;
  esac
}
for pair in "semgrep:semgrep-planted-secret.json" "trivy:trivy-planted-secret.json" \
            "nuclei:nuclei-planted-secret.jsonl" "zap:zap-planted-token.xml"; do
  tool="${pair%%:*}"; fx="$FIX/${pair#*:}"
  ext="${pair##*.}"
  cp "$fx" "$WORK/r.$ext"; "$WRITE" "$tool" "$WORK/r.$ext" ok true 0 x
  got="$(field "$WORK/r.$ext.status.json" reported)"
  want="$(count_expected "$tool" "$fx")"
  [ "$got" = "$want" ] && ok "$tool reported=$got (independently counted $want)" \
                       || bad "$tool reported=$got, independent count $want"
  rm -f "$WORK/r.$ext" "$WORK/r.$ext.status.json"
done

sect "an unparseable report is -1 and forces status error"
printf 'not json{' > "$WORK/bad.json"
"$WRITE" semgrep "$WORK/bad.json" ok true 0 x
[ "$(field "$WORK/bad.json.status.json" reported)" = "-1" ] && ok "reported=-1" || bad "reported not -1"
[ "$(field "$WORK/bad.json.status.json" status)" = "error" ] && ok "status downgraded to error" || bad "status not forced to error"

sect "a broken run writes status=error, contact=false, even on a non-zero exit"
rm -f "$WORK/dead.jsonl.status.json"
ALLOWLIST="127.0.0.1:19" TARGET_URL="http://127.0.0.1:19" NUCLEI_BIN=/bin/true TARGET_READY_TIMEOUT=2 \
  "$SC/run-nuclei.sh" "$WORK/dead.jsonl" >/dev/null 2>&1
rc=$?
if [ -s "$WORK/dead.jsonl.status.json" ]; then
  ok "sidecar present after wrapper exit $rc"
  [ "$(field "$WORK/dead.jsonl.status.json" status)" = "error" ] && ok "status=error on a dead target" || bad "status not error"
  [ "$(field "$WORK/dead.jsonl.status.json" contact_proven)" = "False" ] && ok "contact_proven=false" || bad "contact wrongly proven"
else
  bad "no sidecar after a failed run — the failure is indistinguishable from never running"
fi

sect "a clean run against a live target is status=ok, reported=0, contact proven"
rm -f "$WORK/live.jsonl.status.json"
ALLOWLIST="127.0.0.1:13000" TARGET_URL="http://127.0.0.1:13000" NUCLEI_BIN=/bin/true \
  "$SC/run-nuclei.sh" "$WORK/live.jsonl" >/dev/null 2>&1
if [ -s "$WORK/live.jsonl.status.json" ]; then
  [ "$(field "$WORK/live.jsonl.status.json" status)" = "ok" ] && ok "status=ok" || bad "clean run not ok"
  [ "$(field "$WORK/live.jsonl.status.json" reported)" = "0" ] && ok "reported=0 (clean is not failure)" || bad "reported wrong"
  [ "$(field "$WORK/live.jsonl.status.json" contact_proven)" = "True" ] && ok "contact proven" || bad "contact not proven on a live target"
else
  bad "no sidecar after a clean run"
fi

sect "nuclei redirect/egress flags are set (configuration assertion, not a live redirect test)"
# Constructing a redirecting endpoint the loopback harness would follow is not
# practical here, so this asserts the flags are present in the invocation. -dr
# forcibly disables redirects; -ni disables third-party OAST callbacks.
if grep -q 'redirect_egress_flags=(-dr -ni)' "$SC/run-nuclei.sh"; then
  ok "run-nuclei.sh sets -dr and -ni"
else
  bad "run-nuclei.sh is missing the redirect/egress flags"
fi

sect "the sidecar is published atomically (no partial file under a temp name)"
ls "$WORK"/.status.* >/dev/null 2>&1 && bad "a temp status file was left behind" || ok "no temp status residue"

printf '\n== summary ==\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
