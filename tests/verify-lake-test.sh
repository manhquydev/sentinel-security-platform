#!/usr/bin/env bash
# verify-lake.sh must catch a lake that has drifted from its baseline.
#
# The live lake is correct, so the negative control drifts the BASELINE instead:
# a baseline claiming the wrong count, or naming a scan_type that is not in the
# engagement, must make verify-lake fail. A verification script that cannot fail
# proves nothing. SKIP_REIMPORT keeps every case read-only.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFY="$REPO_ROOT/scripts/verify-lake.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
sect(){ printf '\n== %s ==\n' "$1"; }

# verify-lake is read-only, so every case runs it directly against the live lake.
run() { BASELINE="$1" "$VERIFY" >/dev/null 2>&1; }

mk_baseline() { # <file> <trivy> <semgrep> <nuclei>
  python3 - "$@" <<'PY'
import json, sys
f, tr, sg, nu = sys.argv[1:5]
json.dump({"product": "juice-shop-harness", "engagement": "week1-baseline",
           "expected": {"Trivy Scan": int(tr), "Semgrep JSON Report": int(sg), "Nuclei Scan": int(nu)}},
          open(f, "w"))
PY
}

sect "the committed baseline passes against the live lake"
if BASELINE="$REPO_ROOT/infra/defectdojo/lake-baseline.json" "$VERIFY" >/dev/null 2>&1; then
  ok "the real baseline verifies"
else
  bad "the real baseline does not verify — the lake or the baseline is wrong"
fi

sect "a baseline that OMITS a real source fails (the engagement has an extra type)"
# Only two of the three real scan_types — the third is present in the lake as an
# unaccounted test, which the scan_type-set check must reject.
python3 - "$WORK/partial.json" <<'PY'
import json, sys
json.dump({"product": "juice-shop-harness", "engagement": "week1-baseline",
           "expected": {"Trivy Scan": 4, "Semgrep JSON Report": 221}}, open(sys.argv[1], "w"))
PY
run "$WORK/partial.json" && bad "accepted a baseline missing Nuclei Scan while the lake has it" \
  || ok "rejected a baseline that omits a source present in the lake"

sect "a drifted baseline count fails"
mk_baseline "$WORK/high.json" 5 221 21
run "$WORK/high.json" && bad "accepted Trivy=5 against a lake of 4" || ok "rejected an inflated count"
mk_baseline "$WORK/low.json" 4 220 21
run "$WORK/low.json" && bad "accepted Semgrep=220 against a lake of 221" || ok "rejected a deflated count"

sect "a baseline naming an absent scan_type fails"
python3 - "$WORK/ghost.json" <<'PY'
import json, sys
json.dump({"product": "juice-shop-harness", "engagement": "week1-baseline",
           "expected": {"Nonexistent Scan": 1}}, open(sys.argv[1], "w"))
PY
run "$WORK/ghost.json" && bad "accepted a scan_type not in the engagement" || ok "rejected an unknown scan_type"

sect "an unreadable baseline fails closed"
BASELINE="$WORK/does-not-exist.json" "$VERIFY" >/dev/null 2>&1 \
  && bad "accepted a missing baseline file" || ok "missing baseline file rejected"

printf '\n== summary ==\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
