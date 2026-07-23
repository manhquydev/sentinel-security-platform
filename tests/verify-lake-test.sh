#!/usr/bin/env bash
# verify-lake.sh must catch a lake that has drifted from its baseline, across
# any number of Products (docs/decisions/0007: a Product is exactly one
# application, so the baseline is now a products[] list).
#
# Most cases drift the BASELINE rather than the live lake: a baseline claiming
# the wrong count, naming a scan_type that is not in the engagement, or naming
# a Product that does not exist, must all make verify-lake fail. A
# verification script that cannot fail proves nothing. Every case here is
# read-only against the live lake — verify-lake.sh never writes, so nothing
# here needs SKIP_REIMPORT to stay safe, but the variable is honoured (as a
# no-op) for callers that set it out of habit from other suites in this repo.
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

# <file> <trivy> <nuclei>  — a one-Product baseline for the real juice-shop-harness
# Product, with adjustable counts. Semgrep is deliberately absent: it left this
# Product's expected set under decision 0007 (it belongs to a WebGoat Product).
mk_baseline() {
  python3 - "$@" <<'PY'
import json, sys
f, tr, nu = sys.argv[1:4]
json.dump({"products": [{"product": "juice-shop-harness", "engagement": "week1-baseline",
                          "expected": {"Trivy Scan": int(tr), "Nuclei Scan": int(nu)}}]},
          open(f, "w"))
PY
}

sect "the committed baseline reports today's real migration debt as drift"
# infra/defectdojo/lake-baseline.json describes the POST-split target: the
# juice-shop-harness Product carries Trivy and Nuclei only. The live lake has
# not been migrated yet — the 221-finding OWASP Benchmark Semgrep test is
# still sitting in this Product's engagement (docs/decisions/0007) — so
# verify-lake must currently reject the live lake, precisely on that stale
# test. This is real evidence, not a synthetic fixture: it is exactly the
# "first timer firing fails the drift check" state the migration plan exists
# to resolve.
committed_out="$(BASELINE="$REPO_ROOT/infra/defectdojo/lake-baseline.json" "$VERIFY" 2>&1)"
if BASELINE="$REPO_ROOT/infra/defectdojo/lake-baseline.json" "$VERIFY" >/dev/null 2>&1; then
  bad "the committed baseline passed against a lake that still carries the stale Semgrep test — migration already happened and this check is stale"
elif printf '%s' "$committed_out" | grep -q 'extra: Semgrep JSON Report'; then
  ok "committed baseline correctly flags the un-retired OWASP Benchmark Semgrep test as drift"
else
  bad "committed baseline failed for an unexpected reason:"$'\n'"$committed_out"
fi

sect "a baseline that omits a real source fails (the engagement has an extra type)"
python3 - "$WORK/partial.json" <<'PY'
import json, sys
json.dump({"products": [{"product": "juice-shop-harness", "engagement": "week1-baseline",
                          "expected": {"Trivy Scan": 4}}]}, open(sys.argv[1], "w"))
PY
run "$WORK/partial.json" && bad "accepted a baseline missing Nuclei Scan while the lake has it" \
  || ok "rejected a baseline that omits a source present in the lake"

sect "a drifted baseline count fails"
mk_baseline "$WORK/high.json" 5 21
run "$WORK/high.json" && bad "accepted Trivy=5 against a lake of 4" || ok "rejected an inflated count"
mk_baseline "$WORK/low.json" 4 20
run "$WORK/low.json" && bad "accepted Nuclei=20 against a lake of 21" || ok "rejected a deflated count"

sect "a baseline naming an absent scan_type fails"
python3 - "$WORK/ghost.json" <<'PY'
import json, sys
json.dump({"products": [{"product": "juice-shop-harness", "engagement": "week1-baseline",
                          "expected": {"Nonexistent Scan": 1}}]}, open(sys.argv[1], "w"))
PY
run "$WORK/ghost.json" && bad "accepted a scan_type not in the engagement" || ok "rejected an unknown scan_type"

sect "a baseline naming an absent Product fails"
# Observed failing first without the guard: DefectDojo's engagements endpoint
# ignores an EMPTY product= filter rather than matching zero rows — verified
# live, `GET /api/v2/engagements/?product=&name=week1-baseline` returned the
# real engagement (id=1) that belongs to juice-shop-harness. A verifier that
# skips the explicit product-existence check and passes an empty id straight
# into that filter would silently validate against the WRONG Product's
# engagement instead of rejecting the baseline. verify-lake.sh looks the
# Product up by name first and fails closed when that lookup is empty, before
# ever querying engagements.
python3 - "$WORK/ghost-product.json" <<'PY'
import json, sys
json.dump({"products": [{"product": "sentinel-nonexistent-product", "engagement": "week1-baseline",
                          "expected": {"Trivy Scan": 4}}]}, open(sys.argv[1], "w"))
PY
run "$WORK/ghost-product.json" && bad "accepted a Product that does not exist" || ok "rejected an absent Product"

sect "a multi-Product baseline reports each Product independently"
# One entry names the real Product with a real, verifiable count; the other
# names an absent Product. Both must be checked and reported — a Product
# lookup failure must not abort the rest of the baseline.
python3 - "$WORK/mixed.json" <<'PY'
import json, sys
json.dump({"products": [
    {"product": "juice-shop-harness", "engagement": "week1-baseline",
     "expected": {"Trivy Scan": 4, "Nuclei Scan": 21}},
    {"product": "sentinel-nonexistent-product", "engagement": "week1-baseline",
     "expected": {"Trivy Scan": 4}},
]}, open(sys.argv[1], "w"))
PY
mixed_out="$(BASELINE="$WORK/mixed.json" "$VERIFY" 2>&1)"
if BASELINE="$WORK/mixed.json" "$VERIFY" >/dev/null 2>&1; then
  bad "accepted a baseline containing an absent Product"
elif printf '%s' "$mixed_out" | grep -q "Trivy Scan: 4 active (baseline 4)" \
  && printf '%s' "$mixed_out" | grep -q "product 'sentinel-nonexistent-product' not found"; then
  ok "checked the real Product and reported the absent one, in the same run"
else
  bad "did not check both Products independently:"$'\n'"$mixed_out"
fi

sect "an unreadable baseline fails closed"
BASELINE="$WORK/does-not-exist.json" "$VERIFY" >/dev/null 2>&1 \
  && bad "accepted a missing baseline file" || ok "missing baseline file rejected"

printf '\n== summary ==\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
