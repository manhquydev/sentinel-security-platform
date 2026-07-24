#!/usr/bin/env bash
# Week-9 PII-redaction measurement guard (invariant PA5) from
# docs/plans/active/2026-07-24-no-issue-week9-pii-redaction.md.
#
# Runs the recall + false-positive measurement over the committed synthetic corpus and asserts:
#   - recall == 1.0 on the covered shapes, FP == 0 on security content (the measure exits 0);
#   - the run FAILS CLOSED if the corpus is missing/empty (a "0% FP over an absent corpus" is the
#     journal's documented vacuous-measurement failure — proven here with a negative control).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$REPO_ROOT/rag/.venv/bin/python"
MEASURE="$REPO_ROOT/evaluation/pii-redaction/measure.py"
CORPUS="$REPO_ROOT/evaluation/pii-redaction/corpus.json"

PASS=0; FAIL=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
sect() { printf '\n== %s ==\n' "$1"; }

[ -x "$PY" ] || { echo "missing venv at $PY"; exit 2; }

sect "PA5: recall==1.0 on covered shapes AND 0 false-positives on security content"
if "$PY" "$MEASURE"; then
  ok "measurement passes its committed thresholds (recall_min=1.0, fp_max=0)"
else
  bad "PA5 measurement failed its thresholds"
fi

sect "PA5 (fail-closed): the guard refuses to pass over an absent corpus (negative control)"
TMP="$(mktemp -d)"
cp "$MEASURE" "$TMP/measure.py"
# No corpus.json beside the copy -> the presence gate must exit non-zero (2), not report 0% FP.
if "$PY" "$TMP/measure.py" >/dev/null 2>&1; then
  bad "guard PASSED with no corpus present — that is the vacuous-measurement failure it must prevent"
else
  ok "guard fails closed when the corpus is absent (no vacuous 0% FP)"
fi
rm -rf "$TMP"

printf '\n== summary ==\n'
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
