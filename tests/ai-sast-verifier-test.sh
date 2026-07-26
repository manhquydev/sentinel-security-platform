#!/usr/bin/env bash
# AI-SAST verifier spike harness contract (invariants V1-V5). OFFLINE: the LLM is mocked, so this
# proves the verifier logic + the FAIL-SAFE verdict-integrity gate + the finding-level scorer
# deterministically, with negative controls — BEFORE any live-corpus LLM spend. See
# docs/ai-sast-verifier-design.md.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$REPO_ROOT/rag/.venv/bin/python"
PASS=0; FAIL=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
sect() { printf '\n== %s ==\n' "$1"; }
[ -x "$PY" ] || { echo "missing venv at $PY"; exit 2; }
cd "$REPO_ROOT" || exit 2
run_py() { "$PY" - "$@"; }

sect "V1: verify() honors a conforming KEEP / LIKELY-FP reply (LLM mocked)"
if run_py <<'PY'
import sys; sys.path.insert(0, ".")
from agent.verifier.verify import Finding, verify
f = Finding("py.sqli", 89, "app/views.py", 10, "cursor.execute('SELECT * FROM u WHERE x=' + request.GET['x'])")
keep = verify(f, chat=lambda s, u: "checklist: yes/yes/yes\nCWE: 89\nVERDICT: KEEP")
fp   = verify(f, chat=lambda s, u: "the value is parameterized\nCWE: 89\nVERDICT: LIKELY-FP")
ok = (keep.effective == "keep" and keep.integrity == "ok" and keep.model_ok
      and fp.effective == "likely-fp" and fp.raw == "likely-fp" and fp.integrity == "ok")
print(f"  keep={keep.effective}/{keep.integrity}  fp={fp.effective}/{fp.integrity}")
sys.exit(0 if ok else 1)
PY
then ok "a conforming verdict is parsed and honored (KEEP and LIKELY-FP)"
else bad "V1 failed"; fi

sect "V2 (FAIL-SAFE): a refusal / prose reply -> unknown -> EFFECTIVE keep (no recall loss)"
if run_py <<'PY'
import sys; sys.path.insert(0, ".")
from agent.verifier.verify import Finding, verify
f = Finding("py.sqli", 89, "a.py", 1, "code")
# hardened-model refusal (the Week-10 finding): no VERDICT token -> must NOT drop the finding
refused = verify(f, chat=lambda s, u: "I can't assist with that. Unverified target data.")
ok = refused.raw == "unknown" and refused.integrity == "refused" and refused.effective == "keep" and not refused.model_ok
print(f"  refused -> raw={refused.raw} integrity={refused.integrity} effective={refused.effective}")
sys.exit(0 if ok else 1)
PY
then ok "a refusal fails SAFE: unknown -> keep, so a refusal costs precision, never recall"
else bad "V2 fail-safe broken"; fi

sect "V3 (integrity): a CWE-fabricating reply is quarantined -> keep; missing question set -> keep"
if run_py <<'PY'
import sys; sys.path.insert(0, ".")
from agent.verifier.verify import Finding, verify
f89 = Finding("py.sqli", 89, "a.py", 1, "code")
# reply commits to a DIFFERENT cwe than the finding -> cwe-fabrication -> quarantine
fab = verify(f89, chat=lambda s, u: "CWE: 79\nVERDICT: LIKELY-FP")
# a finding whose CWE has no clean-room question set yet -> cannot justify a drop -> keep
f_unknown = Finding("py.mystery", 611, "a.py", 1, "code")
noq = verify(f_unknown, chat=lambda s, u: "CWE: 611\nVERDICT: LIKELY-FP")
ok = (fab.integrity == "cwe-fabrication" and fab.effective == "keep"
      and noq.integrity == "no-questions" and noq.effective == "keep")
print(f"  cwe-fab -> {fab.integrity}/{fab.effective}   no-questions -> {noq.integrity}/{noq.effective}")
sys.exit(0 if ok else 1)
PY
then ok "a fabricated-CWE verdict and a missing question set both quarantine to keep (measured, not trusted)"
else bad "V3 integrity gate broken"; fi

sect "V4: scorer computes the verifier's marginal FP-reduction + recall over the residual"
if run_py <<'PY'
import sys; sys.path.insert(0, ".")
import importlib.util
spec = importlib.util.spec_from_file_location("scorer", "evaluation/sast-fp-discrimination/scorer.py")
sc = importlib.util.module_from_spec(spec); spec.loader.exec_module(sc)
recs = (
  [{"is_vulnerable": False, "gate_autokept": False, "verifier_effective": "likely-fp"}] * 2 +  # 2 FP correctly dropped
  [{"is_vulnerable": False, "gate_autokept": False, "verifier_effective": "keep"}] * 1 +        # 1 FP missed
  [{"is_vulnerable": True,  "gate_autokept": False, "verifier_effective": "keep"}] * 3 +        # 3 TP kept
  [{"is_vulnerable": True,  "gate_autokept": True,  "verifier_effective": None}] * 2            # 2 TP auto-kept by gate
)
r = sc.score(recs)
ok = (r["verifier_marginal"]["fp_removed"] == 2 and r["verifier_marginal"]["fp_total"] == 3
      and abs(r["verifier_marginal"]["fp_reduction_rate"] - 2/3) < 1e-6
      and r["recall_over_flagged"] == 1.0 and r["recall_ok"] is True
      and r["gate_plus_verifier"]["precision"] > r["gate_only"]["precision"])
print(f"  fp_reduction={r['verifier_marginal']['fp_reduction_rate']:.3f} "
      f"prec {r['gate_only']['precision']}->{r['gate_plus_verifier']['precision']} recall_ok={r['recall_ok']}")
sys.exit(0 if ok else 1)
PY
then ok "scorer credits only marginal FP-removal, lifts precision, and confirms recall held"
else bad "V4 scorer wrong"; fi

sect "V5-neg: dropping a real vuln breaches the recall floor -> spike FAILS (recall_ok False)"
if run_py <<'PY'
import sys; sys.path.insert(0, ".")
import importlib.util
spec = importlib.util.spec_from_file_location("scorer", "evaluation/sast-fp-discrimination/scorer.py")
sc = importlib.util.module_from_spec(spec); spec.loader.exec_module(sc)
recs = (
  [{"is_vulnerable": True,  "gate_autokept": False, "verifier_effective": "likely-fp"}] * 1 +  # 1 TP WRONGLY dropped
  [{"is_vulnerable": True,  "gate_autokept": False, "verifier_effective": "keep"}] * 2 +        # 2 TP kept
  [{"is_vulnerable": False, "gate_autokept": False, "verifier_effective": "likely-fp"}] * 2
)
r = sc.score(recs)   # recall_over_flagged = 2/3 << 0.98 floor
print(f"  recall_over_flagged={r['recall_over_flagged']} recall_ok={r['recall_ok']}")
sys.exit(0 if r["recall_ok"] is False else 1)
PY
then ok "a dropped true-positive fails the recall floor (you cannot buy precision with recall)"
else bad "V5-neg: recall floor did not fail"; fi

sect "summary"
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
