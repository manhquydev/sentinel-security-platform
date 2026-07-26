#!/usr/bin/env bash
# Week-11 FinOps contract (invariants FO1-FO6): per-run cost/token/latency metering + spike alerting
# (agent/finops.py, decision 0019). Mostly UNIT-level (no gateway); one live leg SKIPs without a key.
# Every "must hold" carries a negative control (a changed input flips the assertion).
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

sect "FO1: run_meter aggregates exact tokens/latency + per-model cost estimate"
if run_py <<'PY'
import sys; sys.path.insert(0, ".")
from agent import finops
with finops.run_meter("t1") as m:
    finops.record("cheap-sast", 1000, 500, 1.2)
    finops.record("cheap-sast", 2000, 100, 0.8)
    finops.record("local-vllm", 4000, 4000, 3.0)
r = m.report()
# tokens exact; local-vllm priced 0; cheap-sast cost = (3000/1e6*0.27)+(600/1e6*1.10)
exp_cost = round(3000/1e6*0.27 + 600/1e6*1.10, 6)
ok = (r["total_tokens"] == 11600 and r["prompt_tokens"] == 7000 and r["completion_tokens"] == 4600
      and r["calls"] == 3 and r["cost_estimate_usd"] == exp_cost and r["cost_is_estimate"] is True
      and r["per_model"]["local-vllm"]["cost_estimate_usd"] == 0.0
      and r["latency_s"]["total"] == 5.0 and r["latency_s"]["max"] == 3.0)
print(f"  tokens={r['total_tokens']} cost={r['cost_estimate_usd']} (exp {exp_cost}) lat={r['latency_s']}")
sys.exit(0 if ok else 1)
PY
then ok "meter aggregates exact tokens + latency, prices per model, flags cost as estimate"
else bad "FO1 aggregation wrong"; fi

sect "FO1-neg: a changed record changes the totals (not a rubber stamp)"
if run_py <<'PY'
import sys; sys.path.insert(0, ".")
from agent import finops
with finops.run_meter("t") as m:
    finops.record("cheap-sast", 1000, 500, 1.0)
a = m.report()["total_tokens"]
with finops.run_meter("t2") as m2:
    finops.record("cheap-sast", 9999, 500, 1.0)
b = m2.report()["total_tokens"]
sys.exit(0 if a != b and b == 10499 else 1)
PY
then ok "totals track the actual records (negative control holds)"
else bad "FO1-neg: totals did not change"; fi

sect "FO2: record() outside a meter is a no-op (opt-in; nothing changes for non-adopters)"
if run_py <<'PY'
import sys; sys.path.insert(0, ".")
from agent import finops
finops.record("cheap-sast", 100, 100, 0.5)   # no active meter -> must not raise, must not record
with finops.run_meter("t") as m:
    pass
sys.exit(0 if m.report()["calls"] == 0 else 1)
PY
then ok "metering is strictly opt-in: no active meter -> no record, no crash"
else bad "FO2: record leaked outside a meter"; fi

sect "FO3: check_thresholds flags a breach AND passes within budget (both directions)"
if run_py <<'PY'
import sys; sys.path.insert(0, ".")
from agent import finops
with finops.run_meter("t") as m:
    finops.record("sast-sol", 150000, 100000, 5.0)   # 250k tokens -> breaches the 200k token ceiling
over = finops.check_thresholds(m.report())
with finops.run_meter("t2") as m2:
    finops.record("cheap-sast", 100, 100, 0.5)       # tiny -> within budget
under = finops.check_thresholds(m2.report())
metrics = {a["metric"] for a in over}
ok = bool(over) and "total_tokens" in metrics and under == []
print(f"  breached={sorted(metrics)}  within_budget_alerts={under}")
sys.exit(0 if ok else 1)
PY
then ok "a cost/token spike raises alerts; a small run raises none (the drift/spike guard works both ways)"
else bad "FO3: threshold guard wrong"; fi

sect "FO4: unknown model is flagged unpriced (no silent \$0)"
if run_py <<'PY'
import sys; sys.path.insert(0, ".")
from agent import finops
with finops.run_meter("t") as m:
    finops.record("some-unlisted-model", 1000, 1000, 1.0)
r = m.report()
sys.exit(0 if r["unpriced_models"] == ["some-unlisted-model"] else 1)
PY
then ok "an unpriced model is surfaced, not silently costed at \$0"
else bad "FO4: unpriced model not flagged"; fi

sect "FO5: agent/llm.py records usage into an active meter (live; SKIP without a gateway key)"
if [ -z "${LITELLM_MASTER_KEY:-}" ]; then
  printf '  \033[33mSKIP\033[0m FO5 live gateway metering (needs LITELLM_MASTER_KEY)\n'
else
  if run_py <<'PY'
import sys; sys.path.insert(0, ".")
from agent import finops, llm
with finops.run_meter("live") as m:
    llm.chat([llm.Msg("user", "Reply with the single word OK.", llm.operator())],
             model="sast-sol", max_tokens=8)
r = m.report()
print(f"  live: calls={r['calls']} prompt={r['prompt_tokens']} completion={r['completion_tokens']} lat={r['latency_s']['total']}")
sys.exit(0 if r["calls"] == 1 and r["prompt_tokens"] > 0 and r["latency_s"]["total"] > 0 else 1)
PY
  then ok "a real gateway call inside a meter captures prompt/completion tokens + latency"
  else bad "FO5: live metering did not capture usage"; fi
fi

sect "FO6: pricing + budget are overridable via env JSON"
if run_py <<'PY'
import sys, json, tempfile, os
sys.path.insert(0, ".")
from agent import finops
pf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False); json.dump({"cheap-sast":[2.0,4.0]}, pf); pf.close()
bf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False); json.dump({"total_tokens": 10}, bf); bf.close()
os.environ["FINOPS_PRICING"]=pf.name; os.environ["FINOPS_BUDGET"]=bf.name
with finops.run_meter("t") as m:
    finops.record("cheap-sast", 1_000_000, 0, 1.0)   # 1M input @ $2 => $2.0
r = m.report()
alerts = finops.check_thresholds(r)
sys.exit(0 if r["cost_estimate_usd"] == 2.0 and any(a["metric"]=="total_tokens" for a in alerts) else 1)
PY
then ok "pricing + budget honor env overrides (FINOPS_PRICING / FINOPS_BUDGET)"
else bad "FO6: overrides not honored"; fi

sect "summary"
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
