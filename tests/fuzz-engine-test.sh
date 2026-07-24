#!/usr/bin/env bash
# Week-5 fuzzing engine contract. UNIT (no services): the signal detectors flag facts and stay
# quiet on a benign response, and the payload corpus is read-safe (no state-changing DML/commands).
# LIVE (skips unless REQUIRE_AGENT=1): a bounded read-only run against Juice Shop finds real
# signals through the agent-recon identity, within budget.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$REPO_ROOT/rag/.venv/bin/python"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/infra/.env}"
REQUIRE_AGENT="${REQUIRE_AGENT:-0}"

PASS=0; FAIL=0; SKIP=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
skip() { printf '  \033[33mSKIP\033[0m %s\n' "$1"; SKIP=$((SKIP+1)); }
sect() { printf '\n== %s ==\n' "$1"; }

[ -x "$PY" ] || { echo "missing venv at $PY"; exit 2; }
cd "$REPO_ROOT" || { echo "cannot cd to $REPO_ROOT"; exit 2; }
run_py() { "$PY" - "$@"; }

sect "unit: deterministic signal detection"

if run_py <<'PY'
import sys
from agent.fuzz_signals import baseline_of, detect
base = baseline_of(200, '{"data":[]}' * 5, "application/json")
# A benign response identical to the baseline trips nothing (negative control).
quiet = detect(base, 200, '{"data":[]}' * 5, "application/json", "apple")
# A 500 with a DB stack trace and an HTML content-type trips the right signals.
loud = detect(base, 500, "SequelizeDatabaseError: near \"'\": syntax error", "text/html", "')--")
kinds = {s.kind for s in loud}
ok = (not quiet
      and "server_error" in kinds and "stack_trace" in kinds and "ctype_drift" in kinds)
# A reflected payload under a 200 is flagged.
refl = detect(base, 200, "you searched for <script>alert(1)</script>", "text/html", "<script>alert(1)</script>")
ok = ok and any(s.kind == "reflected" for s in refl)
sys.exit(0 if ok else 1)
PY
then ok "detectors: quiet on baseline; flag 500 + stack trace + ctype drift + reflection"
else bad "signal detection wrong"; fi

sect "unit: the payload corpus is read-safe"

if run_py <<'PY'
import sys, re
from agent.fuzz_payloads import CORPUS, classes
# No payload may carry a state-changing SQL verb or a shell command — this is a read-only fuzzer.
banned = re.compile(r"\b(drop|delete|insert|update|truncate|alter)\b|;\s*rm|rm\s+-rf|shutdown", re.I)
offenders = [p.value for p in CORPUS if banned.search(p.value)]
print("  classes:", classes())
sys.exit(0 if (CORPUS and not offenders and len(classes()) >= 5) else 1)
PY
then ok "corpus is non-empty, multi-class, and contains no state-changing verb/command"
else bad "corpus contains an unsafe (state-changing) payload"; fi

sect "unit: only public read-only GET endpoints are fuzz targets"

if run_py <<'PY'
import sys, json, os
from agent.fuzz import _fuzzable_targets, BASELINE
targets = _fuzzable_targets(BASELINE)
data = json.load(open(BASELINE, encoding="utf-8"))
by_pathparam = {(e["path"]): e for e in data["endpoints"]}
# Every selected target must be a public, read-only GET in the baseline.
ok = bool(targets)
for t in targets:
    e = by_pathparam.get(t.path, {})
    ok = ok and e.get("method") == "GET" and e.get("auth_class") == "public" and e.get("state_change") == "read-only"
print("  targets:", [(t.path, t.param) for t in targets])
sys.exit(0 if ok else 1)
PY
then ok "targets are all public read-only GET (no admin/state-changing surface)"
else bad "a non-read-only target was selected"; fi

sect "live: bounded read-only run against the gateway"

[ -f "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; }
if [ -z "${AGENT_RECON_SECRET:-}" ] || [ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 4 "${KONG_PROXY:-https://127.0.0.1:18443}/rest/products/search?q=x" 2>/dev/null)" = "000" ]; then
  m="gateway not reachable / no secret"; [ "$REQUIRE_AGENT" = "1" ] && bad "$m" || skip "$m"
else
  if run_py <<'PY'
import sys
from agent.fuzz import run, MAX_REQUESTS_PER_TARGET
r = run(use_llm=False)
print(f"  requests={r.requests_sent} findings={len(r.findings)} signals={r.signal_counts}")
# Bounded (never exceeds budget * targets, plus one baseline each) and finds real signal on the
# deliberately-vulnerable search endpoint.
budget_ok = r.requests_sent <= len(r.targets) * (MAX_REQUESTS_PER_TARGET + 1)
found_real = r.signal_counts.get("server_error", 0) >= 1 or r.signal_counts.get("stack_trace", 0) >= 1
sys.exit(0 if (budget_ok and found_real and r.findings) else 1)
PY
  then ok "bounded run finds a real 5xx/stack-trace signal read-only"
  else bad "live fuzz run failed"; fi
fi

printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ]
