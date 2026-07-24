#!/usr/bin/env bash
# Week-4 Recon agent contract. Two layers, matching the repo's other suites.
#
# SCHEMA (no services): the Attack Surface Map is a strict contract — a hallucinated field or an
# out-of-vocabulary enum is REJECTED, and the code-computed aggregates must match the findings
# (so an LLM cannot fabricate a count). PROVENANCE (skips if the gateway is down, unless
# REQUIRE_AGENT=1): the LLM client refuses to send an unlabelled message (fail-closed in code),
# and a correctly-labelled call — operator instructions + target-derived data — round-trips
# through the gateway's provenance boundary.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$REPO_ROOT/rag/.venv/bin/python"   # shared venv (pydantic + requests + rag)
ENV_FILE="${ENV_FILE:-$REPO_ROOT/infra/.env}"
REQUIRE_AGENT="${REQUIRE_AGENT:-0}"

PASS=0; FAIL=0; SKIP=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
skip() { printf '  \033[33mSKIP\033[0m %s\n' "$1"; SKIP=$((SKIP+1)); }
sect() { printf '\n== %s ==\n' "$1"; }

[ -x "$PY" ] || { echo "missing venv at $PY"; exit 2; }
cd "$REPO_ROOT"
run_py() { "$PY" - "$@"; }

# ---------------------------------------------------------------------------
sect "schema: the Attack Surface Map is a strict contract (no services)"

if run_py <<'PY'
import sys
from agent.schema import AttackSurfaceMap
good = {
  "target": "juice-shop", "generated_at": "2026-07-24T00:00:00Z", "agent_version": "0.1",
  "endpoints": [{"path": "/rest/products/search", "method": "GET", "auth_class": "public",
                 "state_change": "read-only",
                 "findings": [{"finding_id": "1", "title": "XSS", "severity": "High",
                               "scanner": "DAST", "cwe": 79, "rag_refs": ["owasp:XSS"]}]}],
  "provenance": {"attack_surface_baseline": "juice-shop-df1b6bbd8bce", "model": "sast-sol"},
}
m = AttackSurfaceMap.model_validate(good).recompute_aggregates()
sys.exit(0 if (m.severity_counts == {"High": 1} and m.cwe_summary == {"79": 1}
               and not m.consistency_errors()) else 1)
PY
then ok "well-formed map validates; aggregates computed by code and consistent"
else bad "valid map failed"; fi

if run_py <<'PY'
import sys
from pydantic import ValidationError
from agent.schema import AttackSurfaceMap
bad = {"target": "x", "generated_at": "t", "agent_version": "0.1", "endpoints": [],
       "provenance": {"attack_surface_baseline": "b", "model": "m"},
       "hallucinated_field": "boom"}
try:
    AttackSurfaceMap.model_validate(bad); sys.exit(1)          # extra=forbid must reject
except ValidationError:
    sys.exit(0)
PY
then ok "a hallucinated extra field is rejected"; else bad "extra field not rejected"; fi

if run_py <<'PY'
import sys
from pydantic import ValidationError
from agent.schema import EndpointSurface
try:
    EndpointSurface.model_validate({"path": "/x", "auth_class": "root", "state_change": "read-only"})
    sys.exit(1)   # 'root' is not in the auth taxonomy
except ValidationError:
    sys.exit(0)
PY
then ok "an out-of-vocabulary auth_class is rejected"; else bad "bad enum not rejected"; fi

if run_py <<'PY'
import sys
from agent.schema import AttackSurfaceMap
m = AttackSurfaceMap.model_validate({
  "target": "x", "generated_at": "t", "agent_version": "0.1",
  "endpoints": [{"path": "/x", "auth_class": "public", "state_change": "read-only",
                 "findings": [{"finding_id": "1", "title": "t", "severity": "Low", "scanner": "SAST"}]}],
  "severity_counts": {"Low": 5},  # deliberately wrong (real is 1)
  "provenance": {"attack_surface_baseline": "b", "model": "m"}})
sys.exit(0 if m.consistency_errors() else 1)  # must FLAG the fabricated count
PY
then ok "a fabricated aggregate count is flagged by the consistency check"; else bad "consistency check missed a bad count"; fi

# ---------------------------------------------------------------------------
sect "provenance: the LLM boundary"

# Client-side fail-closed: an unlabelled message cannot be sent.
if run_py <<'PY'
import sys
from agent.llm import Msg, _spans
try:
    _spans([Msg("user", "hi", trust="banana")]); sys.exit(1)
except ValueError:
    sys.exit(0)
PY
then ok "client refuses a message with no valid trust label (fail-closed)"; else bad "client sent an unlabelled message"; fi

[ -f "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; }
if [ -z "${LITELLM_MASTER_KEY:-}" ] || [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://127.0.0.1:4000/health 2>/dev/null)" = "000" ]; then
  m="gateway not reachable / no key"
  if [ "$REQUIRE_AGENT" = "1" ]; then bad "$m (REQUIRE_AGENT=1)"; else skip "$m"; fi
else
  if run_py <<'PY'
import sys
from agent.llm import chat, Msg, operator, target_derived
out = chat([
    Msg("system", "You are a security analyst. Answer in one word.", operator()),
    Msg("user", "A scanner reported reflected XSS. Reply with the single word: acknowledged",
        target_derived(source="nuclei-sanitized", target="juice-shop@sha256:e681")),
], model="sast-sol", max_tokens=8)
sys.exit(0 if out and out.strip() else 1)
PY
  then ok "provenance-labelled call (operator + target-derived) round-trips the gateway"
  else bad "provenance-labelled call failed"; fi
fi

# ---------------------------------------------------------------------------
printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ]
