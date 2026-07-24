#!/usr/bin/env bash
# D1 model-egress contract (Week 6): agent/*.py must reach a model ONLY through agent/llm.py's
# provenance-labelled door. Provenance + redaction are enforced server-side at the LiteLLM
# gateway (infra/litellm/guardrails/sentinel_guardrail.py), so the real invariant this test
# locks down is narrower and code-level: nothing under agent/ imports a direct LLM SDK,
# instantiates a LangChain chat-model client, or references a raw router/provider base URL
# outside llm.py — and no agent code ever flips LangSmith tracing on (D12 air-gap; langgraph
# pulls langchain-core, which pulls langsmith transitively).
#
# Pure static grep. No venv, no services — the whole point is this holds even when nothing is
# running. Distinct from tests/import-contract-test.sh, which guards scanners/import-report.sh
# (an unrelated DefectDojo-import safety contract), not model egress.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT_DIR="$REPO_ROOT/agent"

PASS=0; FAIL=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
sect() { printf '\n== %s ==\n' "$1"; }

[ -d "$AGENT_DIR" ] || { echo "missing $AGENT_DIR" >&2; exit 2; }
cd "$REPO_ROOT" || exit 2

mapfile -t OTHER_FILES < <(find "$AGENT_DIR" -maxdepth 1 -name '*.py' ! -name 'llm.py')

# ---------------------------------------------------------------------------
sect "no direct LLM SDK import outside agent/llm.py"

DIRECT_SDK_PATTERN='^[[:space:]]*(import|from)[[:space:]]+(openai|anthropic|cohere|litellm|langchain_openai|langchain_anthropic|langchain_cohere)\b'
offenders=""
for f in "${OTHER_FILES[@]}"; do
  hit="$(grep -nE "$DIRECT_SDK_PATTERN" "$f" 2>/dev/null || true)"
  [ -n "$hit" ] && offenders+="$f: $hit"$'\n'
done
if [ -z "$offenders" ]; then
  ok "no agent/*.py (besides llm.py) imports a direct LLM SDK"
else
  bad "direct LLM SDK import found outside llm.py"; printf '%s' "$offenders" >&2
fi

sect "negative control: the SDK-import pattern actually fires on a planted import"
tmpf="$(mktemp /tmp/egress-negctl-XXXXXX.py)"
trap 'rm -f "$tmpf"' EXIT
printf 'import openai\nfrom litellm import completion\n' > "$tmpf"
if grep -cE "$DIRECT_SDK_PATTERN" "$tmpf" | grep -qE '^[2-9]|^[0-9]{2,}'; then
  ok "pattern flags both planted direct SDK imports (detector is not vacuous)"
else
  bad "pattern failed to flag a planted direct SDK import"
fi
rm -f "$tmpf"; trap - EXIT

# ---------------------------------------------------------------------------
sect "no LangChain chat-model CLIENT is instantiated (orchestration imports are fine)"

# langgraph.graph.StateGraph / langgraph.checkpoint.sqlite.SqliteSaver / langgraph.types are
# ORCHESTRATION, not a model door, and are allowed everywhere. What is never allowed is
# instantiating a chat-model client that could itself reach a provider.
CHATMODEL_PATTERN='(ChatOpenAI|ChatAnthropic|ChatCohere|ChatLiteLLM|init_chat_model)[[:space:]]*\('
offenders=""
for f in "${OTHER_FILES[@]}" "$AGENT_DIR/llm.py"; do
  hit="$(grep -nE "$CHATMODEL_PATTERN" "$f" 2>/dev/null || true)"
  [ -n "$hit" ] && offenders+="$f: $hit"$'\n'
done
if [ -z "$offenders" ]; then
  ok "no agent/*.py instantiates a LangChain chat-model client"
else
  bad "a LangChain chat-model client is instantiated"; printf '%s' "$offenders" >&2
fi

sect "negative control: the chat-model pattern actually fires on a planted instantiation"
tmpf="$(mktemp /tmp/egress-negctl-XXXXXX.py)"
trap 'rm -f "$tmpf"' EXIT
printf 'llm = ChatOpenAI(model="gpt-4")\n' > "$tmpf"
if grep -qE "$CHATMODEL_PATTERN" "$tmpf"; then
  ok "pattern flags a planted ChatOpenAI(...) instantiation"
else
  bad "pattern failed to flag a planted chat-model instantiation"
fi
rm -f "$tmpf"; trap - EXIT

# ---------------------------------------------------------------------------
sect "no raw model/router base URL referenced outside agent/llm.py"

# llm.py legitimately reads LITELLM_BASE (the gateway's own base — the labelled door itself).
# Nothing else may reference the router's base env var or a bare provider host; that would be
# an egress path that bypasses the gateway's provenance/redaction enforcement entirely.
ROUTER_PATTERN='ROUTER_API_BASE|api\.openai\.com|api\.anthropic\.com|api\.cohere\.ai|generativelanguage\.googleapis\.com'
offenders=""
for f in "${OTHER_FILES[@]}"; do
  hit="$(grep -nE "$ROUTER_PATTERN" "$f" 2>/dev/null || true)"
  [ -n "$hit" ] && offenders+="$f: $hit"$'\n'
done
if [ -z "$offenders" ]; then
  ok "no agent/*.py (besides llm.py) references a raw router/provider base URL"
else
  bad "a raw router/provider base URL is referenced outside llm.py"; printf '%s' "$offenders" >&2
fi

sect "negative control: the router-base pattern actually fires on a planted reference"
tmpf="$(mktemp /tmp/egress-negctl-XXXXXX.py)"
trap 'rm -f "$tmpf"' EXIT
printf 'BASE = os.environ["ROUTER_API_BASE"]\n' > "$tmpf"
if grep -qE "$ROUTER_PATTERN" "$tmpf"; then
  ok "pattern flags a planted ROUTER_API_BASE reference"
else
  bad "pattern failed to flag a planted router-base reference"
fi
rm -f "$tmpf"; trap - EXIT

# ---------------------------------------------------------------------------
sect "LangSmith stays hard-off (D12 air-gap)"

offenders="$(grep -rnE "LANGCHAIN_TRACING_V2['\"]?\]?[[:space:]]*[:=][[:space:]]*['\"]?(True|true)" "$AGENT_DIR" --include='*.py' 2>/dev/null || true)"
if [ -z "$offenders" ]; then
  ok "no agent/*.py sets LANGCHAIN_TRACING_V2 truthy"
else
  bad "agent code sets LANGCHAIN_TRACING_V2 truthy"; printf '%s\n' "$offenders" >&2
fi

sect "negative control: the LangSmith-enable pattern actually fires on a planted assignment"
tmpf="$(mktemp /tmp/egress-negctl-XXXXXX.py)"
trap 'rm -f "$tmpf"' EXIT
printf 'os.environ["LANGCHAIN_TRACING_V2"] = "true"\n' > "$tmpf"
if grep -qE "LANGCHAIN_TRACING_V2['\"]?\]?[[:space:]]*[:=][[:space:]]*['\"]?(True|true)" "$tmpf"; then
  ok "pattern flags a planted LANGCHAIN_TRACING_V2=true assignment"
else
  bad "pattern failed to flag a planted LangSmith-enable assignment"
fi
rm -f "$tmpf"; trap - EXIT

# The *running* environment is what actually determines whether langchain-core's transitive
# langsmith client activates at import time — a clean codebase is not enough on its own.
if [ "${LANGCHAIN_TRACING_V2:-false}" = "true" ] || [ "${LANGCHAIN_TRACING_V2:-false}" = "True" ]; then
  bad "LANGCHAIN_TRACING_V2 is truthy in the current environment"
else
  ok "LANGCHAIN_TRACING_V2 is not truthy in the current environment"
fi
if [ -n "${LANGCHAIN_API_KEY:-}" ]; then
  bad "LANGCHAIN_API_KEY is set in the current environment (LangSmith must stay air-gapped)"
else
  ok "LANGCHAIN_API_KEY is not set in the current environment"
fi

# `langsmith==0.10.10` (pulled transitively by langchain-core; see requirements.lock) honors its
# OWN env-var family — LANGSMITH_TRACING / LANGSMITH_API_KEY / LANGSMITH_ENDPOINT — in addition
# to the legacy LANGCHAIN_* names checked above (MF3). Checking only the legacy pair leaves a
# real air-gap bypass: LANGSMITH_TRACING=true would activate SaaS trace egress even with
# LANGCHAIN_TRACING_V2 unset.
if [ "${LANGSMITH_TRACING:-false}" = "true" ] || [ "${LANGSMITH_TRACING:-false}" = "True" ]; then
  bad "LANGSMITH_TRACING is truthy in the current environment"
else
  ok "LANGSMITH_TRACING is not truthy in the current environment"
fi
if [ -n "${LANGSMITH_API_KEY:-}" ]; then
  bad "LANGSMITH_API_KEY is set in the current environment (LangSmith must stay air-gapped)"
else
  ok "LANGSMITH_API_KEY is not set in the current environment"
fi

# ---------------------------------------------------------------------------
printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
