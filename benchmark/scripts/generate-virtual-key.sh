#!/usr/bin/env bash
# Generate a per-tool virtual key scoped to specific model aliases, via LiteLLM's
# /key/generate admin endpoint. Never hand the master key to a tool.
#
# max_budget is still sent, but it is only enforced for models LiteLLM can price.
# LiteLLM has no pricing entry for the router's models, so their spend is recorded as 0
# and the cap never trips (the router itself returns cost: null). Treat the budget as live
# only for aliases backed by a priced provider (e.g. cheap-sast/DeepSeek); for router
# aliases it is inert and per-key attribution, not the cap, is what limits blast radius.
#
# Usage: generate-virtual-key.sh <name> <max_budget_usd> <model_alias> [model_alias ...]
# Example: generate-virtual-key.sh saist 2.00 cheap-sast
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "Usage: $0 <name> <max_budget_usd> <model_alias> [model_alias ...]" >&2
  exit 1
fi

: "${LITELLM_MASTER_KEY:?LITELLM_MASTER_KEY must be set in the environment}"
: "${LITELLM_BASE_URL:=http://localhost:4000}"

name="$1"
max_budget="$2"
shift 2
models_json="$(printf '%s\n' "$@" | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))')"

# A max_budget of 0 is NOT "no cap" — LiteLLM evaluates spend >= budget, so 0 >= 0 is
# already exceeded and every request 429s before it reaches a provider. Omit the field
# entirely instead, which is also the honest encoding: for models LiteLLM cannot price
# there is no cap to express. Pass 0 or "none" to mean uncapped.
payload="$(python3 - "$name" "$models_json" "$max_budget" <<'PY'
import json, sys
name, models_json, max_budget = sys.argv[1:4]
body = {"key_alias": name, "models": json.loads(models_json)}
try:
    budget = float(max_budget)
except ValueError:
    budget = 0.0
if budget > 0:
    body["max_budget"] = budget
print(json.dumps(body))
PY
)"

response="$(curl -sf -X POST "$LITELLM_BASE_URL/key/generate" \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d "$payload")"

key="$(python3 -c "import json,sys; print(json.load(sys.stdin)['key'])" <<<"$response")"

if [ "${max_budget%.*}" -gt 0 ] 2>/dev/null; then
  echo "Generated virtual key for '$name' (models: $*, max_budget: \$$max_budget)."
else
  echo "Generated virtual key for '$name' (models: $*, no budget cap)."
fi
echo "[note] max_budget is enforced only for models LiteLLM can price; it is inert for router models."
echo "Store it as ${name^^}_VIRTUAL_KEY in benchmark/.env — value is NOT printed here."
printf '%s\n' "$key" > "$(dirname "${BASH_SOURCE[0]}")/../.${name}.key.tmp"
echo "Wrote to benchmark/.${name}.key.tmp (gitignored) — move the value into .env then delete this file."
