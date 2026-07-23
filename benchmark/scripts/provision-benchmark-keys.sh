#!/usr/bin/env bash
# Provision the per-tier, per-run virtual keys the baseline needs: one per
# (model tier x run number), each scoped to its own alias.
#
# The model dimension belongs in the key name because per-key attribution is the
# only per-arm accounting left once LiteLLM's pricing-based spend goes inert for the
# router's models. Two tiers at the same run number sharing one credential
# reproduces the run-1 attribution bug across both arms at once, and nothing
# downstream can tell the arms apart afterwards.
#
# Emitting every name from one loop is the point: hand-invoking
# generate-virtual-key.sh once per combination is where a tier collision gets introduced.
#
# Requires a running LiteLLM proxy and LITELLM_MASTER_KEY. Prints no key values.
#
# Usage: bash benchmark/scripts/provision-benchmark-keys.sh [max_budget_usd]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${LITELLM_MASTER_KEY:?LITELLM_MASTER_KEY must be set in the environment}"

# Budget is inert for router models (LiteLLM has no pricing for them, and the router
# reports cost: null) — see generate-virtual-key.sh.
max_budget="${1:-0}"

for tier in sol terra gpt55; do
  alias="sast-$tier"
  for run in 1 2 3; do
    # V0_SOL_RUN1_VIRTUAL_KEY etc. — the name run-full-benchmark.py derives
    # from --model and --run.
    name="v0_$(echo "$tier" | tr '-' '_')_run${run}"
    echo "== $name -> $alias =="
    bash "$SCRIPT_DIR/generate-virtual-key.sh" "$name" "$max_budget" "$alias"
  done
done

echo
echo "Keys provisioned. Move each benchmark/.<name>.key.tmp value into benchmark/.env"
echo "as its uppercase V0_..._VIRTUAL_KEY, then delete the tmp files."
echo "Verify each one authenticates before the Phase 2 gate: a run that fails on a missing"
echo "credential is indistinguishable from a tier that genuinely failed the gate."
