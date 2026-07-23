#!/usr/bin/env bash
# Verify environment is ready before running the Step-0 spike or any scan.
# Prints only presence/absence of secrets, never their values.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BENCHMARK_DIR="$REPO_ROOT/benchmark"
fail=0

check() {
  local desc="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "[ok]   $desc"
  else
    echo "[FAIL] $desc"
    fail=1
  fi
}

check "docker available" command -v docker
check "git available" command -v git
check "python3 available" command -v python3

check "ROUTER_API_KEY set" test -n "${ROUTER_API_KEY:-}"
check "ROUTER_API_BASE set" test -n "${ROUTER_API_BASE:-}"
check "LITELLM_MASTER_KEY set" test -n "${LITELLM_MASTER_KEY:-}"

# DEEPSEEK_API_KEY is only needed to re-score or reproduce the frozen V0 comparison
# arm. New runs go to the router, so its absence is a note rather than a failure.
if [ -z "${DEEPSEEK_API_KEY:-}" ]; then
  echo "[note] DEEPSEEK_API_KEY unset — fine for router runs; required only to reproduce the frozen DeepSeek arm"
else
  echo "[ok]   DEEPSEEK_API_KEY set (frozen comparison arm reproducible)"
fi

check ".gitignore has runs/" grep -qxF "runs/" "$REPO_ROOT/.gitignore"
check ".gitignore has benchmark db patterns" grep -q 'benchmark/\*\*/\*\.db' "$REPO_ROOT/.gitignore"
check ".gitignore has benchmark/results/" grep -qxF "benchmark/results/" "$REPO_ROOT/.gitignore"
check "litellm-config.yaml disables message/body logging" grep -q "turn_off_message_logging: true" "$BENCHMARK_DIR/litellm-config.yaml"

# The vendored Metis is patched in this tree (usage-file uniqueness). A re-provision
# or a manual `git checkout` inside benchmark/tools/arm-metis silently reverts it and
# the next run loses usage files without any symptom until the token totals are read
# back. Assert both the pin and the patch, so that reversion fails here instead.
METIS_DIR="$BENCHMARK_DIR/tools/arm-metis"
MANIFEST="$BENCHMARK_DIR/tools/manifest.json"

check "vendored Metis present" test -d "$METIS_DIR/.git"
check "tools manifest present" test -f "$MANIFEST"

check "Metis at the pinned SHA" \
  bash -c '[ "$(git -C "$1" rev-parse HEAD)" = "$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[\"metis\"][\"sha\"])" "$2")" ]' _ "$METIS_DIR" "$MANIFEST"
check "Metis usage-uniqueness patch present" \
  grep -q "VINSOC PATCH (usage-file uniqueness)" "$METIS_DIR/src/metis/usage/runtime.py"

if [ "$fail" -eq 1 ]; then
  echo
  echo "Preflight FAILED. Resolve the [FAIL] items above before running the spike."
  exit 1
fi
echo
echo "Preflight OK."
