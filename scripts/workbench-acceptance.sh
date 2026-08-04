#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHONPATH="$ROOT" python3 -m pytest -q "$ROOT/tests/test_workbench_"*.py
bash "$ROOT/tests/workbench-b3-gateway-isolation-test.sh"
bash "$ROOT/scripts/workbench-artifact-guard.sh" "$ROOT/evaluation/workbench"
echo "Workbench fixture acceptance passed. CMC dispatch remains disabled without a passed value gate."
