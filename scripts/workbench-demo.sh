#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHONPATH="$ROOT" python3 -m pytest -q \
  "$ROOT/tests/test_workbench_web.py" \
  "$ROOT/tests/test_workbench_web_session.py" \
  "$ROOT/tests/test_workbench_reporting.py"
echo "Fixture demo evidence is valid; CMC remains disabled unless cmc_value_gate is passed."
