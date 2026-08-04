#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test ! -f "$ROOT/infra/workbench/b3-gateway.env"
test ! -f "$ROOT/infra/workbench/b3-dispatcher.env"
PYTHONPATH="$ROOT" python3 -m pytest -q "$ROOT/tests/test_workbench_"*.py
echo "Clean local fixture verification passed without infra/.env or cloud credentials."
