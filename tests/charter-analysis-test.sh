#!/usr/bin/env bash
# Charter analysis contract: entirely offline. The required live stage is intentionally not
# invoked here; `agent.llm.checked_chat` makes a missing/404 liveliness check fatal when called.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/rag/.venv/bin/python"
[ -x "$PY" ] || { echo "missing venv at $PY" >&2; exit 2; }
cd "$ROOT"
PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" "$PY" tests/test_charter_contracts.py -v
PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" "$PY" tests/test_charter_trivy.py -v
