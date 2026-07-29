#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$REPO_ROOT/rag/.venv/bin/python"

if [ ! -x "$PY" ]; then
  printf '%s\n' "missing RAG virtualenv Python at $PY; create it with: python3 -m venv rag/.venv && rag/.venv/bin/pip install -r rag/requirements.txt" >&2
  exit 2
fi

cd "$REPO_ROOT"
exec "$PY" tests/test_charter_rag.py
