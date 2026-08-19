#!/usr/bin/env bash
# Bind lock + HTTP contract for the Week-5 loopback facade. No Kong, no infra/.env.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="$ROOT/infra/week5-demo/docker-compose.yml"
PY="${PYTHON:-python3}"
ok() { printf 'ok  %s\n' "$1"; }
bad() { printf 'BAD %s\n' "$1" >&2; exit 1; }

# Host publish must be 127.0.0.1. No PyYAML (grader slim venv).
if "$PY" - "$COMPOSE" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
quoted = re.findall(r'^\s*-\s*"([^"]+)"\s*$', text, re.M)
if not quoted:
    sys.stderr.write("no quoted ports\n")
    sys.exit(1)
bad = [p for p in quoted if not p.startswith("127.0.0.1:")]
bare = re.findall(r'^\s*-\s*"?(\d+:\d+)"?\s*$', text, re.M)
if bad or bare:
    sys.stderr.write("\n".join([*bad, *bare]) + "\n")
    sys.exit(1)
PY
then ok "compose publishes 127.0.0.1 only"
else bad "a published port is not bound to 127.0.0.1"
fi

export PYTHONPATH="$ROOT"
"$PY" -m pytest "$ROOT/tests/test_week5_demo_facade.py" -q
ok "facade unit tests"

ok "week5-demo-facade-test done"
