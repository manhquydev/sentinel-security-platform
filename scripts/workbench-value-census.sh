#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  printf 'usage: %s <census.json> <cmc-value-gate.json>\n' "$0" >&2
  exit 64
fi

source_path=$1
output_path=$2
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python_bin=${PYTHON_BIN:-"$repo_root/rag/.venv/bin/python"}

if [ ! -x "$python_bin" ]; then
  python_bin=python3
fi

"$python_bin" - "$source_path" "$output_path" <<'PY'
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

from workbench.value_gate import evaluate_cmc_value_gate

source = Path(sys.argv[1])
output = Path(sys.argv[2])
if not source.is_file():
    raise SystemExit(f"census input does not exist: {source}")
if output.exists():
    raise SystemExit(f"refusing to replace existing terminal record: {output}")

document = json.loads(source.read_text(encoding="utf-8"))
record = evaluate_cmc_value_gate(document)
payload = {
    "schema_version": "sentinel-workbench-cmc-value-gate/v1",
    "status": record.status,
    "numerator": record.numerator,
    "denominator": record.denominator,
    "threshold": record.threshold,
    "timing_summary": record.timing_summary,
    "reason": record.reason,
    "digest": record.digest,
}
output.parent.mkdir(parents=True, exist_ok=True)
fd, temporary = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, output)
except BaseException:
    Path(temporary).unlink(missing_ok=True)
    raise
PY
