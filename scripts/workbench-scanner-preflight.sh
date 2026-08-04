#!/usr/bin/env bash
# Emit capability facts only.  This script never invokes a scanner.
set -euo pipefail

if [ "$#" -ne 2 ] || [ "$1" != "--fixture-profile" ] || [ "$2" != "typescript" ]; then
  echo "usage: $0 --fixture-profile typescript" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
python3 - <<'PY'
import json
from pathlib import Path

from workbench.scanner_contracts import default_engine_statuses

print(
    json.dumps(
        {
            "schema_version": "sentinel-workbench-scanner-preflight/v1",
            "profile": "fixture-typescript",
            "kind": "capability-status-not-scan-result",
            "engines": default_engine_statuses(Path("scanners/image-pins.env")),
        },
        sort_keys=True,
    )
)
PY
