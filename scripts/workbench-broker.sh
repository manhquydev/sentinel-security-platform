#!/usr/bin/env bash
# Host-only contract check.  Network serving is introduced with Phase 6.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec python3 -m workbench.host_broker "$@"
