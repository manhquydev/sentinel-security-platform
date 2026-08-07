#!/usr/bin/env bash
# Sync allowlisted Markdown from docs/ into Starlight + public raw/llms surfaces.
# Canonical implementation: website-sync-docs.py
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "${ROOT}/scripts/website-sync-docs.py"
