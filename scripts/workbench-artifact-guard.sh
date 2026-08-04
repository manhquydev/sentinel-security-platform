#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <private-artifact-root-or-file> [...]" >&2
  exit 2
fi

for target in "$@"; do
  [[ -e "$target" ]] || { echo "artifact guard target missing: $target" >&2; exit 2; }
  if rg -n --hidden --glob '!*.sqlite*' \
      -e 'WORKBENCH_RAW_(SOURCE|SECRET|PROMPT|PROVIDER_BODY)_CANARY' \
      -e 'sk-[A-Za-z0-9_-]{10,}' \
      -e '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' \
      "$target"; then
    echo "artifact guard found raw source, secret, prompt, provider material, or PII" >&2
    exit 1
  fi
done
