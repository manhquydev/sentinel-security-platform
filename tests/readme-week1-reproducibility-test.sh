#!/usr/bin/env bash
# Offline contract for the named Week-1 fresh-clone scan-to-redaction examples.
# It deliberately inspects only those blocks: historical/provisioned commands may
# legitimately use DefectDojo credentials, imports, verification, or TARGET_URL.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0
FAIL=0

ok() { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); }

section() {
  local file="$1" heading="$2"
  awk -v heading="$heading" '
    $0 == "## " heading { found = 1; next }
    found && /^## / { exit }
    found { print }
    END { if (!found) exit 1 }
  ' "$file"
}

require() {
  local block="$1" pattern="$2" description="$3"
  if grep -Eq -- "$pattern" <<<"$block"; then
    ok "$description"
  else
    bad "$description"
  fi
}

forbid() {
  local block="$1" pattern="$2" description="$3"
  if grep -Eiq -- "$pattern" <<<"$block"; then
    bad "$description"
  else
    ok "$description"
  fi
}

check_fresh_clone_block() {
  local file="$1" heading="$2" block
  if ! block="$(section "$file" "$heading")"; then
    bad "$file has the named '$heading' block"
    return
  fi
  ok "$file has the named '$heading' block"

  require "$block" 'command -v jq' "$file preflights jq"
  require "$block" 'set -euo pipefail' "$file stops on scan or redaction failure"
  require "$block" '(source|\.) scanners/image-pins\.env' "$file sources committed image pins"
  require "$block" 'IMAGE="\$JUICE_SHOP_IMAGE"' "$file selects the pinned Juice Shop image"
  require "$block" 'TRIVY_SCANNERS="secret,misconfig"' "$file selects the offline Trivy scanners"
  require "$block" 'mktemp -d' "$file creates a private temporary workspace"
  require "$block" 'trap .*rm -rf' "$file removes the private raw workspace on exit"
  require "$block" 'sanitized_report=.*mktemp' "$file keeps the sanitized report outside the raw workspace"
  require "$block" 'run-trivy\.sh' "$file runs Trivy"
  require "$block" 'redact-report\.sh trivy' "$file redacts the Trivy report"

  local scan_line redact_line
  scan_line="$(grep -nE 'run-trivy\.sh' <<<"$block" | head -n1 | cut -d: -f1 || true)"
  redact_line="$(grep -nE 'redact-report\.sh trivy' <<<"$block" | head -n1 | cut -d: -f1 || true)"
  if [ -n "$scan_line" ] && [ -n "$redact_line" ] && [ "$scan_line" -lt "$redact_line" ]; then
    ok "$file scans before redaction"
  else
    bad "$file scans before redaction"
  fi

  local cleanup_line
  cleanup_line="$(grep -nE '^[[:space:]]*rm -rf "\$workspace"$' <<<"$block" | head -n1 | cut -d: -f1 || true)"
  if [ -n "$cleanup_line" ] && [ -n "$redact_line" ] && [ "$redact_line" -lt "$cleanup_line" ]; then
    ok "$file removes the raw workspace immediately after redaction"
  else
    bad "$file removes the raw workspace immediately after redaction"
  fi

  forbid "$block" '(import-report|scan-and-import)' "$file has no import command in the no-secret block"
  forbid "$block" 'verify-lake' "$file has no verification command in the no-secret block"
  local non_pin_sources
  non_pin_sources="$(grep -Ev '^[[:space:]]*(source|\.)[[:space:]]+scanners/image-pins[.]env[[:space:]]*$' <<<"$block")"
  forbid "$non_pin_sources" '(source|\.) +[^[:space:]]*[.]env([^[:alnum:]_.-]|$)' "$file has no private environment source in the no-secret block"
  forbid "$block" 'TARGET_URL|target[[:space:]-]*url' "$file has no target-URL command in the no-secret block"
}

check_fresh_clone_block "$REPO_ROOT/README.md" 'Fresh-clone scan-to-redaction (no secrets)'
check_fresh_clone_block "$REPO_ROOT/scanners/README.md" 'Fresh-clone Trivy image scan (no secrets)'

for file in "$REPO_ROOT/README.md" "$REPO_ROOT/scanners/README.md"; do
  text="$(<"$file")"
  require "$text" 'Docker (daemon|socket)' "$file names Docker daemon/socket access"
  require "$text" 'jq' "$file names jq as a prerequisite"
  require "$text" 'public.*pinned images?|pinned images?.*public' "$file names public pinned-image availability"
  require "$text" 'no .*DefectDojo.*credentials|no .*credentials.*DefectDojo' "$file states the no-secret boundary"
done

root_text="$(<"$REPO_ROOT/README.md")"
require "$root_text" 'Provisioned (import|DefectDojo|lake)' 'root README labels import/verification as provisioned'
require "$root_text" 'does not reproduce.*historical baseline|does not replay.*historical baseline' 'root README disclaims exact historical-baseline replay'

for file in "$REPO_ROOT/infra/defectdojo/README.md" \
            "$REPO_ROOT/infra/defectdojo/docker-compose.yml" \
            "$REPO_ROOT/infra/defectdojo-db/docker-compose.yml"; do
  text="$(<"$file")"
  require "$text" 'docker compose --env-file infra/[.]env -f infra/defectdojo' "$file uses the repository-root DefectDojo env-file path"
  forbid "$text" 'docker compose --env-file [.]\./[.]env -f infra/defectdojo' "$file has no parent-directory DefectDojo env-file path"
done

printf '\n== summary ==\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
