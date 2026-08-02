#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FILE="$REPO_ROOT/docs/operations/sentinel-live-acceptance-runbook.md"
PASS=0
FAIL=0

ok() { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1" >&2; FAIL=$((FAIL + 1)); }

require() {
  local pattern="$1" description="$2"
  if grep -Eqi -- "$pattern" "$FILE"; then
    ok "$description"
  else
    bad "$description"
  fi
}

forbid() {
  local pattern="$1" description="$2"
  if grep -Eqi -- "$pattern" "$FILE"; then
    bad "$description"
  else
    ok "$description"
  fi
}

[ -f "$FILE" ] && ok 'runbook exists' || { bad 'runbook exists'; exit 1; }

require '^# Sentinel Live Acceptance Runbook$' 'runbook has the expected title'
require 'Historical R5 is prohibited|No R5 reuse' 'runbook forbids R5 reuse'
require 'Trusted approval-key source' 'runbook names approval-key authority'
require 'Executor adapter principal' 'runbook names executor-principal authority'
require 'Authoritative Kong audit source' 'runbook names audit-source authority'
require 'SENTINEL_CHARTER_APPROVAL_FILE' 'runbook names approval file variable'
require 'SENTINEL_CHARTER_PUBLIC_KEY' 'runbook names public key variable'
require 'SENTINEL_CHARTER_EXECUTOR_ADAPTER' 'runbook names executor adapter variable'
require 'SENTINEL_NUCLEI_IMAGE_DIGEST|SENTINEL_NUCLEI_BIN' 'runbook requires an admitted scanner selector'
require 'A local `receipt_digest` is adapter metadata, not authoritative Kong evidence' 'runbook distinguishes local digest from authoritative audit'
require 'Do not retry' 'runbook forbids retry after unknown outcome'
require 'recover-audit ID' 'runbook names bounded audit recovery command'
require 'never retries or dispatches' 'runbook keeps audit recovery non-dispatching'
require 'not a receipt, response-guard, normal final' 'runbook keeps audit recovery out of normal receipt and guard evidence'
require 'report, or evaluation proof' 'runbook keeps audit recovery out of normal report and evaluation evidence'
require 'does not make the run a live-acceptance success' 'runbook keeps recovery out of live acceptance'
require 'factual readiness report' 'runbook requires truthful blocked reporting'

forbid 'BEGIN [A-Z ]*PRIVATE KEY' 'runbook contains no private key material'
forbid 'Bearer [A-Za-z0-9._~-]{12,}' 'runbook contains no bearer token'
forbid 'Authorization:' 'runbook contains no authorization header example'
forbid 'password=' 'runbook contains no password assignment'
forbid 'api[_-]?key=' 'runbook contains no API key assignment'

printf '\n== summary ==\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
