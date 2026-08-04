#!/usr/bin/env bash
# Offline source/config contract for first-initializing the RAG store from a clone.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA="$REPO_ROOT/infra/rag-store/schema.sql"
COMPOSE="$REPO_ROOT/infra/rag-store/docker-compose.yml"
TEMP_ENV="$(mktemp)"
PASS=0
FAIL=0

cleanup() {
  rm -f "$TEMP_ENV"
}
trap cleanup EXIT

ok() { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); }

require_file() {
  local path="$1" description="$2"
  if [ -f "$path" ]; then
    ok "$description"
  else
    bad "$description"
  fi
}

require_text() {
  local text="$1" pattern="$2" description="$3"
  if grep -Eq -- "$pattern" <<<"$text"; then
    ok "$description"
  else
    bad "$description"
  fi
}

require_file "$SCHEMA" "schema source exists"

if git -C "$REPO_ROOT" check-ignore -q -- infra/rag-store/schema.sql; then
  bad "schema source is not ignored"
else
  ok "schema source is not ignored"
fi

if git -C "$REPO_ROOT" add --dry-run -- infra/rag-store/schema.sql; then
  ok "schema source is addable without force"
else
  bad "schema source is addable without force"
fi

printf 'RAG_DB_USER=fresh_clone_user\nRAG_DB_PASSWORD=fresh_clone_password\nRAG_DB_PORT=55439\n' >"$TEMP_ENV"
if ! COMPOSE_CONFIG="$(docker compose --env-file "$TEMP_ENV" -f "$COMPOSE" config 2>&1)"; then
  printf '%s\n' "$COMPOSE_CONFIG" >&2
  bad "compose configuration renders with non-secret temporary variables"
  COMPOSE_CONFIG=""
else
  ok "compose configuration renders with non-secret temporary variables"
fi

require_text "$COMPOSE_CONFIG" "source: $SCHEMA" "compose uses the source-relative schema bind mount"
require_text "$COMPOSE_CONFIG" 'target: /docker-entrypoint-initdb\.d/10-schema\.sql' "compose targets PostgreSQL first-initialization"
require_text "$COMPOSE_CONFIG" 'read_only: true' "schema bind mount is read-only"
require_text "$COMPOSE_CONFIG" 'published: "55439"' "compose permits an isolated configured loopback port"
if grep -Eq 'container_name:' "$COMPOSE"; then
  bad "compose does not force a globally shared container name"
else
  ok "compose does not force a globally shared container name"
fi

printf '\n== summary ==\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
