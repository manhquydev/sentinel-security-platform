#!/usr/bin/env bash
# Start existing Charter Compose owners only.  This script never runs a Charter run.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKER="${DOCKER:-docker}"
ENV_FILE="${SENTINEL_CHARTER_ENV_FILE:-$ROOT/infra/.env}"
CERT_DIR="${SENTINEL_CHARTER_CERT_DIR:-$ROOT/infra/defectdojo-db/certs}"

fail() {
  printf '%s\n' "FATAL: $1" >&2
  exit 1
}

value_from_env_file() {
  local wanted="$1" output="$2" line value seen=0
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    case "$line" in
      "$wanted"=*)
        seen=$((seen + 1))
        value="${line#*=}"
        ;;
    esac
  done < "$ENV_FILE"
  [ "$seen" -eq 1 ] && [ -n "${value:-}" ] || return 1
  printf -v "$output" '%s' "$value"
}

[ "$#" -eq 0 ] || fail "this launcher accepts no arguments"
[ -f "$ENV_FILE" ] || fail "private environment file is unavailable"

adc_path=""
value_from_env_file VERTEXAI_ADC_PATH adc_path || fail "private environment prerequisites are invalid"
[ -f "$adc_path" ] && [ -r "$adc_path" ] || fail "private environment prerequisites are invalid"

for required in KONG_PROVISION_KEY AGENT_RECON_SECRET PROBE_ADMIN_SECRET SENTINEL_CHARTER_EXECUTOR_SECRET; do
  private_value=""
  value_from_env_file "$required" private_value || fail "private environment prerequisites are invalid"
done

for certificate in ca.crt server.crt; do
  [ -f "$CERT_DIR/$certificate" ] && [ -r "$CERT_DIR/$certificate" ] || fail "DefectDojo prerequisites are unavailable"
done

"$DOCKER" network inspect dd-net >/dev/null 2>&1 || fail "DefectDojo prerequisites are unavailable"

for container in sentinel-kong-db sentinel-kong-migrations sentinel-kong-config sentinel-kong; do
  if "$DOCKER" container inspect "$container" >/dev/null 2>&1; then
    fail "Kong state is not fresh"
  fi
done
if "$DOCKER" volume inspect sentinel-kong_kong-db >/dev/null 2>&1; then
  fail "Kong state is not fresh"
fi

compose_up() {
  "$DOCKER" compose --env-file "$ENV_FILE" -f "$1" up -d
}

compose_up "$ROOT/infra/langfuse/docker-compose.yml"
compose_up "$ROOT/infra/litellm/docker-compose.yml"
compose_up "$ROOT/infra/harness/juice-shop.compose.yml"
ENV_FILE="$ENV_FILE" "$ROOT/infra/kong/render-config.sh"
compose_up "$ROOT/infra/kong/docker-compose.yml"
compose_up "$ROOT/infra/defectdojo-db/docker-compose.yml"
compose_up "$ROOT/infra/defectdojo/docker-compose.yml"

statuses="$("$DOCKER" container inspect --format '{{.State.Status}}' \
  sentinel-litellm sentinel-kong juice-shop dd-postgres dd-nginx)" || fail "topology status is unavailable"
while IFS= read -r status; do
  [ "$status" = running ] || fail "topology is not running"
done <<<"$statuses"

printf '%s\n' "Charter topology start requested; this is not a Charter run."
