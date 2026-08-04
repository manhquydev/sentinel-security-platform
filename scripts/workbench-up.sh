#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose="$ROOT/infra/workbench/docker-compose.yml"
if rg -q '/var/run/docker.sock|B3_LITELLM_VIRTUAL_KEY|/evidence|infra/.env' "$compose"; then
  echo "unsafe workbench web compose topology" >&2
  exit 1
fi

runtime_base="${XDG_RUNTIME_DIR:-/tmp}"
umask 077
runtime_root="$(mktemp -d "$runtime_base/sentinel-workbench.XXXXXX")"
printf '%s\n' "sentinel-workbench-host-broker-v1" > "$runtime_root/ownership"
startup_capability="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
broker_origin="http://127.0.0.1:4174"
fixture_values="$(PYTHONPATH="$ROOT" python3 -c 'from workbench.fixture_transport import CONFIG_DIGEST, PAIR_DIGEST, PROFILE_ID; print(CONFIG_DIGEST, PAIR_DIGEST, PROFILE_ID)')"
read -r config_digest pair_digest profile_id <<< "$fixture_values"

WORKBENCH_UI_ORIGIN="http://127.0.0.1:4173" \
WORKBENCH_STARTUP_CAPABILITY="$startup_capability" \
WORKBENCH_CONFIG_DIGEST="$config_digest" \
WORKBENCH_ALLOWED_PROFILES="$profile_id" \
WORKBENCH_ALLOWED_PAIR_DIGESTS="$pair_digest" \
WORKBENCH_BROKER_STATE_PATH="$runtime_root/broker.sqlite" \
bash "$ROOT/scripts/workbench-broker.sh" --serve >"$runtime_root/broker.log" 2>&1 &
broker_pid="$!"

for _ in $(seq 1 20); do
  if ! kill -0 "$broker_pid" 2>/dev/null; then
    echo "host broker failed to start" >&2
    exit 1
  fi
  sleep 0.05
done

WORKBENCH_UI_ORIGIN="http://127.0.0.1:4173" \
WORKBENCH_STARTUP_CAPABILITY="$startup_capability" \
WORKBENCH_CONFIG_DIGEST="$config_digest" \
WORKBENCH_ALLOWED_PROFILES="$profile_id" \
WORKBENCH_ALLOWED_PAIR_DIGESTS="$pair_digest" \
WORKBENCH_BROKER_STATE_PATH="$runtime_root/broker.sqlite" \
WORKBENCH_PRIVATE_WORKER_SOCKET="$runtime_root/worker.sock" \
bash "$ROOT/scripts/workbench-worker.sh" --serve >"$runtime_root/worker.log" 2>&1 &
worker_pid="$!"

for _ in $(seq 1 20); do
  if ! kill -0 "$worker_pid" 2>/dev/null; then
    echo "host worker failed to start" >&2
    kill "$broker_pid" 2>/dev/null || true
    exit 1
  fi
  sleep 0.05
done

if ! WORKBENCH_BROKER_ORIGIN="$broker_origin" docker compose -p sentinel-workbench -f "$compose" up -d --build; then
  kill "$worker_pid" 2>/dev/null || true
  kill "$broker_pid" 2>/dev/null || true
  rm -rf "$runtime_root"
  exit 1
fi

echo "Workbench: http://127.0.0.1:4173/#startup_capability=$startup_capability"
echo "Host broker state: $runtime_root"
