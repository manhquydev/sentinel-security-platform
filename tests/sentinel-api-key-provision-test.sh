#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$ROOT/scripts/sentinel-provision-api-key.py"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
pass=0 fail=0
ok() { printf 'PASS %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf 'FAIL %s\n' "$1" >&2; fail=$((fail + 1)); }

kong="$tmp/kong.env"
executor="$tmp/executor.env"
printf '%s\n' 'KONG_PROVISION_KEY=private-value' >"$kong"
printf '%s\n' 'SENTINEL_CHARTER_EXECUTOR_SECRET=private-value' >"$executor"
chmod 600 "$kong" "$executor"

if output="$(python3 "$TOOL" --kong-env "$kong" --executor-env "$executor")"; then
  [ "$output" = 'API key provisioned' ] && ok 'provisioner reports only generic success' || bad 'provisioner output is unexpected'
else
  bad 'initial provisioning failed'
fi

key_from() { awk -F= '$1=="SENTINEL_CHARTER_EXECUTOR_API_KEY" {print $2}' "$1"; }
key_a="$(key_from "$kong")"
key_b="$(key_from "$executor")"
if [ -n "$key_a" ] && [ "$key_a" = "$key_b" ] \
  && [ "$(grep -c '^SENTINEL_CHARTER_EXECUTOR_API_KEY=' "$kong")" = 1 ] \
  && [ "$(grep -c '^SENTINEL_CHARTER_EXECUTOR_API_KEY=' "$executor")" = 1 ] \
  && [ "$(stat -c '%a' "$kong")" = 600 ] && [ "$(stat -c '%a' "$executor")" = 600 ]; then
  ok 'private files receive one shared API key with mode 0600'
else
  bad 'private API-key publication contract failed'
fi
if ! grep -Fq "$key_a" <<<"$output"; then ok 'provisioner does not print the API key'; else bad 'provisioner leaked the API key'; fi

if output="$(python3 "$TOOL" --kong-env "$kong" --executor-env "$executor")"; then
  [ "$output" = 'API key already synchronized' ] && ok 'provisioner is idempotent' || bad 'idempotent output is unexpected'
else
  bad 'idempotent provisioning failed'
fi

before_kong="$(sha256sum "$kong" | awk '{print $1}')"
before_executor="$(sha256sum "$executor" | awk '{print $1}')"
sed -i 's/^SENTINEL_CHARTER_EXECUTOR_API_KEY=.*/SENTINEL_CHARTER_EXECUTOR_API_KEY=mismatch/' "$executor"
if python3 "$TOOL" --kong-env "$kong" --executor-env "$executor" >"$tmp/out" 2>&1; then
  bad 'mismatched private API keys were accepted'
else
  [ "$(sha256sum "$kong" | awk '{print $1}')" = "$before_kong" ] \
    && [ "$(grep '^SENTINEL_CHARTER_EXECUTOR_API_KEY=' "$executor")" = 'SENTINEL_CHARTER_EXECUTOR_API_KEY=mismatch' ] \
    && ok 'mismatched private API keys fail without overwriting either file' \
    || bad 'mismatched private API keys changed a file'
fi

chmod 644 "$kong"
if python3 "$TOOL" --kong-env "$kong" --executor-env "$executor" >"$tmp/out" 2>&1; then
  bad 'world-readable private environment was accepted'
else
  ok 'unsafe private environment is refused'
fi

printf '%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
