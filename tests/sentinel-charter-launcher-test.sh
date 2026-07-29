#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAUNCHER="$ROOT/scripts/sentinel-charter-up.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0
ok() { printf 'ok - %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf 'not ok - %s\n' "$1" >&2; fail=$((fail + 1)); }

bin="$tmp/bin"
mkdir -p "$bin" "$tmp/certs"
touch "$tmp/certs/ca.crt" "$tmp/certs/server.crt" "$tmp/adc.json"
log="$tmp/docker.log"

cat >"$bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s ' "$@" >>"$DOCKER_LOG"; printf '\n' >>"$DOCKER_LOG"
case "$1 $2" in
  'network inspect') [ "${FAKE_NO_DD_NET:-0}" = 1 ] && exit 1; exit 0 ;;
  'volume inspect') [ "${FAKE_KONG_VOLUME:-0}" = 1 ] && exit 0; exit 1 ;;
  'container inspect')
    if [ "${3:-}" = '--format' ]; then
      for container in "${@:5}"; do
        if [ "${FAKE_STOPPED_CONTAINER:-}" = "$container" ]; then printf '%s\n' exited; else printf '%s\n' running; fi
      done
      exit 0
    fi
    if [ "${FAKE_KONG_CONTAINER:-}" = "${3:-}" ]; then exit 0; fi
    exit 1
    ;;
  'compose --env-file') exit 0 ;;
esac
exit 0
EOF
chmod +x "$bin/docker"

cat >"$bin/envsubst" <<'EOF'
#!/usr/bin/env bash
python3 - <<'PY'
import os
import sys

content = sys.stdin.read()
for name in ("KONG_PROVISION_KEY", "AGENT_RECON_SECRET", "PROBE_ADMIN_SECRET", "SENTINEL_CHARTER_EXECUTOR_SECRET"):
    content = content.replace("${" + name + "}", os.environ[name])
sys.stdout.write(content)
PY
EOF
chmod +x "$bin/envsubst"

write_env() {
  cat >"$tmp/env" <<EOF
VERTEXAI_ADC_PATH=$tmp/adc.json
KONG_PROVISION_KEY=redacted-provision
AGENT_RECON_SECRET=redacted-recon
PROBE_ADMIN_SECRET=redacted-probe
SENTINEL_CHARTER_EXECUTOR_SECRET=redacted-executor
EOF
}

run_launcher() {
  : >"$log"
  DOCKER="$bin/docker" DOCKER_LOG="$log" PATH="$bin:$PATH" OUT="$tmp/rendered.yml" \
    SENTINEL_CHARTER_ENV_FILE="$tmp/env" SENTINEL_CHARTER_CERT_DIR="$tmp/certs" \
    "$LAUNCHER" "$@"
}

write_env
rm -f "$tmp/env"
if run_launcher >"$tmp/out" 2>&1; then bad 'missing env passed'; else
  [ ! -s "$log" ] && ok 'missing env fails before Docker' || bad 'missing env reached Docker'
fi

write_env
printf 'VERTEXAI_ADC_PATH=%s\n' "$tmp/adc.json" >>"$tmp/env"
if run_launcher >"$tmp/out" 2>&1; then bad 'duplicate ADC passed'; else
  [ ! -s "$log" ] && ok 'duplicate ADC fails before Docker' || bad 'duplicate ADC reached Docker'
fi

write_env
marker="$tmp/evaluated"
printf 'VERTEXAI_ADC_PATH=$(touch %s)\n' "$marker" >"$tmp/env"
cat >>"$tmp/env" <<'EOF'
KONG_PROVISION_KEY=redacted-provision
AGENT_RECON_SECRET=redacted-recon
PROBE_ADMIN_SECRET=redacted-probe
SENTINEL_CHARTER_EXECUTOR_SECRET=redacted-executor
EOF
if run_launcher >"$tmp/out" 2>&1; then bad 'shell-looking ADC passed'; else
  [ ! -e "$marker" ] && [ ! -s "$log" ] && ok 'env content is not evaluated' || bad 'env content was evaluated or reached Docker'
fi

write_env
rm -f "$tmp/adc.json"
if run_launcher >"$tmp/out" 2>&1; then bad 'missing ADC passed'; else
  [ ! -s "$log" ] && ok 'missing ADC fails before Docker' || bad 'missing ADC reached Docker'
fi
touch "$tmp/adc.json"

for certificate in ca.crt server.crt; do
  write_env
  rm -f "$tmp/certs/$certificate"
  if run_launcher >"$tmp/out" 2>&1; then bad "missing $certificate passed"; else
    [ ! -s "$log" ] && ok "missing $certificate fails before Docker" || bad "missing $certificate reached Docker"
  fi
  touch "$tmp/certs/$certificate"
done

write_env
sed -i '/AGENT_RECON_SECRET/d' "$tmp/env"
if run_launcher >"$tmp/out" 2>&1; then bad 'missing renderer value passed'; else
  [ ! -s "$log" ] && ok 'missing renderer value fails before Docker' || bad 'missing renderer value reached Docker'
fi

write_env
if FAKE_NO_DD_NET=1 run_launcher >"$tmp/out" 2>&1; then bad 'missing dd-net passed'; else
  if ! grep -q 'compose' "$log" && ! grep -q 'redacted-' "$tmp/out"; then ok 'missing dd-net fails before compose without secret output'; else bad 'missing dd-net reached compose or leaked a secret'; fi
fi

for container in sentinel-kong-db sentinel-kong-migrations sentinel-kong-config sentinel-kong; do
  write_env
  if FAKE_KONG_CONTAINER="$container" run_launcher >"$tmp/out" 2>&1; then bad "existing $container passed"; else
    ! grep -q 'compose' "$log" && ok "existing $container fails before compose" || bad "existing $container reached compose"
  fi
done

write_env
if FAKE_KONG_VOLUME=1 run_launcher >"$tmp/out" 2>&1; then bad 'existing Kong volume passed'; else
  ! grep -q 'compose' "$log" && ok 'existing Kong volume fails before compose' || bad 'existing Kong volume reached compose'
fi

write_env
if run_launcher >"$tmp/out" 2>&1; then
  expected='infra/langfuse/docker-compose.yml infra/litellm/docker-compose.yml infra/harness/juice-shop.compose.yml infra/kong/docker-compose.yml infra/defectdojo-db/docker-compose.yml infra/defectdojo/docker-compose.yml'
  actual="$(grep 'compose' "$log" | sed -E 's@.*-f .*/(infra/[^ ]+).*@\1@' | tr '\n' ' ')"
  if [ "$actual" = "$expected " ]; then ok 'exact Compose owner order'; else bad "unexpected owner order: $actual"; fi
  argv_ok=1
  for compose_file in $expected; do
    grep -Fqx "compose --env-file $tmp/env -f $ROOT/$compose_file up -d " "$log" || argv_ok=0
  done
  [ "$argv_ok" -eq 1 ] && ok 'exact Compose owner argv' || bad 'unexpected Compose owner argv'
  grep -Fqx 'container inspect --format {{.State.Status}} sentinel-litellm sentinel-kong juice-shop dd-postgres dd-nginx ' "$log" \
    && ok 'exact bounded final status vector' || bad 'unexpected final status vector'
  if ! grep -Eqi 'curl|http|retry|controller|scanner|import|approval|executor|target|teardown| down ' "$log"; then ok 'no forbidden command reached fake Docker'; else bad 'forbidden command reached fake Docker'; fi
  if ! grep -q 'redacted-' "$tmp/out" && ! grep -q 'redacted-' "$log"; then ok 'no secret emitted'; else bad 'secret was emitted'; fi
else
  bad 'valid launcher contract failed'
fi

write_env
if FAKE_STOPPED_CONTAINER=sentinel-kong run_launcher >"$tmp/out" 2>&1; then
  bad 'stopped service produced a successful launch'
else
  grep -q 'topology is not running' "$tmp/out" && ok 'stopped service fails bounded status admission' || bad 'stopped service failure was unclear'
fi

write_env
marker="$tmp/renderer-evaluated"
sed -i "s|^KONG_PROVISION_KEY=.*|KONG_PROVISION_KEY=\$(touch $marker)|" "$tmp/env"
if run_launcher >"$tmp/out" 2>&1 && [ ! -e "$marker" ]; then
  ok 'renderer environment content is not evaluated'
else
  bad 'renderer environment content was evaluated or rejected unexpectedly'
fi

printf '%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
