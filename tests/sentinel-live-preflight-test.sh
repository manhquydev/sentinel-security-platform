#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/scripts/sentinel-live-preflight.sh"
tmp="$(mktemp -d)"
trap 'kill "${listener_pid:-}" 2>/dev/null || true; rm -rf "$tmp"' EXIT

pass=0
fail=0
ok() { printf 'PASS %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf 'FAIL %s\n' "$1" >&2; fail=$((fail + 1)); }

fixture="$tmp/fixture"
mkdir -p "$fixture/scripts" "$fixture/rag/.venv/bin" "$fixture/infra/litellm" \
  "$fixture/plans/260730-1018-sentinel-fresh-bounded-live-acceptance-closure" "$tmp/bin" "$tmp/home/.sentinel" "$tmp/runs"
cp "$SOURCE" "$fixture/scripts/sentinel-live-preflight.sh"
chmod +x "$fixture/scripts/sentinel-live-preflight.sh"
touch "$fixture/scripts/scan-and-import.sh"
chmod +x "$fixture/scripts/scan-and-import.sh"
mkdir -p "$fixture/scanners"
touch "$fixture/scanners/target-allowlist.sh"
chmod +x "$fixture/scanners/target-allowlist.sh"
ln -s "$ROOT/rag/.venv/bin/python" "$fixture/rag/.venv/bin/python"
cp "$ROOT/infra/litellm/config.yaml" "$fixture/infra/litellm/config.yaml"
touch "$fixture/infra/.env"
chmod 600 "$fixture/infra/.env"
chmod 700 "$tmp/runs"

cat >"$tmp/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$DOCKER_LOG"
case "$1" in
  info) exit 0 ;;
  container)
    [ "${2:-}" = inspect ] || exit 1
    if [ -n "${FAKE_DOCKER_MISSING_NAME:-}" ] && [[ "$*" == *" ${FAKE_DOCKER_MISSING_NAME}" ]]; then
      exit 1
    fi
    if [ "${FAKE_DOCKER_UNHEALTHY:-0}" = 1 ]; then
      printf '%s\n' 'true unhealthy'
      exit 0
    fi
    if [[ "$*" == *" dd-nginx" ]]; then
      printf '%s\n' 'true none'
    else
      printf '%s\n' 'true healthy'
    fi
    exit 0
    ;;
esac
exit 1
EOF
chmod +x "$tmp/bin/docker"

python3 - <<'PY' &
import socket
import threading

listeners = []
for port in (4000, 8080, 13000, 18443):
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", port))
        sock.listen()
        listeners.append(sock)
    except OSError:
        pass

def accept_forever(value):
    while True:
        try:
            conn, _ = value.accept()
        except OSError:
            return
        conn.close()

for sock in listeners:
    threading.Thread(target=accept_forever, args=(sock,), daemon=True).start()
threading.Event().wait()
PY
listener_pid=$!

python3 - "$tmp/home/.sentinel/charter-approval-manhquy.ed25519.pub.pem" "$tmp/home/private.pem" <<'PY'
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pathlib import Path

public, private = map(Path, __import__("sys").argv[1:])
key = Ed25519PrivateKey.generate()
private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
PY
chmod 600 "$tmp/home/private.pem" "$tmp/home/.sentinel/charter-approval-manhquy.ed25519.pub.pem"

cat >"$tmp/home/.sentinel/charter-executor-adapter.sh" <<'EOF'
#!/usr/bin/env bash
touch "$ADAPTER_MARKER"
exit 99
EOF
chmod 700 "$tmp/home/.sentinel/charter-executor-adapter.sh"

expected_key_sha="$(openssl pkey -pubin -in "$tmp/home/.sentinel/charter-approval-manhquy.ed25519.pub.pem" -outform DER | sha256sum | awk '{print $1}')"
sed -i "s/EXPECTED_KEY_SHA256=\"[0-9a-f]*\"/EXPECTED_KEY_SHA256=\"$expected_key_sha\"/" "$fixture/scripts/sentinel-live-preflight.sh"

create_approved_run() {
  local id=$1 spec_ttl=${2:-300} approval_ttl=${3:-300}
  local run="$tmp/runs/$id"
  mkdir -m 700 "$run"
  "$ROOT/rag/.venv/bin/python" - "$run" "$id" "$tmp/home/private.pem" "$tmp/approval.json" "$spec_ttl" "$approval_ttl" <<'PY'
import json
import sys
from dataclasses import asdict
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from agent.charter_approval import sign
from agent.charter_requests import make_spec

run, run_id, private_path, approval_path, spec_ttl, approval_ttl = sys.argv[1:]
run, run_id, private_path, approval_path = map(Path, (run, run_id, private_path, approval_path))
spec = make_spec(run_id=str(run_id), method="GET", path="/rest/products/search", query="q=apple", ttl=int(spec_ttl))
payload = asdict(spec)
payload["headers"] = [list(pair) for pair in spec.headers]
(run / "request-spec.json").write_text(json.dumps(payload), encoding="utf-8")
private = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
Path(approval_path).write_text(json.dumps(asdict(sign(spec, private, ttl=int(approval_ttl)))), encoding="utf-8")
PY
  chmod 600 "$run/request-spec.json" "$tmp/approval.json"
}

run_preflight() {
  HOME="$tmp/home" PATH="$tmp/bin:$PATH" DOCKER_LOG="$tmp/docker.log" ADAPTER_MARKER="$tmp/adapter-called" \
    SENTINEL_RUNS_DIR="$tmp/runs" TARGET_URL="http://127.0.0.1:13000" \
    SENTINEL_LITELLM_ALIAS="sast-charter-vertex-gemini-flash-lite" LITELLM_MASTER_KEY="redacted-master" \
    SENTINEL_NUCLEI_IMAGE_DIGEST="$(printf 'a%.0s' {1..64})" \
    SENTINEL_CHARTER_PUBLIC_KEY="$tmp/home/.sentinel/charter-approval-manhquy.ed25519.pub.pem" \
    SENTINEL_CHARTER_EXECUTOR_ADAPTER="$tmp/home/.sentinel/charter-executor-adapter.sh" \
    SENTINEL_CHARTER_APPROVAL_FILE="$tmp/approval.json" \
    PYTHONPATH="$ROOT" "$fixture/scripts/sentinel-live-preflight.sh" "$@"
}

: >"$tmp/docker.log"
if run_preflight base >"$tmp/out" 2>&1; then
  grep -Fxq 'READY_FOR_FRESH_PROPOSAL' "$tmp/out" && ok 'base readiness is explicitly non-dispatching' || bad 'base readiness had no ready result'
  [ ! -e "$tmp/adapter-called" ] && ok 'base readiness never invokes adapter' || bad 'base readiness invoked adapter'
  ! grep -Eq 'compose|run|exec|logs|down|up' "$tmp/docker.log" && ok 'base readiness uses no Docker mutation or log source' || bad 'base readiness used unsafe Docker command'
  ! grep -q 'redacted-master' "$tmp/out" && ok 'base readiness emits no secret value' || bad 'base readiness emitted a secret'
else
  sed -n '1,120p' "$tmp/out" >&2
  sed -n '1,120p' "$tmp/docker.log" >&2
  bad 'valid base readiness failed'
fi

: >"$tmp/docker.log"
if SENTINEL_NUCLEI_BIN=/bin/true run_preflight base >"$tmp/out" 2>&1; then
  bad 'two scanner selectors passed'
else
  grep -Fxq 'BLOCK scanner-selector' "$tmp/out" && ok 'two scanner selectors fail closed' || bad 'two selector refusal missing'
fi

if NUCLEI_IMAGE="projectdiscovery/nuclei@sha256:$(printf 'b%.0s' {1..64})" run_preflight base >"$tmp/out" 2>&1; then
  bad 'legacy image selector passed'
else
  grep -Fxq 'BLOCK scanner-selector' "$tmp/out" && ok 'legacy image selector fails closed' || bad 'legacy image selector refusal missing'
fi

: >"$tmp/docker.log"
if FAKE_DOCKER_UNHEALTHY=1 run_preflight base >"$tmp/out" 2>&1; then
  bad 'unhealthy topology passed'
else
  grep -Fxq 'BLOCK litellm-container' "$tmp/out" && ok 'unhealthy container blocks readiness' || bad 'unhealthy container refusal missing'
fi

if SENTINEL_CHARTER_EXECUTOR_SECRET=unexpected run_preflight base >"$tmp/out" 2>&1; then
  bad 'controller executor secret passed readiness'
else
  grep -Fxq 'BLOCK controller-secret-boundary' "$tmp/out" && ok 'controller executor secret blocks readiness' || bad 'controller secret refusal missing'
fi

chmod 755 "$tmp/home/.sentinel/charter-executor-adapter.sh"
if run_preflight base >"$tmp/out" 2>&1; then
  bad 'unsafe adapter mode passed readiness'
else
  grep -Fxq 'BLOCK executor-adapter-boundary' "$tmp/out" && ok 'unsafe adapter mode blocks readiness' || bad 'adapter mode refusal missing'
fi
chmod 700 "$tmp/home/.sentinel/charter-executor-adapter.sh"

mv "$tmp/home/.sentinel/charter-executor-adapter.sh" "$tmp/home/.sentinel/charter-executor-adapter-real.sh"
ln -s "$tmp/home/.sentinel/charter-executor-adapter-real.sh" "$tmp/home/.sentinel/charter-executor-adapter.sh"
if run_preflight base >"$tmp/out" 2>&1; then
  bad 'adapter symlink passed readiness'
else
  grep -Fxq 'BLOCK executor-adapter-boundary' "$tmp/out" && ok 'adapter symlink blocks readiness' || bad 'adapter symlink refusal missing'
fi
rm "$tmp/home/.sentinel/charter-executor-adapter.sh"
mv "$tmp/home/.sentinel/charter-executor-adapter-real.sh" "$tmp/home/.sentinel/charter-executor-adapter.sh"

if FAKE_DOCKER_MISSING_NAME=dd-nginx run_preflight base >"$tmp/out" 2>&1; then
  bad 'missing service passed readiness'
else
  grep -Fxq 'BLOCK defectdojo-container' "$tmp/out" && ok 'missing service blocks readiness' || bad 'missing service refusal missing'
fi

create_approved_run current
: >"$tmp/docker.log"
if run_preflight dispatch current >"$tmp/out" 2>&1; then
  grep -Fxq 'READY_FOR_APPROVED_DISPATCH' "$tmp/out" && ok 'fresh signed approval reaches dispatch readiness' || bad 'dispatch readiness result missing'
  [ ! -e "$tmp/adapter-called" ] && ok 'dispatch readiness never invokes adapter' || bad 'dispatch readiness invoked adapter'
else
  sed -n '1,120p' "$tmp/out" >&2
  sed -n '1,120p' "$tmp/docker.log" >&2
  bad 'valid dispatch readiness failed'
fi

chmod 644 "$tmp/approval.json"
if run_preflight dispatch current >"$tmp/out" 2>&1; then
  bad 'world-readable approval passed dispatch readiness'
else
  grep -Fxq 'BLOCK signed-approval' "$tmp/out" && ok 'world-readable approval blocks dispatch readiness' || bad 'approval mode refusal missing'
fi
chmod 600 "$tmp/approval.json"

chmod 755 "$tmp/runs"
if run_preflight dispatch current >"$tmp/out" 2>&1; then
  bad 'non-private run root passed dispatch readiness'
else
  grep -Fxq 'BLOCK fresh-approved-request' "$tmp/out" && ok 'non-private run root blocks dispatch readiness' || bad 'run root refusal missing'
fi
chmod 700 "$tmp/runs"

chmod 644 "$tmp/runs/current/request-spec.json"
if run_preflight dispatch current >"$tmp/out" 2>&1; then
  bad 'non-private request spec passed dispatch readiness'
else
  grep -Fxq 'BLOCK fresh-approved-request' "$tmp/out" && ok 'non-private request spec blocks dispatch readiness' || bad 'request spec refusal missing'
fi
chmod 600 "$tmp/runs/current/request-spec.json"

create_approved_run expired -1
if run_preflight dispatch expired >"$tmp/out" 2>&1; then
  bad 'expired request passed dispatch readiness'
else
  grep -Fxq 'BLOCK fresh-approved-request' "$tmp/out" && ok 'signed expired request blocks before dispatch' || bad 'expired request refusal missing'
fi

create_approved_run expired-approval 300 -1
if run_preflight dispatch expired-approval >"$tmp/out" 2>&1; then
  bad 'expired approval passed dispatch readiness'
else
  grep -Fxq 'BLOCK fresh-approved-request' "$tmp/out" && ok 'expired signed approval blocks before dispatch' || bad 'expired approval refusal missing'
fi

sed -i 's/EXPECTED_KEY_SHA256="[0-9a-f]*"/EXPECTED_KEY_SHA256="0000000000000000000000000000000000000000000000000000000000000000"/' "$fixture/scripts/sentinel-live-preflight.sh"
if run_preflight base >"$tmp/out" 2>&1; then
  bad 'wrong public-key fingerprint passed readiness'
else
  grep -Fxq 'BLOCK approval-public-key-fingerprint' "$tmp/out" && ok 'wrong public-key fingerprint blocks readiness' || bad 'public-key fingerprint refusal missing'
fi

printf '%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
