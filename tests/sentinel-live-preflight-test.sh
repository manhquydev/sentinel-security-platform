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
output_omits() { ! grep -Fq "$1" "$tmp/out"; }

fixture="$tmp/fixture"
mkdir -p "$fixture/scripts" "$fixture/rag/.venv/bin" "$fixture/infra/litellm" \
  "$fixture/plans/260730-1018-sentinel-fresh-bounded-live-acceptance-closure" "$tmp/bin" "$tmp/home/.sentinel" "$tmp/runs"
cp "$SOURCE" "$fixture/scripts/sentinel-live-preflight.sh"
cp "$ROOT/scripts/scan-and-import.sh" "$fixture/scripts/scan-and-import.sh"
chmod +x "$fixture/scripts/sentinel-live-preflight.sh"
chmod +x "$fixture/scripts/scan-and-import.sh"
mkdir -p "$fixture/scanners"
touch "$fixture/scanners/target-allowlist.sh"
chmod +x "$fixture/scanners/target-allowlist.sh"
printf 'export NUCLEI_IMAGE="projectdiscovery/nuclei@sha256:%s"\n' "$(printf 'a%.0s' {1..64})" >"$fixture/scanners/image-pins.env"
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

python3 - "$tmp/home/.sentinel/operator-approval.pub.pem" "$tmp/home/private.pem" <<'PY'
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pathlib import Path

public, private = map(Path, __import__("sys").argv[1:])
key = Ed25519PrivateKey.generate()
private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
PY
chmod 600 "$tmp/home/private.pem" "$tmp/home/.sentinel/operator-approval.pub.pem"

python3 - "$tmp/home/.sentinel/different-operator-approval.pub.pem" <<'PY'
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pathlib import Path

Path(__import__("sys").argv[1]).write_bytes(
    Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
)
PY
chmod 600 "$tmp/home/.sentinel/different-operator-approval.pub.pem"

cat >"$tmp/home/.sentinel/charter-executor-adapter.sh" <<'EOF'
#!/usr/bin/env bash
touch "$ADAPTER_MARKER"
exit 99
EOF
chmod 700 "$tmp/home/.sentinel/charter-executor-adapter.sh"

expected_key_sha="$(openssl pkey -pubin -in "$tmp/home/.sentinel/operator-approval.pub.pem" -outform DER | sha256sum | awk '{print $1}')"

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
spec = make_spec(run_id=str(run_id), method="GET", path="/sentinel-charter/rest/products/search", query="q=apple", ttl=int(spec_ttl))
payload = asdict(spec)
payload["headers"] = [list(pair) for pair in spec.headers]
(run / "request-spec.json").write_text(json.dumps(payload), encoding="utf-8")
private = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
Path(approval_path).write_text(json.dumps(asdict(sign(spec, private, ttl=int(approval_ttl)))), encoding="utf-8")
PY
  chmod 600 "$run/request-spec.json" "$tmp/approval.json"
}

run_preflight() {
  local scanner_digest="${FIXTURE_SENTINEL_NUCLEI_IMAGE_DIGEST-$(printf 'a%.0s' {1..64})}"
  local public_key_sha256="${FIXTURE_SENTINEL_CHARTER_PUBLIC_KEY_SHA256-$expected_key_sha}"
  local public_key="${FIXTURE_SENTINEL_CHARTER_PUBLIC_KEY-$tmp/home/.sentinel/operator-approval.pub.pem}"
  HOME="$tmp/home" PATH="$tmp/bin:$PATH" DOCKER_LOG="$tmp/docker.log" ADAPTER_MARKER="$tmp/adapter-called" \
    SENTINEL_RUNS_DIR="$tmp/runs" TARGET_URL="http://127.0.0.1:13000" \
    SENTINEL_LITELLM_ALIAS="sast-charter-vertex-gemini-flash-lite" LITELLM_MASTER_KEY="redacted-master" \
    SENTINEL_NUCLEI_IMAGE_DIGEST="$scanner_digest" \
    SENTINEL_CHARTER_PUBLIC_KEY="$public_key" \
    SENTINEL_CHARTER_PUBLIC_KEY_SHA256="$public_key_sha256" \
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

: >"$fixture/scanners/image-pins.env"
if run_preflight base >"$tmp/out" 2>&1; then
  bad 'image policy without a pin passed'
else
  grep -Fxq 'BLOCK scanner-selector' "$tmp/out" && ok 'image policy without a pin fails closed' || bad 'missing image pin refusal missing'
  grep -Fxq 'INFO scanner-selector-reason missing-image-policy-pin' "$tmp/out" && ok 'missing image pin has a safe operator diagnostic' || bad 'missing image pin diagnostic missing'
fi
printf 'export NUCLEI_IMAGE="projectdiscovery/nuclei@sha256:%s"\n' "$(printf 'a%.0s' {1..64})" >"$fixture/scanners/image-pins.env"

: >"$tmp/docker.log"
if FIXTURE_SENTINEL_NUCLEI_IMAGE_DIGEST="$(printf 'b%.0s' {1..64})" run_preflight base >"$tmp/out" 2>&1; then
  bad 'unapproved scanner image passed'
else
  grep -Fxq 'BLOCK scanner-selector' "$tmp/out" && ok 'unapproved image selector fails closed' || bad 'unapproved image selector refusal missing'
  grep -Fxq 'INFO scanner-selector-reason image-policy-mismatch' "$tmp/out" && ok 'unapproved image has a safe operator diagnostic' || bad 'unapproved image diagnostic missing'
  output_omits "$(printf 'b%.0s' {1..64})" && ok 'unapproved image digest is not disclosed' || bad 'unapproved image digest leaked'
  output_omits 'scan-and-import:' && ok 'raw selector error is not disclosed' || bad 'raw selector error leaked'
fi

mkdir "$tmp/attacker-scanners"
printf 'export NUCLEI_IMAGE="projectdiscovery/nuclei@sha256:%s"\n' "$(printf 'b%.0s' {1..64})" >"$tmp/attacker-scanners/image-pins.env"
if SCANNERS_DIR="$tmp/attacker-scanners" FIXTURE_SENTINEL_NUCLEI_IMAGE_DIGEST="$(printf 'b%.0s' {1..64})" run_preflight base >"$tmp/out" 2>&1; then
  bad 'environment-selected scanner policy passed'
else
  grep -Fxq 'BLOCK scanner-selector' "$tmp/out" && ok 'preflight ignores an environment-selected scanner policy' || bad 'scanner policy path refusal missing'
  grep -Fxq 'INFO scanner-selector-reason image-policy-mismatch' "$tmp/out" && ok 'environment-selected policy has no path disclosure' || bad 'environment-selected policy diagnostic missing'
  output_omits "$tmp/attacker-scanners" && ok 'environment-selected policy path is not disclosed' || bad 'environment-selected policy path leaked'
fi

if NUCLEI_IMAGE="projectdiscovery/nuclei@sha256:$(printf 'b%.0s' {1..64})" run_preflight base >"$tmp/out" 2>&1; then
  bad 'legacy image selector passed'
else
  grep -Fxq 'BLOCK scanner-selector' "$tmp/out" && ok 'legacy image selector fails closed' || bad 'legacy image selector refusal missing'
  grep -Fxq 'INFO scanner-selector-reason legacy-selector' "$tmp/out" && ok 'legacy image has a safe operator diagnostic' || bad 'legacy image diagnostic missing'
fi

if NUCLEI_BIN=/bin/true run_preflight base >"$tmp/out" 2>&1; then
  bad 'legacy binary selector passed'
else
  grep -Fxq 'BLOCK scanner-selector' "$tmp/out" && ok 'legacy binary selector fails closed' || bad 'legacy binary selector refusal missing'
  grep -Fxq 'INFO scanner-selector-reason legacy-selector' "$tmp/out" && ok 'legacy binary has a safe operator diagnostic' || bad 'legacy binary diagnostic missing'
  output_omits /bin/true && ok 'legacy binary path is not disclosed' || bad 'legacy binary path leaked'
fi

if FIXTURE_SENTINEL_NUCLEI_IMAGE_DIGEST= SENTINEL_NUCLEI_BIN=/bin/true run_preflight base >"$tmp/out" 2>&1; then
  bad 'unregistered local binary passed'
else
  grep -Fxq 'BLOCK scanner-selector' "$tmp/out" && ok 'unregistered local binary fails closed' || bad 'local binary refusal missing'
  grep -Fxq 'INFO scanner-selector-reason unregistered-local-binary' "$tmp/out" && ok 'local binary has a safe operator diagnostic' || bad 'local binary diagnostic missing'
  output_omits /bin/true && ok 'unregistered local binary path is not disclosed' || bad 'unregistered local binary path leaked'
fi

if FIXTURE_SENTINEL_NUCLEI_IMAGE_DIGEST= SENTINEL_NUCLEI_BIN= run_preflight base >"$tmp/out" 2>&1; then
  bad 'missing scanner selector passed'
else
  grep -Fxq 'BLOCK scanner-selector' "$tmp/out" && ok 'missing scanner selector fails closed' || bad 'missing scanner selector refusal missing'
  grep -Fxq 'INFO scanner-selector-reason missing-selector' "$tmp/out" && ok 'missing selector has a safe operator diagnostic' || bad 'missing selector diagnostic missing'
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
if SENTINEL_CHARTER_EXECUTOR_API_KEY=unexpected run_preflight base >"$tmp/out" 2>&1; then
  bad 'controller accepted executor API key in its environment'
else
  grep -Fxq 'BLOCK controller-secret-boundary' "$tmp/out" && ok 'controller refuses executor API key in its environment' \
    || bad 'controller API-key boundary refusal missing'
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

if FIXTURE_SENTINEL_CHARTER_PUBLIC_KEY_SHA256="$(printf '0%.0s' {1..64})" run_preflight base >"$tmp/out" 2>&1; then
  bad 'wrong public-key fingerprint passed readiness'
else
  grep -Fxq 'BLOCK approval-public-key-fingerprint' "$tmp/out" && ok 'wrong public-key fingerprint blocks readiness' || bad 'public-key fingerprint refusal missing'
  [ ! -e "$tmp/adapter-called" ] && ok 'wrong public-key fingerprint invokes no adapter' || bad 'wrong public-key fingerprint invoked adapter'
fi

if FIXTURE_SENTINEL_CHARTER_PUBLIC_KEY_SHA256= run_preflight base >"$tmp/out" 2>&1; then
  bad 'missing public-key fingerprint passed readiness'
else
  grep -Fxq 'BLOCK approval-public-key-fingerprint' "$tmp/out" && ok 'missing public-key fingerprint blocks readiness' || bad 'missing public-key fingerprint refusal missing'
  [ ! -e "$tmp/adapter-called" ] && ok 'missing public-key fingerprint invokes no adapter' || bad 'missing public-key fingerprint invoked adapter'
fi

if FIXTURE_SENTINEL_CHARTER_PUBLIC_KEY_SHA256="${expected_key_sha^^}" run_preflight base >"$tmp/out" 2>&1; then
  bad 'uppercase public-key fingerprint passed readiness'
else
  grep -Fxq 'BLOCK approval-public-key-fingerprint' "$tmp/out" && ok 'uppercase public-key fingerprint blocks readiness' || bad 'uppercase public-key fingerprint refusal missing'
  [ ! -e "$tmp/adapter-called" ] && ok 'uppercase public-key fingerprint invokes no adapter' || bad 'uppercase public-key fingerprint invoked adapter'
fi

if FIXTURE_SENTINEL_CHARTER_PUBLIC_KEY_SHA256=not-a-sha256-pin run_preflight base >"$tmp/out" 2>&1; then
  bad 'malformed public-key fingerprint passed readiness'
else
  grep -Fxq 'BLOCK approval-public-key-fingerprint' "$tmp/out" && ok 'malformed public-key fingerprint blocks readiness' || bad 'malformed public-key fingerprint refusal missing'
  [ ! -e "$tmp/adapter-called" ] && ok 'malformed public-key fingerprint invokes no adapter' || bad 'malformed public-key fingerprint invoked adapter'
fi

if FIXTURE_SENTINEL_CHARTER_PUBLIC_KEY="$tmp/home/.sentinel/different-operator-approval.pub.pem" run_preflight base >"$tmp/out" 2>&1; then
  bad 'substituted public key passed readiness'
else
  grep -Fxq 'BLOCK approval-public-key-fingerprint' "$tmp/out" && ok 'substituted public key blocks readiness' || bad 'substituted public-key refusal missing'
  [ ! -e "$tmp/adapter-called" ] && ok 'substituted public key invokes no adapter' || bad 'substituted public key invoked adapter'
fi

chmod 660 "$tmp/home/.sentinel/operator-approval.pub.pem"
if run_preflight base >"$tmp/out" 2>&1; then
  bad 'group-or-other-writable public key passed readiness'
else
  grep -Fxq 'BLOCK approval-public-key-path' "$tmp/out" && ok 'group-or-other-writable public key blocks readiness' || bad 'public-key mode refusal missing'
  [ ! -e "$tmp/adapter-called" ] && ok 'group-or-other-writable public key invokes no adapter' || bad 'group-or-other-writable public key invoked adapter'
fi
chmod 600 "$tmp/home/.sentinel/operator-approval.pub.pem"

cp "$tmp/home/.sentinel/operator-approval.pub.pem" "$tmp/home/.sentinel/operator-approval-real.pub.pem"
rm "$tmp/home/.sentinel/operator-approval.pub.pem"
ln -s "$tmp/home/.sentinel/operator-approval-real.pub.pem" "$tmp/home/.sentinel/operator-approval.pub.pem"
if run_preflight base >"$tmp/out" 2>&1; then
  bad 'public-key symlink passed readiness'
else
  grep -Fxq 'BLOCK approval-public-key-path' "$tmp/out" && ok 'public-key symlink blocks readiness' || bad 'public-key symlink refusal missing'
  [ ! -e "$tmp/adapter-called" ] && ok 'public-key symlink invokes no adapter' || bad 'public-key symlink invoked adapter'
fi
rm "$tmp/home/.sentinel/operator-approval.pub.pem"
mv "$tmp/home/.sentinel/operator-approval-real.pub.pem" "$tmp/home/.sentinel/operator-approval.pub.pem"

printf '%s\n' 'not a public key' >"$tmp/home/.sentinel/not-an-ed25519-key.pem"
chmod 600 "$tmp/home/.sentinel/not-an-ed25519-key.pem"
if FIXTURE_SENTINEL_CHARTER_PUBLIC_KEY="$tmp/home/.sentinel/not-an-ed25519-key.pem" run_preflight base >"$tmp/out" 2>&1; then
  bad 'non-Ed25519 public material passed readiness'
else
  grep -Fxq 'BLOCK approval-public-key-fingerprint' "$tmp/out" && ok 'non-Ed25519 public material blocks readiness' || bad 'non-Ed25519 refusal missing'
  ! grep -Fq 'not a public key' "$tmp/out" && ok 'non-Ed25519 material is not disclosed' || bad 'non-Ed25519 material leaked'
  [ ! -e "$tmp/adapter-called" ] && ok 'non-Ed25519 material invokes no adapter' || bad 'non-Ed25519 material invoked adapter'
fi

printf '%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
