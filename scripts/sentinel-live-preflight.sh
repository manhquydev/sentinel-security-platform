#!/usr/bin/env bash
# Read-only readiness checks for a future local Charter acceptance attempt.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT/rag/.venv/bin/python"
RUNS="${SENTINEL_RUNS_DIR:-$ROOT/.sentinel-runs}"
PLAN_DIR="$ROOT/plans/260730-1018-sentinel-fresh-bounded-live-acceptance-closure"
EXPECTED_KEY_SHA256="93d82ca0c299d3df6adaec268b0a76356989a5798fa9f2d489cec477e2ac3098"
EXPECTED_KEY_PATH="${HOME:-}/.sentinel/charter-approval-manhquy.ed25519.pub.pem"
EXPECTED_ADAPTER_PATH="${HOME:-}/.sentinel/charter-executor-adapter.sh"
blocked=0

usage() {
  printf '%s\n' 'usage: sentinel-live-preflight.sh base | dispatch RUN_ID' >&2
  exit 2
}

pass() { printf 'PASS %s\n' "$1"; }
block() { printf 'BLOCK %s\n' "$1"; blocked=1; }
safe_run_id() { [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]]; }

private_regular() {
  local path=$1 expected_mode=$2
  [[ -f "$path" && ! -L "$path" ]] || return 1
  [[ "$(stat -c '%a' "$path")" == "$expected_mode" ]] || return 1
  [[ "$(stat -c '%u' "$path")" == "$(id -u)" ]]
}

regular_not_writable_by_others() {
  local path=$1 mode
  [[ -f "$path" && ! -L "$path" ]] || return 1
  [[ "$(stat -c '%u' "$path")" == "$(id -u)" ]] || return 1
  mode=$(stat -c '%a' "$path")
  (( (8#$mode & 022) == 0 ))
}

check_repo_paths() {
  private_regular "$ROOT/infra/.env" 600 && pass private-environment || block private-environment
  [[ -x "$PYTHON" ]] && pass charter-python || block charter-python
  [[ -d "$PLAN_DIR" && ! -L "$PLAN_DIR" ]] && pass acceptance-plan || block acceptance-plan
  [[ -x "$ROOT/scripts/scan-and-import.sh" && -x "$ROOT/scanners/target-allowlist.sh" ]] \
    && pass scan-contract || block scan-contract
}

check_environment() {
  [[ "${TARGET_URL:-}" == http://127.0.0.1:13000 ]] && pass target-origin || block target-origin
  [[ -n "${SENTINEL_LITELLM_ALIAS:-}" ]] && pass model-alias-present || block model-alias-present
  [[ -n "${LITELLM_MASTER_KEY:-}" ]] && pass model-credential-present || block model-credential-present
  [[ -z "${SENTINEL_CHARTER_EXECUTOR_SECRET:-}" ]] && pass controller-secret-boundary || block controller-secret-boundary
  if [[ -n "${SENTINEL_LITELLM_ALIAS:-}" ]] \
      && grep -Eq "^[[:space:]]*(-[[:space:]]*)?model_name:[[:space:]]*${SENTINEL_LITELLM_ALIAS}[[:space:]]*(#.*)?$" \
        "$ROOT/infra/litellm/config.yaml"; then
    pass model-alias-config
  else
    block model-alias-config
  fi
}

check_scanner_selector() {
  local image="${SENTINEL_NUCLEI_IMAGE_DIGEST:-}" binary="${SENTINEL_NUCLEI_BIN:-}" legacy="${NUCLEI_BIN:-}" count=0
  [[ -n "$image" ]] && count=$((count + 1))
  [[ -n "$binary" ]] && count=$((count + 1))
  [[ -n "$legacy" ]] && count=$((count + 1))
  if [[ "$count" -ne 1 || -n "$legacy" ]]; then
    block scanner-selector
  elif [[ -n "$image" && "$image" =~ ^[0-9a-f]{64}$ ]]; then
    pass scanner-selector
  elif [[ -n "$binary" && -f "$binary" && ! -L "$binary" && -x "$binary" ]]; then
    pass scanner-selector
  else
    block scanner-selector
  fi
}

check_operator_boundary() {
  [[ -n "${HOME:-}" ]] && pass operator-home || { block operator-home; return; }
  [[ "${SENTINEL_CHARTER_PUBLIC_KEY:-}" == "$EXPECTED_KEY_PATH" ]] \
    && regular_not_writable_by_others "$EXPECTED_KEY_PATH" && pass approval-public-key-path \
    || block approval-public-key-path
  [[ "${SENTINEL_CHARTER_EXECUTOR_ADAPTER:-}" == "$EXPECTED_ADAPTER_PATH" ]] \
    && private_regular "$EXPECTED_ADAPTER_PATH" 700 && pass executor-adapter-boundary \
    || block executor-adapter-boundary
  PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON" - "$EXPECTED_KEY_PATH" "$EXPECTED_KEY_SHA256" <<'PY' >/dev/null 2>&1 \
    && pass approval-public-key-fingerprint || block approval-public-key-fingerprint
import hashlib
import os
import stat
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

path, expected = sys.argv[1:]
item = os.lstat(path)
if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid():
    raise SystemExit(1)
if stat.S_IMODE(item.st_mode) & 0o022:
    raise SystemExit(1)
fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    info = os.fstat(fd)
    if not os.path.samestat(item, info):
        raise SystemExit(1)
    data = b""
    while True:
        part = os.read(fd, 65536)
        if not part:
            break
        data += part
finally:
    os.close(fd)
key = serialization.load_pem_public_key(data)
if not isinstance(key, Ed25519PublicKey):
    raise SystemExit(1)
der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
raise SystemExit(0 if hashlib.sha256(der).hexdigest() == expected else 1)
PY
}

container_ready() {
  local name=$1 expected=$2 status
  status=$(docker container inspect --format '{{.State.Running}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$name" 2>/dev/null) || status=
  [[ "$status" == "$expected" ]]
}

loopback_port_ready() {
  PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON" - "$1" <<'PY' >/dev/null 2>&1
import socket
import sys

with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1):
    pass
PY
}

check_topology() {
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && pass docker-daemon || { block docker-daemon; return; }
  container_ready sentinel-litellm 'true healthy' && pass litellm-container || block litellm-container
  container_ready sentinel-kong 'true healthy' && pass kong-container || block kong-container
  container_ready juice-shop 'true healthy' && pass juice-shop-container || block juice-shop-container
  container_ready dd-nginx 'true none' && pass defectdojo-container || block defectdojo-container
  loopback_port_ready 4000 && pass litellm-loopback || block litellm-loopback
  loopback_port_ready 18443 && pass kong-loopback || block kong-loopback
  loopback_port_ready 13000 && pass juice-shop-loopback || block juice-shop-loopback
  loopback_port_ready 8080 && pass defectdojo-loopback || block defectdojo-loopback
}

check_dispatch_artifacts() {
  local run_id=$1 approval="${SENTINEL_CHARTER_APPROVAL_FILE:-}"
  [[ -n "$approval" ]] && private_regular "$approval" 600 \
    || { block signed-approval; return; }
  PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON" - "$RUNS" "$run_id" "$approval" "$EXPECTED_KEY_PATH" <<'PY' >/dev/null 2>&1 \
    && pass fresh-approved-request || block fresh-approved-request
import json
import os
import stat
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from agent.charter_approval import CharterApproval, verify
from agent.charter_requests import load_spec

root, run_id, approval_path, public_path = map(Path, sys.argv[1:])
if not run_id.name or run_id.name != str(run_id):
    raise SystemExit(1)

def private_directory(path: Path):
    item = os.lstat(path)
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode) or item.st_uid != os.geteuid() or stat.S_IMODE(item.st_mode) != 0o700:
        raise ValueError("unsafe directory")
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not os.path.samestat(item, os.fstat(fd)):
            raise ValueError("raced directory")
    finally:
        os.close(fd)

def read_regular(path: Path, *, private: bool):
    item = os.lstat(path)
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid():
        raise ValueError("unsafe file")
    mode = stat.S_IMODE(item.st_mode)
    if (private and mode != 0o600) or (not private and mode & 0o022):
        raise ValueError("unsafe file mode")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not os.path.samestat(item, os.fstat(fd)):
            raise ValueError("raced file")
        chunks = []
        while True:
            part = os.read(fd, 65536)
            if not part:
                return b"".join(chunks)
            chunks.append(part)
    finally:
        os.close(fd)

run = root / run_id
private_directory(root)
private_directory(run)
spec = load_spec(json.loads(read_regular(run / "request-spec.json", private=True)))
if spec.run_id != str(run_id):
    raise ValueError("wrong run")
if spec.expires_at <= time.time():
    raise ValueError("expired spec")
approval = CharterApproval(**json.loads(read_regular(approval_path, private=False)))
public = serialization.load_pem_public_key(read_regular(public_path, private=False))
if approval.decision != "approve" or not verify(approval, spec, public):
    raise ValueError("invalid approval")
PY
}

mode=${1:-}
case "$mode" in
  base)
    [[ "$#" -eq 1 ]] || usage
    check_repo_paths
    check_environment
    check_scanner_selector
    check_operator_boundary
    check_topology
    ;;
  dispatch)
    [[ "$#" -eq 2 ]] && safe_run_id "$2" || usage
    check_repo_paths
    check_environment
    check_scanner_selector
    check_operator_boundary
    check_topology
    check_dispatch_artifacts "$2"
    ;;
  *) usage ;;
esac

if [[ "$blocked" -ne 0 ]]; then
  printf 'BLOCKED %s\n' "$mode"
  exit 1
fi
if [[ "$mode" == base ]]; then
  printf '%s\n' 'READY_FOR_FRESH_PROPOSAL'
else
  printf '%s\n' 'READY_FOR_APPROVED_DISPATCH'
fi
