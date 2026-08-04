#!/usr/bin/env bash
# Read-only readiness checks for a future local Charter acceptance attempt.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT/rag/.venv/bin/python"
RUNS="${SENTINEL_RUNS_DIR:-$ROOT/.sentinel-runs}"
PLAN_DIR="$ROOT/plans/260730-1018-sentinel-fresh-bounded-live-acceptance-closure"
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

safe_operator_parent_chain() {
  local path=$1 parent owner mode
  [[ "$path" == /* && "$path" != *'//' && "$path" != */./* && "$path" != */../* ]] || return 1
  parent=${path%/*}
  [[ -n "$parent" ]] || parent=/
  while :; do
    [[ -d "$parent" && ! -L "$parent" ]] || return 1
    owner=$(stat -c '%u' "$parent") || return 1
    mode=$(stat -c '%a' "$parent") || return 1
    [[ "$owner" == "$(id -u)" || "$owner" == 0 ]] || return 1
    if (( (8#$mode & 022) != 0 )); then
      # A root-owned sticky directory such as /tmp cannot be used by another
      # UID to replace an existing operator-owned entry. All other writable
      # ancestors would allow a pathname replacement before adapter execution.
      [[ "$owner" == 0 ]] && (( (8#$mode & 01000) != 0 )) || return 1
    fi
    [[ "$parent" == / ]] && return 0
    parent=${parent%/*}
    [[ -n "$parent" ]] || parent=/
  done
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
  [[ -z "${SENTINEL_CHARTER_EXECUTOR_SECRET:-}" && -z "${SENTINEL_CHARTER_EXECUTOR_API_KEY:-}" ]] \
    && pass controller-secret-boundary || block controller-secret-boundary
  if [[ -n "${SENTINEL_LITELLM_ALIAS:-}" ]] \
      && grep -Eq "^[[:space:]]*(-[[:space:]]*)?model_name:[[:space:]]*${SENTINEL_LITELLM_ALIAS}[[:space:]]*(#.*)?$" \
        "$ROOT/infra/litellm/config.yaml"; then
    pass model-alias-config
  else
    block model-alias-config
  fi
}

check_scanner_selector() {
  local reason
  reason="$(SCANNERS_DIR="$ROOT/scanners" "$ROOT/scripts/scan-and-import.sh" charter-selector-status 2>/dev/null)" || true
  if [[ "$reason" == admitted ]]; then
    pass scanner-selector
  else
    block scanner-selector
    case "$reason" in
      legacy-selector|conflicting-selectors|invalid-image-digest|missing-image-policy|unreadable-image-policy|missing-image-policy-pin|image-policy-mismatch|missing-selector|unsafe-local-binary|unregistered-local-binary)
        printf 'INFO scanner-selector-reason %s\n' "$reason"
        ;;
      *)
        printf '%s\n' 'INFO scanner-selector-reason selector-unavailable'
        ;;
    esac
  fi
}

check_operator_boundary() {
  local public_key="${SENTINEL_CHARTER_PUBLIC_KEY:-}"
  local public_key_sha256="${SENTINEL_CHARTER_PUBLIC_KEY_SHA256:-}"
  local adapter="${SENTINEL_CHARTER_EXECUTOR_ADAPTER:-}"
  [[ -n "$public_key" ]] && regular_not_writable_by_others "$public_key" && safe_operator_parent_chain "$public_key" && pass approval-public-key-path \
    || block approval-public-key-path
  [[ -n "$adapter" ]] && private_regular "$adapter" 700 && safe_operator_parent_chain "$adapter" && pass executor-adapter-boundary \
    || block executor-adapter-boundary
  [[ "$public_key_sha256" =~ ^[0-9a-f]{64}$ ]] \
    && PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON" - "$public_key" "$public_key_sha256" <<'PY' >/dev/null 2>&1 \
    && pass approval-public-key-fingerprint || block approval-public-key-fingerprint
import hashlib
import os
import stat
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

path, expected = sys.argv[1:]

def safe_parents(path):
    if not os.path.isabs(path) or "//" in path or "/./" in path or "/../" in path:
        raise SystemExit(1)
    parent = os.path.dirname(path) or os.sep
    while True:
        item = os.lstat(parent)
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
            raise SystemExit(1)
        mode = stat.S_IMODE(item.st_mode)
        if item.st_uid not in (os.geteuid(), 0):
            raise SystemExit(1)
        if mode & 0o022 and not (item.st_uid == 0 and mode & stat.S_ISVTX):
            raise SystemExit(1)
        if parent == os.sep:
            return
        parent = os.path.dirname(parent) or os.sep

safe_parents(path)
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
  local run_id=$1 approval="${SENTINEL_CHARTER_APPROVAL_FILE:-}" public_key="${SENTINEL_CHARTER_PUBLIC_KEY:-}"
  [[ -n "$approval" ]] && private_regular "$approval" 600 \
    || { block signed-approval; return; }
  PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON" - "$RUNS" "$run_id" "$approval" "$public_key" <<'PY' >/dev/null 2>&1 \
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
