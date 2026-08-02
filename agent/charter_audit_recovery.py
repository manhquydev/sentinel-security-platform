"""Fail-closed durable-state helpers for the bounded Kong audit recovery path."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

from .charter_receipt import ReceiptContractError, decode_object, validate_audit
from .charter_requests import CharterRequestError, RequestStore, load_spec, parse_kong_file_log

_NORMAL_ARTIFACTS = (
    "receipt.json",
    "request-descriptor.json",
    "request.json",
    "artifact-bindings.json",
    "charter-evaluation.json",
)
_AUDIT_ARTIFACTS = (
    "audit-recovery.json",
    "audit-recovery-report.json",
    "audit-evaluation.json",
)


class AuditRecoveryError(RuntimeError):
    """Recovery evidence is incomplete, inconsistent, or unsafe to continue."""


def _regular_bytes(path: Path, *, nonempty: bool = True) -> bytes:
    try:
        item = path.lstat()
    except OSError as exc:
        raise AuditRecoveryError(f"missing private recovery state: {path.name}") from exc
    if (stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode)
            or stat.S_IMODE(item.st_mode) != 0o600):
        raise AuditRecoveryError(f"unsafe private recovery state: {path.name}")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise AuditRecoveryError(f"unreadable private recovery state: {path.name}") from exc
    try:
        if not os.path.samestat(item, os.fstat(fd)):
            raise AuditRecoveryError(f"raced private recovery state: {path.name}")
        chunks: list[bytes] = []
        while part := os.read(fd, 65536):
            chunks.append(part)
    finally:
        os.close(fd)
    value = b"".join(chunks)
    if nonempty and not value:
        raise AuditRecoveryError(f"empty private recovery state: {path.name}")
    return value


def _json_document(path: Path) -> object:
    try:
        return decode_object(_regular_bytes(path))
    except (ReceiptContractError, UnicodeDecodeError) as exc:
        raise AuditRecoveryError(f"invalid private recovery state: {path.name}") from exc


def _manifest_and_spec(run_dir: Path) -> tuple[dict, object]:
    try:
        manifest = json.loads(_regular_bytes(run_dir / "manifest.json").decode("utf-8"))
        spec = load_spec(_json_document(run_dir / "request-spec.json"))
    except (UnicodeDecodeError, json.JSONDecodeError, CharterRequestError) as exc:
        raise AuditRecoveryError("invalid immutable audit recovery inputs") from exc
    if (not isinstance(manifest, dict) or manifest.get("schema_version") != "sentinel-run/v2"
            or manifest.get("input", {}).get("source") != "local"
            or manifest.get("result", {}).get("status") != "failed"
            or manifest.get("stages", {}).get("executor", {}).get("status") != "failed"):
        raise AuditRecoveryError("audit recovery requires a failed local v2 executor")
    order, stages = manifest.get("stage_order"), manifest.get("stages")
    if (not isinstance(order, list) or len(order) < 8 or order[7] != "executor"
            or not isinstance(stages, dict) or len(stages) != 8
            or any(stages.get(name, {}).get("status") != "passed" for name in order[:7])):
        raise AuditRecoveryError("audit recovery requires executor as the first incomplete boundary")
    return manifest, spec


def _stranded_effect(manifest: dict, spec_path: Path) -> None:
    events = manifest.get("effect_ledger")
    if not isinstance(events, list) or not events:
        raise AuditRecoveryError("audit recovery requires a stranded executor effect")
    prepared = events[-1]
    unknown = None
    if prepared.get("state") == "unknown":
        if len(events) < 2:
            raise AuditRecoveryError("audit recovery requires a prepared executor effect")
        unknown = prepared
        prepared = events[-2]
    elif prepared.get("state") != "prepared":
        raise AuditRecoveryError("audit recovery requires a stranded executor effect")
    expected_digest = hashlib.sha256(_regular_bytes(spec_path)).hexdigest()
    if (prepared.get("stage") != "executor" or prepared.get("effect") != "charter-request"
            or prepared.get("state") != "prepared"
            or prepared.get("intent_path") != "request-spec.json"
            or prepared.get("intent_sha256") != expected_digest):
        raise AuditRecoveryError("audit recovery request binding mismatch")
    if unknown is not None and (
            unknown.get("stage") != prepared.get("stage")
            or unknown.get("effect") != prepared.get("effect")
            or unknown.get("intent_path") != prepared.get("intent_path")
            or unknown.get("intent_sha256") != prepared.get("intent_sha256")):
        raise AuditRecoveryError("audit recovery request binding mismatch")


def _request_row(run_dir: Path, request_id: str) -> tuple[str, str | None]:
    path = run_dir / "executor-state.sqlite"
    try:
        item = path.lstat()
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode) or item.st_size == 0:
            raise AuditRecoveryError("unsafe audit recovery SQLite state")
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            row = connection.execute(
                "SELECT state, receipt_digest FROM requests WHERE id=?", (request_id,)
            ).fetchone()
            events = {
                item[0] for item in connection.execute(
                    "SELECT state FROM events WHERE id=?", (request_id,)
                ).fetchall()
            }
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise AuditRecoveryError("unreadable audit recovery SQLite state") from exc
    if (not row or row[0] not in {"unknown", "terminal"}
            or row[0] not in events):
        raise AuditRecoveryError("audit recovery request is not durable")
    return row


def _audit(run_dir: Path, spec: object) -> tuple[dict, bytes]:
    raw = _regular_bytes(run_dir / "audit-recovery.json")
    try:
        value = validate_audit(decode_object(raw), spec)
    except ReceiptContractError as exc:
        raise AuditRecoveryError("invalid durable audit recovery artifact") from exc
    return value, raw


def _limited_artifacts(run_dir: Path, audit: dict, audit_bytes: bytes) -> None:
    audit_digest = hashlib.sha256(audit_bytes).hexdigest()
    expected_report = {
        "schema_version": "sentinel-audit-recovery-report/v1",
        "request_id": audit["request_id"],
        "audit_sha256": audit_digest,
        "limitation": "gateway-transit-status-only",
    }
    expected_evaluation = {
        "schema_version": "sentinel-audit-evaluation/v1",
        "request_id": audit["request_id"],
        "audit_sha256": audit_digest,
        "result": "limited",
        "limitation": "not-a-receipt-or-response-guard-evaluation",
    }
    if (_json_document(run_dir / "audit-recovery-report.json") != expected_report
            or _json_document(run_dir / "audit-evaluation.json") != expected_evaluation):
        raise AuditRecoveryError("audit recovery limited artifacts are not digest-bound")


def state(run_dir: Path) -> str:
    """Classify the only recoverable durable states before any source acquisition."""
    manifest, spec = _manifest_and_spec(run_dir)
    _stranded_effect(manifest, run_dir / "request-spec.json")
    if any((run_dir / name).exists() or (run_dir / name).is_symlink() for name in _NORMAL_ARTIFACTS):
        raise AuditRecoveryError("normal executor artifacts prohibit audit recovery")
    present = {name for name in _AUDIT_ARTIFACTS if (run_dir / name).exists() or (run_dir / name).is_symlink()}
    row = _request_row(run_dir, spec.request_id)
    if not present:
        if row[0] != "unknown":
            raise AuditRecoveryError("missing audit artifact cannot follow terminal SQLite state")
        return "none"
    if "audit-recovery.json" not in present:
        raise AuditRecoveryError("limited recovery artifact exists without its audit artifact")
    audit, audit_bytes = _audit(run_dir, spec)
    if present == {"audit-recovery.json"}:
        if row[0] == "unknown":
            return "audit-artifact-durable"
        if row == ("terminal", audit["source_digest"]):
            return "sqlite-terminal"
        raise AuditRecoveryError("audit artifact durable state does not match SQLite")
    if present != set(_AUDIT_ARTIFACTS):
        raise AuditRecoveryError("partial audit recovery artifacts are fail-closed")
    if row != ("terminal", audit["source_digest"]):
        raise AuditRecoveryError("audit artifact does not match terminal SQLite state")
    _limited_artifacts(run_dir, audit, audit_bytes)
    return "limited-artifacts-complete"


def acquire(run_dir: Path, recovery_started_at_ms: int) -> str:
    """Acquire the fixed source into process memory and return only sanitized JSON."""
    manifest, spec = _manifest_and_spec(run_dir)
    if state(run_dir) != "none":
        raise AuditRecoveryError("fixed source acquisition requires empty durable audit state")
    if type(recovery_started_at_ms) is not int or recovery_started_at_ms < manifest["created_at_ms"]:
        raise AuditRecoveryError("invalid audit recovery timestamp")
    completed = subprocess.run(
        ("docker", "logs", "sentinel-kong"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode != 0:
        raise AuditRecoveryError("fixed Kong audit source is unavailable")
    store = RequestStore(str(run_dir / "executor-state.sqlite"))
    try:
        candidate = store.audit_candidate(
            spec.request_id,
            parse_kong_file_log(completed.stdout),
            created_at_ms=manifest["created_at_ms"],
            recovery_started_at_ms=recovery_started_at_ms,
        )
    except CharterRequestError as exc:
        raise AuditRecoveryError("fixed Kong audit source did not prove exactly one bounded request") from exc
    finally:
        store.close()
    audit = validate_audit({
        "schema_version": "sentinel-charter-audit/v1",
        "request_id": candidate["request_id"],
        "status": candidate["status"],
        "started_at": candidate["started_at"],
        "manifest_created_at_ms": manifest["created_at_ms"],
        "recovery_started_at_ms": recovery_started_at_ms,
        "source": "docker-logs-sentinel-kong",
        "source_digest": candidate["source_digest"],
    }, spec)
    return json.dumps(audit, sort_keys=True, separators=(",", ":"))


def terminalize(run_dir: Path) -> None:
    """Settle SQLite from a previously durable, validated audit artifact only."""
    if state(run_dir) != "audit-artifact-durable":
        raise AuditRecoveryError("SQLite terminalization requires only the durable audit artifact")
    _, spec = _manifest_and_spec(run_dir)
    audit, _ = _audit(run_dir, spec)
    store = RequestStore(str(run_dir / "executor-state.sqlite"))
    try:
        store.terminalize_audit_projection(spec.request_id, audit["source_digest"])
    finally:
        store.close()


def main(args: list[str]) -> None:
    if len(args) == 2 and args[0] == "state":
        print(state(Path(args[1])))
        return
    if len(args) == 3 and args[0] == "acquire":
        print(acquire(Path(args[1]), int(args[2])))
        return
    if len(args) == 2 and args[0] == "terminalize":
        terminalize(Path(args[1]))
        return
    raise SystemExit("usage: charter_audit_recovery.py state|acquire|terminalize RUN_DIR [RECOVERY_STARTED_AT_MS]")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (AuditRecoveryError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
