"""Append-only metadata ledger for deterministic arm executions."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping

from .artifacts import ArtifactViolation, PrivateArtifactStore


class LedgerViolation(ValueError):
    """Raised when an append-only run ledger would be rewritten or leak data."""


class RunLedger:
    def __init__(self, path: Path | str, artifacts: PrivateArtifactStore) -> None:
        self._path = Path(path).resolve()
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self._path.parent.is_symlink() or self._path.parent.stat().st_mode & 0o077:
            raise LedgerViolation("run ledger parent must be private")
        self._artifacts = artifacts

    def append(self, run_id: str, record: Mapping[str, object]) -> None:
        try:
            self._artifacts._assert_metadata_only(record)
        except ArtifactViolation as error:
            raise LedgerViolation("run ledger accepts metadata-only records") from error
        if not isinstance(run_id, str) or not run_id:
            raise LedgerViolation("run ledger requires a run ID")
        existing_ids: set[str] = set()
        if self._path.exists():
            for line in self._path.read_text(encoding="utf-8").splitlines():
                if not line:
                    continue
                try:
                    existing_ids.add(str(json.loads(line)["record_id"]))
                except (KeyError, TypeError, json.JSONDecodeError) as error:
                    raise LedgerViolation("run ledger contains a malformed historical record") from error
        record_id = record.get("record_id")
        if not isinstance(record_id, str) or not record_id or record_id in existing_ids:
            raise LedgerViolation("run ledger records are immutable and uniquely identified")
        payload = {"run_id": run_id, **dict(record)}
        descriptor = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, "ab") as handle:
            handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
