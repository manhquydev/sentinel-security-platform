"""Private run evidence retention with source-free reproducibility bundles."""
from __future__ import annotations

import json
import os
import re
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Mapping

from agent import pii
from infra.litellm.guardrails import egress_redaction


class ArtifactViolation(ValueError):
    """Raised when an artifact would expose source/secret material or unsafe deletion."""


_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_FORBIDDEN_KEYS = {
    "source",
    "source_text",
    "raw_provider_body",
    "provider_body",
    "prompt",
    "response",
    "secret",
    "token",
    "key",
    "credential",
}
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$")
_SAFE_STRING_KEYS = {
    "schema_version",
    "run_id",
    "owner",
    "terminal_state",
    "finished_at",
    "route_id",
    "profile",
    "arm",
    "status",
    "command_id",
    "attempt_id",
    "record_id",
    "pair_id",
    "snapshot_id",
    "repository_identity",
    "repository_id",
    "kind",
    "reason_code",
}


class PrivateArtifactStore:
    """Maintain owner-marked 0700 runs and 0600 metadata-only records."""

    def __init__(self, evidence_root: Path | str) -> None:
        self._root = Path(evidence_root).resolve()
        self._runs = self._root / "runs"
        self._bundles = self._root / "reproducibility"
        for path in (self._root, self._runs, self._bundles):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            if path.is_symlink() or not path.is_dir():
                raise ArtifactViolation("private artifact root is invalid")
            os.chmod(path, 0o700)

    def begin_run(self, run_id: str) -> str:
        if not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None:
            raise ArtifactViolation("run ID must be labelled")
        root = self.run_path(run_id)
        if root.exists():
            raise ArtifactViolation("run ownership marker already exists")
        root.mkdir(mode=0o700)
        marker = {
            "schema_version": "sentinel-workbench-private-run/v1",
            "run_id": run_id,
            "owner": "local-workbench-os-identity",
            "terminal_state": None,
            "finished_at": None,
            "retention_days": 30,
        }
        self._write_private_json(root / "ownership.json", marker)
        return run_id

    def run_path(self, run_id: str) -> Path:
        if not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None:
            raise ArtifactViolation("run ID must be labelled")
        return self._runs / run_id

    def write_record(self, run_id: str, kind: str, record: Mapping[str, object]) -> Path:
        if not isinstance(kind, str) or _RUN_ID.fullmatch(kind) is None:
            raise ArtifactViolation("artifact kind must be labelled")
        root = self._require_owned_run(run_id)
        self._assert_metadata_only(record)
        target = root / f"{kind}.json"
        if target.exists():
            raise ArtifactViolation("artifact record is immutable")
        self._write_private_json(target, dict(record))
        return target

    def mark_terminal(self, run_id: str, state: str, *, finished_at: datetime | None = None) -> None:
        if state not in {"succeeded", "failed", "unknown", "cancelled"}:
            raise ArtifactViolation("terminal state is invalid")
        root = self._require_owned_run(run_id)
        marker_path = root / "ownership.json"
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        if marker.get("terminal_state") is not None:
            raise ArtifactViolation("run is already terminal")
        timestamp = finished_at or datetime.now(UTC)
        if timestamp.tzinfo is None:
            raise ArtifactViolation("terminal timestamp must be timezone-aware")
        marker["terminal_state"] = state
        marker["finished_at"] = timestamp.astimezone(UTC).isoformat()
        self._replace_private_json(marker_path, marker)

    def build_reproducibility_bundle(self, run_id: str) -> Path:
        root = self._require_owned_run(run_id)
        entries: dict[str, object] = {}
        for artifact in sorted(root.glob("*.json")):
            if artifact.name == "ownership.json":
                continue
            document = json.loads(artifact.read_text(encoding="utf-8"))
            self._assert_metadata_only(document)
            entries[artifact.name] = document
        target = self._bundles / f"{run_id}.json"
        if target.exists():
            raise ArtifactViolation("reproducibility bundle is immutable")
        self._write_private_json(target, {"schema_version": "sentinel-workbench-repro-bundle/v1", "run_id": run_id, "records": entries})
        return target

    def delete_expired(self, run_id: str, *, now: datetime) -> bool:
        root = self._require_owned_run(run_id)
        marker = json.loads((root / "ownership.json").read_text(encoding="utf-8"))
        if marker.get("run_id") != run_id or marker.get("owner") != "local-workbench-os-identity":
            raise ArtifactViolation("run ownership marker does not permit deletion")
        finished = marker.get("finished_at")
        if marker.get("terminal_state") is None or not isinstance(finished, str):
            raise ArtifactViolation("only a terminal owned run can be deleted")
        expiry = datetime.fromisoformat(finished) + timedelta(days=30)
        if now.tzinfo is None or now < expiry:
            return False
        for path in root.rglob("*"):
            if path.is_symlink():
                raise ArtifactViolation("owned run contains a symbolic link")
        shutil.rmtree(root)
        return True

    def _require_owned_run(self, run_id: str) -> Path:
        root = self.run_path(run_id)
        if root.is_symlink() or not root.is_dir() or root.parent != self._runs:
            raise ArtifactViolation("owned run is absent or invalid")
        marker = root / "ownership.json"
        if not marker.is_file() or marker.is_symlink():
            raise ArtifactViolation("owned run marker is absent")
        return root

    @staticmethod
    def _assert_metadata_only(value: object) -> None:
        def inspect(item: object, *, key: str | None = None) -> None:
            if isinstance(item, Mapping):
                for child_key, child in item.items():
                    if not isinstance(child_key, str):
                        raise ArtifactViolation("artifact keys must be strings")
                    lowered = child_key.lower()
                    if (
                        lowered in _FORBIDDEN_KEYS
                        or lowered.startswith(("raw_", "source_", "provider_"))
                        or lowered.endswith(("_source", "_secret", "_token", "_key", "_credential"))
                    ):
                        raise ArtifactViolation("artifact record contains a prohibited raw material field")
                    inspect(child, key=child_key)
            elif isinstance(item, list):
                for child in item:
                    inspect(child, key=key)
            elif isinstance(item, str):
                if key is None:
                    raise ArtifactViolation("artifact strings require a labelled field")
                if key.endswith("_digest") or (
                    key.endswith("_id") and re.fullmatch(r"[0-9a-f]{64}", item) is not None
                ):
                    if re.fullmatch(r"[0-9a-f]{64}", item) is None:
                        raise ArtifactViolation("artifact digest-like identifier is invalid")
                    return
                if key not in _SAFE_STRING_KEYS or _SAFE_LABEL.fullmatch(item) is None:
                    raise ArtifactViolation("artifact record contains unbounded text")
                try:
                    secret_redacted, secret_findings = egress_redaction.redact(item)
                    pii_redacted, pii_findings = pii.redact(secret_redacted)
                except Exception as error:
                    raise ArtifactViolation("artifact redaction validation failed closed") from error
                if secret_redacted != item or pii_redacted != item or secret_findings or pii_findings:
                    raise ArtifactViolation("artifact record contains sensitive raw material")
            elif not isinstance(item, (str, int, float, bool, type(None))):
                raise ArtifactViolation("artifact record has an unsupported value")

        inspect(value)

    @staticmethod
    def _write_private_json(path: Path, value: Mapping[str, object]) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")
            handle.flush()
            os.fsync(handle.fileno())

    @staticmethod
    def _replace_private_json(path: Path, value: Mapping[str, object]) -> None:
        temporary = path.with_suffix(".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            os.chmod(path, 0o600)
        finally:
            temporary.unlink(missing_ok=True)
