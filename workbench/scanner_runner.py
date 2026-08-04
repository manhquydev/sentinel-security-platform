"""Fixture-only scanner runner topology.

The runner accepts a sealed snapshot ID, never a source path.  It emits only
fixed Docker argv for an already admitted scanner manifest; execution and raw
artifact retention remain host-owned.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Mapping

from .normalize import NormalizationViolation, normalize_codeql, normalize_semgrep, normalize_trivy
from .scanner_contracts import ScannerCapabilityManifest
from .sealed_store import SealedFixtureStore, SealedStoreViolation


class RunnerViolation(ValueError):
    """Raised when a fixture scanner command cannot be safely constructed."""


class FixtureScannerRunner:
    """Build source-isolated commands for a registered fixture snapshot."""

    def __init__(
        self,
        store: SealedFixtureStore,
        capability: ScannerCapabilityManifest,
        prepared_dependency_root: Path | str,
        raw_artifact_root: Path | str,
    ):
        self._store = store
        self._capability = capability
        self._prepared_dependency_root = Path(prepared_dependency_root).resolve()
        if (
            self._prepared_dependency_root.is_symlink()
            or not self._prepared_dependency_root.is_dir()
            or self._prepared_dependency_root.stat().st_mode & 0o077
        ):
            raise RunnerViolation("prepared dependency root must be a private host-owned directory")
        self._raw_artifact_root = Path(raw_artifact_root).resolve()
        self._raw_artifact_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if (
            self._raw_artifact_root.is_symlink()
            or not self._raw_artifact_root.is_dir()
            or self._raw_artifact_root.stat().st_mode & 0o077
        ):
            raise RunnerViolation("raw artifact root must be a private host-owned directory")

    def command_for(self, engine: str, snapshot_id: str) -> tuple[str, ...]:
        if not isinstance(snapshot_id, str):
            raise TypeError("snapshot_id must be a registered digest, not a source path")
        if snapshot_id != self._capability.snapshot_id:
            raise RunnerViolation("snapshot is not the one admitted by this capability manifest")
        try:
            snapshot = self._store.resolve(snapshot_id)
        except SealedStoreViolation as error:
            raise RunnerViolation("scanner input must resolve to an intact sealed fixture") from error
        try:
            item = self._capability.engine(engine)
        except Exception as error:
            raise RunnerViolation("scanner engine is not admitted") from error
        # Exact fixed Docker prefix: every process with the sealed source mount
        # has no network, and no worker command mounts the Docker socket.
        common = (
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{snapshot.root}:/src:ro",
        )
        dependency_root = self._prepared_dependency_root / item.engine / item.acquisition_digest
        if (
            dependency_root.is_symlink()
            or not dependency_root.is_dir()
            or dependency_root.stat().st_mode & 0o077
        ):
            raise RunnerViolation("prepared source-less scanner dependency is not privately registered")
        required_prepared = (
            ("query-suite.qls", "query-pack")
            if item.engine == "codeql"
            else ("frozen.yml",)
            if item.engine == "semgrep"
            else ("metadata.json",)
        )
        for name in required_prepared:
            candidate = dependency_root / name
            if candidate.is_symlink() or not candidate.exists():
                raise RunnerViolation("prepared scanner dependency is incomplete")
        if item.engine == "codeql":
            work_directory = self._raw_artifact_root / snapshot_id / "codeql" / item.acquisition_digest
            work_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(work_directory, 0o700)
            return (
                *common,
                "-v",
                f"{dependency_root}:/prepared:ro",
                "-v",
                f"{work_directory}:/work:rw",
                "--entrypoint",
                "/bin/sh",
                item.image,
                "-ceu",
                (
                    "codeql database create /work/database "
                    "--language=javascript-typescript --source-root=/src --command true && "
                    "codeql database analyze /work/database --format=sarif-latest "
                    "--search-path=/prepared/query-pack /prepared/query-suite.qls "
                    "--output /work/report.sarif"
                ),
            )
        if item.engine == "semgrep":
            return (
                *common,
                "-v",
                f"{dependency_root}:/rules:ro",
                item.image,
                "semgrep",
                "scan",
                "--json",
                "--config",
                "/rules/frozen.yml",
                "/src",
            )
        if item.engine == "trivy":
            return (
                *common,
                "-v",
                f"{dependency_root}:/root/.cache/trivy:ro",
                item.image,
                "filesystem",
                "--offline-scan",
                "--skip-db-update",
                "--skip-java-db-update",
                "--format",
                "json",
                "/src",
            )
        raise RunnerViolation("scanner engine is not admitted")

    def capture_raw_artifact(
        self, engine: str, snapshot_id: str, report: Mapping[str, object]
    ) -> dict[str, object]:
        """Quarantine a parse-complete raw report before exposing only metadata."""
        if snapshot_id != self._capability.snapshot_id:
            raise RunnerViolation("raw artifact snapshot is not admitted")
        try:
            self._store.resolve(snapshot_id)
            self._capability.engine(engine)
        except Exception as error:
            raise RunnerViolation("raw artifact engine or snapshot is not admitted") from error
        normalizer = {
            "codeql": lambda value: normalize_codeql(value, source_mount="/src"),
            "semgrep": lambda value: normalize_semgrep(value, source_mount="/src"),
            "trivy": lambda value: normalize_trivy(value, source_mount="/src"),
        }.get(engine)
        if normalizer is None:
            raise RunnerViolation("raw artifact engine is not admitted")
        try:
            normalized = normalizer(report)
        except NormalizationViolation as error:
            raise RunnerViolation("raw artifact cannot be retained as a complete B0 result") from error
        raw = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        target_directory = self._raw_artifact_root / snapshot_id / engine
        target_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(target_directory, 0o700)
        target = target_directory / f"{digest}.json"
        if not target.exists():
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
            except BaseException:
                target.unlink(missing_ok=True)
                raise
        receipt: dict[str, object] = {
            "schema_version": "sentinel-workbench-raw-artifact-transition/v1",
            "engine": engine,
            "snapshot_id": snapshot_id,
            "raw_artifact_digest": digest,
            "reported_count": len(normalized),
            "normalized_count": len(normalized),
            "state": "quarantined-and-reconciled",
        }
        if engine == "codeql":
            database = self._raw_artifact_root / snapshot_id / "codeql" / self._capability.engine(engine).acquisition_digest / "database"
            if (
                not database.is_dir()
                or database.is_symlink()
                or not (database / "codeql-database.yml").is_file()
                or not (database / "db-javascript").is_dir()
            ):
                raise RunnerViolation("CodeQL database completion evidence is absent")
            receipt["database_digest"] = self._tree_digest(database)
        return receipt

    @staticmethod
    def _tree_digest(root: Path) -> str:
        files: list[dict[str, object]] = []
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
            if path.is_symlink() or not path.is_file():
                if path.is_symlink():
                    raise RunnerViolation("CodeQL database contains a symbolic link")
                continue
            relative = path.relative_to(root).as_posix()
            files.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "bytes": path.stat().st_size,
                }
            )
        if not files:
            raise RunnerViolation("CodeQL database completion evidence is empty")
        return hashlib.sha256(
            json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
