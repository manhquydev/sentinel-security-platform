"""Fixture-only scanner runner topology.

The runner accepts a sealed snapshot ID, never a source path.  It emits only
fixed Docker argv for an already admitted scanner manifest; execution and raw
artifact retention remain host-owned.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Mapping

from .normalize import NormalizationViolation, normalize_codeql, normalize_semgrep, normalize_trivy
from .scanner_contracts import ScannerCapabilityManifest
from .sealed_store import SealedFixtureStore, SealedStoreViolation


class RunnerViolation(ValueError):
    """Raised when a fixture scanner command cannot be safely constructed."""


_TRIVY_DB_SNAPSHOT_SCHEMA = "sentinel-workbench-trivy-db-snapshot/v1"
_MAX_PREPARED_METADATA_BYTES = 16 * 1024


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
            else ("metadata.json", "cache")
        )
        for name in required_prepared:
            candidate = dependency_root / name
            if candidate.is_symlink() or not candidate.exists():
                raise RunnerViolation("prepared scanner dependency is incomplete")
        if item.engine == "trivy":
            self._verify_trivy_db_snapshot(
                dependency_root,
                item.acquisition["db_snapshot_digest"],
            )
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
                    # Pinned MCR image is CodeQL 2.15.x: language id is `javascript`
                    # (covers JS/TS). Actions packs are not prepared from that image.
                    "codeql database create "
                    "--language=javascript --source-root=/src "
                    "-- /work/database && "
                    "codeql database analyze --format=sarif-latest "
                    "--output=/work/javascript.sarif "
                    "--search-path=/prepared/query-pack -- "
                    "/work/database /prepared/query-suite.qls"
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
                f"{dependency_root / 'cache'}:/root/.cache/trivy:ro",
                item.image,
                "filesystem",
                "--scanners",
                "vuln,misconfig,secret",
                "--offline-scan",
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
                "--skip-version-check",
                "--disable-telemetry",
                "--format",
                "json",
                "/src",
            )
        raise RunnerViolation("scanner engine is not admitted")

    @staticmethod
    def _verify_trivy_db_snapshot(dependency_root: Path, expected_digest: str) -> None:
        """Require a private canonical manifest for the prepared offline DB."""
        metadata_path = dependency_root / "metadata.json"
        try:
            descriptor = os.open(
                metadata_path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError as error:
            raise RunnerViolation("prepared scanner dependency is incomplete") from error
        try:
            metadata_stat = os.fstat(descriptor)
            if not stat.S_ISREG(metadata_stat.st_mode) or metadata_stat.st_mode & 0o077:
                raise RunnerViolation("prepared Trivy database metadata must be private and regular")
            handle = os.fdopen(descriptor, "rb")
            descriptor = -1
            with handle:
                raw = handle.read(_MAX_PREPARED_METADATA_BYTES + 1)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if len(raw) > _MAX_PREPARED_METADATA_BYTES:
            raise RunnerViolation("prepared Trivy database metadata is too large")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RunnerViolation("prepared Trivy database metadata is not canonical") from error
        if not isinstance(value, dict) or set(value) != {"schema_version", "db_snapshot_digest"}:
            raise RunnerViolation("prepared Trivy database metadata is not canonical")
        if value["schema_version"] != _TRIVY_DB_SNAPSHOT_SCHEMA or not isinstance(
            value["db_snapshot_digest"], str
        ):
            raise RunnerViolation("prepared Trivy database metadata is not canonical")
        canonical = (
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            + b"\n"
        )
        if raw != canonical:
            raise RunnerViolation("prepared Trivy database metadata is not canonical")
        if value["db_snapshot_digest"] != expected_digest:
            raise RunnerViolation("prepared Trivy database metadata does not match the admitted DB snapshot")
        if FixtureScannerRunner._private_tree_digest(
            dependency_root / "cache", "prepared Trivy database cache"
        ) != expected_digest:
            raise RunnerViolation("prepared Trivy database cache does not match the admitted DB snapshot")

    @staticmethod
    def _private_tree_digest(root: Path, label: str) -> str:
        """Hash a non-empty private regular-file tree without following links."""
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        try:
            root_descriptor = os.open(root, flags)
        except OSError as error:
            raise RunnerViolation(f"{label} is absent or unsafe") from error
        files: list[dict[str, object]] = []

        def hash_regular_file(directory_descriptor: int, name: str, relative: str) -> None:
            try:
                descriptor = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_descriptor,
                )
            except OSError as error:
                raise RunnerViolation(f"{label} contains an unsafe file") from error
            try:
                file_stat = os.fstat(descriptor)
                if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_mode & 0o077:
                    raise RunnerViolation(f"{label} contains a non-private or non-regular file")
                handle = os.fdopen(descriptor, "rb")
                descriptor = -1
                with handle:
                    file_hash = hashlib.sha256()
                    total_bytes = 0
                    while chunk := handle.read(1024 * 1024):
                        file_hash.update(chunk)
                        total_bytes += len(chunk)
                files.append({"path": relative, "sha256": file_hash.hexdigest(), "bytes": total_bytes})
            finally:
                if descriptor >= 0:
                    os.close(descriptor)

        def visit(directory_descriptor: int, relative_root: str) -> None:
            directory_stat = os.fstat(directory_descriptor)
            if not stat.S_ISDIR(directory_stat.st_mode) or directory_stat.st_mode & 0o077:
                raise RunnerViolation(f"{label} contains a non-private or non-directory entry")
            for name in sorted(os.listdir(directory_descriptor)):
                relative = f"{relative_root}/{name}" if relative_root else name
                try:
                    entry_stat = os.stat(
                        name, dir_fd=directory_descriptor, follow_symlinks=False
                    )
                except OSError as error:
                    raise RunnerViolation(f"{label} contains an unreadable entry") from error
                if stat.S_ISLNK(entry_stat.st_mode):
                    raise RunnerViolation(f"{label} contains a symbolic link")
                if stat.S_ISREG(entry_stat.st_mode):
                    hash_regular_file(directory_descriptor, name, relative)
                    continue
                if not stat.S_ISDIR(entry_stat.st_mode):
                    raise RunnerViolation(f"{label} contains a non-regular entry")
                try:
                    child_descriptor = os.open(
                        name,
                        flags,
                        dir_fd=directory_descriptor,
                    )
                except OSError as error:
                    raise RunnerViolation(f"{label} contains an unsafe directory") from error
                try:
                    visit(child_descriptor, relative)
                finally:
                    os.close(child_descriptor)

        try:
            visit(root_descriptor, "")
        finally:
            os.close(root_descriptor)
        if not files:
            raise RunnerViolation(f"{label} is empty")
        return hashlib.sha256(
            json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

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
            database = (
                self._raw_artifact_root
                / snapshot_id
                / "codeql"
                / self._capability.engine(engine).acquisition_digest
                / "database"
            )
            # CodeQL 2.15 single-language DB: manifest + non-empty db-javascript extract.
            member_manifest = database / "codeql-database.yml"
            member_database = database / "db-javascript"
            extract_files = (
                [
                    path
                    for path in member_database.rglob("*")
                    if path.is_file() and not path.is_symlink()
                ]
                if member_database.is_dir() and not member_database.is_symlink()
                else []
            )
            if (
                not database.is_dir()
                or database.is_symlink()
                or not member_manifest.is_file()
                or member_manifest.is_symlink()
                or not member_database.is_dir()
                or member_database.is_symlink()
                or not extract_files
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
