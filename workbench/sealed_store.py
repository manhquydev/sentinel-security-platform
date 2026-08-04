"""Private, fixture-only repository snapshots for the workbench."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class SealedStoreViolation(ValueError):
    """Raised when a snapshot is not a registered, intact sealed fixture."""


_SCHEMA_VERSION = "sentinel-workbench-repository-snapshot/v1"
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_FIXTURE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


@dataclass(frozen=True)
class SealedSnapshot:
    """A verified fixture copy registered under its content digest."""

    snapshot_id: str
    root: Path
    manifest_path: Path
    fixture_id: str


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST_RE.fullmatch(value) is not None


def _is_private(mode: int) -> bool:
    return mode & 0o077 == 0


class SealedFixtureStore:
    """Issue and resolve only copied, read-only fixture snapshots.

    A snapshot ID is a digest of its canonical file manifest.  Resolution does
    not accept a caller-provided directory, which prevents a scanner or graph
    runner from falling back to the mutable original fixture.
    """

    def __init__(self, evidence_root: Path | str, fixture_root: Path | str):
        self.evidence_root = Path(evidence_root).resolve()
        self.fixture_root = Path(fixture_root).resolve()
        if not self.fixture_root.is_dir() or self.fixture_root.is_symlink():
            raise SealedStoreViolation("fixture_root must be an existing non-symlink directory")

        self._mkdir_private(self.evidence_root)
        self._snapshots = self.evidence_root / "snapshots"
        self._manifests = self.evidence_root / "manifests"
        self._staging = self.evidence_root / ".staging"
        for directory in (self._snapshots, self._manifests, self._staging):
            self._mkdir_private(directory)

    def seal_fixture(self, source: Path | str, *, fixture_id: str) -> SealedSnapshot:
        """Copy a registered fixture into the private evidence root and register it."""
        if not isinstance(fixture_id, str) or _FIXTURE_ID_RE.fullmatch(fixture_id) is None:
            raise SealedStoreViolation("fixture_id must be a short labelled identifier")
        source_root = Path(source)
        if source_root.is_symlink() or not source_root.is_dir():
            raise SealedStoreViolation("fixture source must be a non-symlink directory")
        source_root = source_root.resolve()
        if not source_root.is_relative_to(self.fixture_root):
            raise SealedStoreViolation("only paths below fixture_root may be sealed")
        if source_root != self.fixture_root / fixture_id:
            raise SealedStoreViolation("fixture source must be the registered fixture_id directory")

        temporary_snapshot = Path(tempfile.mkdtemp(prefix="seal-", dir=self._staging))
        temporary_root = temporary_snapshot / "source"
        try:
            files = self._copy_fixture(source_root, temporary_root)
            if not files:
                raise SealedStoreViolation("fixture source must contain at least one regular file")
            payload = {
                "schema_version": _SCHEMA_VERSION,
                "fixture_id": fixture_id,
                "files": files,
            }
            snapshot_id = _canonical_digest(payload)
            manifest = {
                "schema_version": _SCHEMA_VERSION,
                "snapshot_id": snapshot_id,
                "fixture_id": fixture_id,
                "root_digest": snapshot_id,
                "file_count": len(files),
                "files": files,
            }
            self._make_tree_read_only(temporary_root)

            registered_root = self._snapshots / snapshot_id
            if registered_root.exists():
                self._discard_temporary(temporary_snapshot)
                return self.resolve(snapshot_id)
            os.replace(temporary_snapshot, registered_root)
            os.chmod(registered_root, 0o500)

            try:
                self._register_manifest(snapshot_id, manifest)
            except FileExistsError:
                return self.resolve(snapshot_id)
            return self.resolve(snapshot_id)
        except BaseException:
            if temporary_snapshot.exists():
                self._discard_temporary(temporary_snapshot)
            raise

    def resolve(self, snapshot_id: str) -> SealedSnapshot:
        """Verify a registered snapshot and return its sealed copy location."""
        if not _is_digest(snapshot_id):
            raise SealedStoreViolation("snapshot_id must be a lowercase sha256 digest")
        self._require_private_directory(self.evidence_root)
        self._require_private_directory(self._snapshots)
        self._require_private_directory(self._manifests)

        manifest_path = self._manifests / f"{snapshot_id}.json"
        self._require_private_file(manifest_path, read_only=True)
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SealedStoreViolation("registered snapshot manifest is unreadable") from error
        fixture_id, files = self._validate_manifest(snapshot_id, manifest)

        snapshot_root = self._snapshots / snapshot_id
        self._require_private_directory(snapshot_root, read_only=True)
        source_root = snapshot_root / "source"
        self._require_private_directory(source_root, read_only=True)
        self._verify_file_tree(source_root, files)
        return SealedSnapshot(snapshot_id, source_root, manifest_path, fixture_id)

    @staticmethod
    def _mkdir_private(path: Path) -> None:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.is_symlink() or not path.is_dir():
            raise SealedStoreViolation("evidence path must be a directory")
        os.chmod(path, 0o700)

    def _copy_fixture(self, source_root: Path, destination_root: Path) -> list[dict[str, Any]]:
        destination_root.mkdir(mode=0o700)
        files: list[dict[str, Any]] = []
        for source in sorted(source_root.rglob("*"), key=lambda path: path.as_posix()):
            relative = source.relative_to(source_root)
            if source.is_symlink():
                raise SealedStoreViolation(f"fixture source contains a symlink: {relative.as_posix()}")
            destination = destination_root / relative
            if source.is_dir():
                destination.mkdir(mode=0o700)
                continue
            if not source.is_file() or not stat.S_ISREG(source.stat().st_mode):
                raise SealedStoreViolation(f"fixture source contains a non-regular file: {relative.as_posix()}")
            data = source.read_bytes()
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._write_private_file(destination, data)
            files.append({"path": relative.as_posix(), "sha256": _sha256(data), "bytes": len(data)})
        return files

    @staticmethod
    def _write_private_file(path: Path, data: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    @staticmethod
    def _make_tree_read_only(root: Path) -> None:
        for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            if path.is_file():
                os.chmod(path, 0o400)
            elif path.is_dir():
                os.chmod(path, 0o500)
        os.chmod(root, 0o500)

    def _register_manifest(self, snapshot_id: str, manifest: dict[str, Any]) -> None:
        temporary = Path(tempfile.mkstemp(prefix=f".{snapshot_id}.", dir=self._manifests)[1])
        final = self._manifests / f"{snapshot_id}.json"
        try:
            data = json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8") + b"\n"
            with temporary.open("wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o400)
            os.link(temporary, final)
            self._fsync_directory(self._manifests)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _discard_temporary(path: Path) -> None:
        for current_root, directories, filenames in os.walk(path, topdown=False):
            current = Path(current_root)
            for name in filenames:
                os.chmod(current / name, 0o600)
            for name in directories:
                os.chmod(current / name, 0o700)
        os.chmod(path, 0o700)
        shutil.rmtree(path)

    def _validate_manifest(self, snapshot_id: str, manifest: object) -> tuple[str, list[dict[str, Any]]]:
        if not isinstance(manifest, dict) or set(manifest) != {
            "schema_version",
            "snapshot_id",
            "fixture_id",
            "root_digest",
            "file_count",
            "files",
        }:
            raise SealedStoreViolation("snapshot manifest has an invalid shape")
        if manifest["schema_version"] != _SCHEMA_VERSION:
            raise SealedStoreViolation("unsupported snapshot manifest schema_version")
        if manifest["snapshot_id"] != snapshot_id or manifest["root_digest"] != snapshot_id:
            raise SealedStoreViolation("snapshot manifest does not bind to its registry ID")
        fixture_id = manifest["fixture_id"]
        if not isinstance(fixture_id, str) or _FIXTURE_ID_RE.fullmatch(fixture_id) is None:
            raise SealedStoreViolation("snapshot manifest fixture_id is invalid")
        files = manifest["files"]
        if not isinstance(files, list) or not files or manifest["file_count"] != len(files):
            raise SealedStoreViolation("snapshot manifest file count is invalid")
        normalized: list[dict[str, Any]] = []
        paths: set[str] = set()
        for entry in files:
            if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "bytes"}:
                raise SealedStoreViolation("snapshot manifest file entry is invalid")
            relative = entry["path"]
            digest = entry["sha256"]
            size = entry["bytes"]
            if (
                not isinstance(relative, str)
                or not relative
                or Path(relative).is_absolute()
                or ".." in Path(relative).parts
                or not _is_digest(digest)
                or not isinstance(size, int)
                or isinstance(size, bool)
                or size < 0
                or relative in paths
            ):
                raise SealedStoreViolation("snapshot manifest file entry is invalid")
            paths.add(relative)
            normalized.append({"path": relative, "sha256": digest, "bytes": size})
        if normalized != sorted(normalized, key=lambda entry: entry["path"]):
            raise SealedStoreViolation("snapshot manifest files must be sorted")
        payload = {"schema_version": _SCHEMA_VERSION, "fixture_id": fixture_id, "files": normalized}
        if _canonical_digest(payload) != snapshot_id:
            raise SealedStoreViolation("snapshot manifest digest is forged")
        return fixture_id, normalized

    def _verify_file_tree(self, root: Path, files: list[dict[str, Any]]) -> None:
        expected = {entry["path"]: entry for entry in files}
        actual: set[str] = set()
        for current_root, directories, filenames in os.walk(root, followlinks=False):
            current = Path(current_root)
            self._require_private_directory(current, read_only=True)
            for name in directories:
                candidate = current / name
                if candidate.is_symlink():
                    raise SealedStoreViolation("sealed snapshot contains a symlink")
            for name in filenames:
                candidate = current / name
                relative = candidate.relative_to(root).as_posix()
                self._require_private_file(candidate, read_only=True)
                actual.add(relative)
                entry = expected.get(relative)
                if entry is None:
                    raise SealedStoreViolation("sealed snapshot contains an unregistered file")
                data = candidate.read_bytes()
                if len(data) != entry["bytes"] or _sha256(data) != entry["sha256"]:
                    raise SealedStoreViolation("sealed snapshot bytes do not match its manifest")
        if actual != set(expected):
            raise SealedStoreViolation("sealed snapshot is missing a registered file")

    @staticmethod
    def _require_private_directory(path: Path, *, read_only: bool = False) -> None:
        try:
            details = path.lstat()
        except OSError as error:
            raise SealedStoreViolation("sealed snapshot directory is absent") from error
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode) or not _is_private(details.st_mode):
            raise SealedStoreViolation("sealed snapshot directory permissions are invalid")
        if read_only and details.st_mode & 0o222:
            raise SealedStoreViolation("sealed snapshot directory is writable")

    @staticmethod
    def _require_private_file(path: Path, *, read_only: bool = False) -> None:
        try:
            details = path.lstat()
        except OSError as error:
            raise SealedStoreViolation("sealed snapshot file is absent") from error
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode) or not _is_private(details.st_mode):
            raise SealedStoreViolation("sealed snapshot file permissions are invalid")
        if read_only and details.st_mode & 0o222:
            raise SealedStoreViolation("sealed snapshot file is writable")
