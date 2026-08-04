"""Descriptor-bound repository intake for Phase 3 sealed snapshots."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


class IntakeViolation(ValueError):
    """Raised when a live repository cannot be safely admitted."""


_SNAPSHOT_SCHEMA = "sentinel-workbench-repository-snapshot/v1"
_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_IGNORED_DIRECTORIES = {".git", ".hg", ".svn", "node_modules", "dist", "build", "coverage", ".next", ".cache"}
_SENSITIVE_BASENAME = re.compile(r"^(?:\.env(?:\..*)?|.*\.(?:pem|key|p12|pfx|sqlite|db|dump))$", re.IGNORECASE)
_TYPE_SCRIPT_SUFFIXES = {".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs", ".json", ".yaml", ".yml", ".md"}
_MAX_BYTES = 256 * 1024
_MAX_LINE = 24 * 1024
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class RepositorySnapshot:
    snapshot_id: str
    root: Path
    manifest_path: Path
    repository_identity: str
    profile: str


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


class RepositoryIntake:
    """Copy only configured repository roots into a private immutable store."""

    def __init__(self, *, evidence_root: Path | str, approved_roots: Mapping[str, Path | str], profile: str) -> None:
        if profile != "typescript":
            raise IntakeViolation("only the frozen typescript profile is currently supported")
        if not approved_roots:
            raise IntakeViolation("repository intake requires configured roots")
        self._roots: dict[str, Path] = {}
        for root_id, root in approved_roots.items():
            if not isinstance(root_id, str) or _IDENTITY.fullmatch(root_id) is None:
                raise IntakeViolation("configured root IDs must be labelled")
            path = Path(root)
            if path.is_symlink() or not path.is_dir():
                raise IntakeViolation("configured root must be an existing non-symlink directory")
            self._roots[root_id] = path.resolve()
        self._profile = profile
        self._evidence_root = Path(evidence_root).resolve()
        self._snapshots = self._evidence_root / "snapshots"
        self._manifests = self._evidence_root / "manifests"
        self._staging = self._evidence_root / ".staging"
        for path in (self._evidence_root, self._snapshots, self._manifests, self._staging):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            if path.is_symlink() or not path.is_dir():
                raise IntakeViolation("private evidence root is invalid")
            os.chmod(path, 0o700)

    def seal_registered_root(self, root_id: str, *, repository_identity: str) -> RepositorySnapshot:
        if root_id not in self._roots:
            raise IntakeViolation("repository root is not configured")
        if not isinstance(repository_identity, str) or _IDENTITY.fullmatch(repository_identity) is None:
            raise IntakeViolation("repository identity must be labelled")
        source = self._roots[root_id]
        staging = Path(tempfile.mkdtemp(prefix="intake-", dir=self._staging))
        copied = staging / "source"
        try:
            entries = self._copy_admitted_tree(source, copied)
            if not entries:
                raise IntakeViolation("admitted repository has no supported files")
            payload = {
                "schema_version": _SNAPSHOT_SCHEMA,
                "repository_identity": repository_identity,
                "profile": self._profile,
                "files": entries,
            }
            snapshot_id = _digest(payload)
            manifest = {**payload, "snapshot_id": snapshot_id, "root_digest": snapshot_id, "file_count": len(entries)}
            self._make_read_only(copied)
            target = self._snapshots / snapshot_id
            if not target.exists():
                os.replace(staging, target)
                os.chmod(target, 0o500)
            else:
                self._discard(staging)
            manifest_path = self._write_manifest(snapshot_id, manifest)
            return self.resolve_snapshot(snapshot_id)
        except BaseException:
            if staging.exists():
                self._discard(staging)
            raise

    def _copy_admitted_tree(self, source_root: Path, target_root: Path) -> list[dict[str, object]]:
        target_root.mkdir(mode=0o700)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            root_descriptor = os.open(source_root, flags)
        except OSError as error:
            raise IntakeViolation("configured repository root cannot be opened safely") from error
        try:
            root_stat = os.fstat(root_descriptor)
            if not stat.S_ISDIR(root_stat.st_mode):
                raise IntakeViolation("configured repository root is not a directory")
            root_mount = self._mount_id_for_fd(root_descriptor)
            return self._copy_directory(
                directory_fd=root_descriptor,
                relative_directory=Path(),
                target_root=target_root,
                root_device=root_stat.st_dev,
                root_mount=root_mount,
            )
        finally:
            os.close(root_descriptor)

    def _copy_directory(
        self,
        *,
        directory_fd: int,
        relative_directory: Path,
        target_root: Path,
        root_device: int,
        root_mount: int,
    ) -> list[dict[str, object]]:
        entries: list[dict[str, object]] = []
        try:
            names = sorted(os.listdir(directory_fd))
        except OSError as error:
            raise IntakeViolation("repository directory cannot be enumerated safely") from error
        for name in names:
            before = self._lstat_at(directory_fd, name)
            if before.st_dev != root_device:
                raise IntakeViolation("repository contains a mount/device escape")
            relative = relative_directory / name
            if stat.S_ISLNK(before.st_mode):
                raise IntakeViolation("repository contains a symbolic link")
            if stat.S_ISDIR(before.st_mode):
                if name in _IGNORED_DIRECTORIES:
                    self._assert_ignored_tree_safe(directory_fd, name, root_device, root_mount)
                    continue
                child_fd = self._open_verified_at(
                    directory_fd,
                    name,
                    expected=before,
                    directory=True,
                )
                try:
                    (target_root / relative).mkdir(mode=0o700, parents=True, exist_ok=True)
                    entries.extend(
                        self._copy_directory(
                            directory_fd=child_fd,
                            relative_directory=relative,
                            target_root=target_root,
                            root_device=root_device,
                            root_mount=root_mount,
                        )
                    )
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(before.st_mode):
                raise IntakeViolation("repository contains a non-regular source entry")
            if _SENSITIVE_BASENAME.fullmatch(name):
                raise IntakeViolation("repository contains a forbidden sensitive file")
            if Path(name).suffix.lower() not in _TYPE_SCRIPT_SUFFIXES:
                continue
            if before.st_size > _MAX_BYTES:
                raise IntakeViolation("repository source file exceeds the admitted size cap")
            data = self._read_verified_file(directory_fd, name, before, root_mount)
            if b"\0" in data:
                raise IntakeViolation("repository contains a binary source file")
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError as error:
                raise IntakeViolation("repository contains a non-UTF-8 source file") from error
            if any(len(line) > _MAX_LINE for line in text.splitlines()):
                raise IntakeViolation("repository contains a minified or oversized source line")
            destination = target_root / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            entries.append({"path": relative.as_posix(), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
        return entries

    @staticmethod
    def _lstat_at(directory_fd: int, name: str) -> os.stat_result:
        try:
            return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as error:
            raise IntakeViolation("repository entry vanished during admission") from error

    @staticmethod
    def _open_verified_at(
        directory_fd: int,
        name: str,
        *,
        expected: os.stat_result,
        directory: bool,
    ) -> int:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        if directory:
            flags |= getattr(os, "O_DIRECTORY", 0)
        try:
            descriptor = os.open(name, flags, dir_fd=directory_fd)
        except OSError as error:
            raise IntakeViolation("repository entry cannot be opened without following links") from error
        actual = os.fstat(descriptor)
        expected_type = stat.S_IFMT(expected.st_mode)
        if (
            actual.st_dev != expected.st_dev
            or actual.st_ino != expected.st_ino
            or stat.S_IFMT(actual.st_mode) != expected_type
        ):
            os.close(descriptor)
            raise IntakeViolation("repository entry changed during descriptor-relative admission")
        return descriptor

    def _read_verified_file(
        self,
        directory_fd: int,
        name: str,
        expected: os.stat_result,
        root_mount: int,
    ) -> bytes:
        descriptor = self._open_verified_at(directory_fd, name, expected=expected, directory=False)
        try:
            if self._mount_id_for_fd(descriptor) != root_mount:
                raise IntakeViolation("repository file crosses a mount boundary")
            chunks: list[bytes] = []
            remaining = expected.st_size + 1
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            actual = os.fstat(descriptor)
            if len(data) != expected.st_size or actual.st_size != expected.st_size:
                raise IntakeViolation("repository file changed while its sealed copy was read")
            return data
        finally:
            os.close(descriptor)

    def _assert_ignored_tree_safe(
        self,
        directory_fd: int,
        name: str,
        root_device: int,
        root_mount: int,
    ) -> None:
        """Ignore dependency/build bytes but still reject links, specials, and mounts."""
        descriptor = self._open_verified_at(
            directory_fd,
            name,
            expected=self._lstat_at(directory_fd, name),
            directory=True,
        )
        try:
            if self._mount_id_for_fd(descriptor) != root_mount:
                raise IntakeViolation("ignored repository directory crosses a mount boundary")
            for child in sorted(os.listdir(descriptor)):
                details = self._lstat_at(descriptor, child)
                if details.st_dev != root_device:
                    raise IntakeViolation("ignored repository directory contains a mount/device escape")
                if stat.S_ISLNK(details.st_mode) or not (stat.S_ISDIR(details.st_mode) or stat.S_ISREG(details.st_mode)):
                    raise IntakeViolation("ignored repository directory contains a symlink or special entry")
                if stat.S_ISDIR(details.st_mode):
                    self._assert_ignored_tree_safe(descriptor, child, root_device, root_mount)
                else:
                    child_file = self._open_verified_at(
                        descriptor,
                        child,
                        expected=details,
                        directory=False,
                    )
                    try:
                        if self._mount_id_for_fd(child_file) != root_mount:
                            raise IntakeViolation("ignored repository file crosses a mount boundary")
                    finally:
                        os.close(child_file)
        finally:
            os.close(descriptor)

    @staticmethod
    def _mount_id_for_fd(descriptor: int) -> int:
        """Resolve Linux mount identity, which is stricter than st_dev."""
        try:
            target = os.path.realpath(f"/proc/self/fd/{descriptor}")
            mounts = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as error:
            raise IntakeViolation("mount identity cannot be verified") from error
        best_length = -1
        best_mount = None
        for line in mounts:
            before_separator, _, _after = line.partition(" - ")
            fields = before_separator.split()
            if len(fields) < 5:
                continue
            mount_point = fields[4].replace("\\040", " ").replace("\\011", "\t")
            if target == mount_point or target.startswith(mount_point.rstrip("/") + "/"):
                if len(mount_point) > best_length:
                    best_length = len(mount_point)
                    best_mount = fields[0]
        if best_mount is None:
            raise IntakeViolation("mount identity is absent for the admitted root")
        return int(best_mount)

    def _write_manifest(self, snapshot_id: str, manifest: Mapping[str, object]) -> Path:
        final = self._manifests / f"{snapshot_id}.json"
        if final.exists():
            return final
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{snapshot_id}.", dir=self._manifests)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8") + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o400)
            os.link(temporary, final)
        finally:
            temporary.unlink(missing_ok=True)
        return final

    def resolve_snapshot(self, snapshot_id: str) -> RepositorySnapshot:
        """Resolve only an intact private copy issued by this intake authority."""
        if not isinstance(snapshot_id, str) or _DIGEST.fullmatch(snapshot_id) is None:
            raise IntakeViolation("sealed snapshot ID must be a lowercase digest")
        manifest_path = self._manifests / f"{snapshot_id}.json"
        root = self._snapshots / snapshot_id / "source"
        self._require_private_path(self._evidence_root, directory=True, read_only=False)
        self._require_private_path(self._manifests, directory=True, read_only=False)
        self._require_private_path(self._snapshots, directory=True, read_only=False)
        self._require_private_path(manifest_path, directory=False, read_only=True)
        self._require_private_path(root.parent, directory=True, read_only=True)
        self._require_private_path(root, directory=True, read_only=True)
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise IntakeViolation("sealed snapshot manifest is unreadable") from error
        if not isinstance(manifest, dict) or set(manifest) != {
            "schema_version",
            "repository_identity",
            "profile",
            "files",
            "snapshot_id",
            "root_digest",
            "file_count",
        }:
            raise IntakeViolation("sealed snapshot manifest has an invalid shape")
        if (
            manifest["schema_version"] != _SNAPSHOT_SCHEMA
            or manifest["snapshot_id"] != snapshot_id
            or manifest["root_digest"] != snapshot_id
            or not isinstance(manifest["repository_identity"], str)
            or _IDENTITY.fullmatch(manifest["repository_identity"]) is None
            or manifest["profile"] != self._profile
            or not isinstance(manifest["files"], list)
            or manifest["file_count"] != len(manifest["files"])
        ):
            raise IntakeViolation("sealed snapshot manifest does not bind the expected profile")
        files: list[dict[str, object]] = []
        paths: set[str] = set()
        for entry in manifest["files"]:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"path", "sha256", "bytes"}
                or not isinstance(entry["path"], str)
                or not entry["path"]
                or Path(entry["path"]).is_absolute()
                or ".." in Path(entry["path"]).parts
                or entry["path"] in paths
                or not isinstance(entry["sha256"], str)
                or _DIGEST.fullmatch(entry["sha256"]) is None
                or not isinstance(entry["bytes"], int)
                or isinstance(entry["bytes"], bool)
                or entry["bytes"] < 0
            ):
                raise IntakeViolation("sealed snapshot manifest file entry is invalid")
            paths.add(entry["path"])
            files.append(dict(entry))
        if not files or files != sorted(files, key=lambda entry: str(entry["path"])):
            raise IntakeViolation("sealed snapshot manifest inventory is invalid")
        payload = {
            "schema_version": _SNAPSHOT_SCHEMA,
            "repository_identity": manifest["repository_identity"],
            "profile": manifest["profile"],
            "files": files,
        }
        if _digest(payload) != snapshot_id:
            raise IntakeViolation("sealed snapshot manifest digest is forged")
        self._verify_sealed_files(root, files)
        return RepositorySnapshot(
            snapshot_id=snapshot_id,
            root=root,
            manifest_path=manifest_path,
            repository_identity=manifest["repository_identity"],
            profile=self._profile,
        )

    def read_sealed_file(self, snapshot_id: str, relative_path: str) -> bytes:
        """Read an admitted file after re-validating its sealed snapshot."""
        snapshot = self.resolve_snapshot(snapshot_id)
        if not isinstance(relative_path, str) or not relative_path or Path(relative_path).is_absolute():
            raise IntakeViolation("sealed file path must be relative")
        manifest = json.loads(snapshot.manifest_path.read_text(encoding="utf-8"))
        entry = next((item for item in manifest["files"] if item["path"] == relative_path), None)
        if entry is None:
            raise IntakeViolation("sealed file is not in the admitted manifest")
        target = snapshot.root / relative_path
        self._require_private_path(target, directory=False, read_only=True)
        data = target.read_bytes()
        if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise IntakeViolation("sealed file bytes do not match the manifest")
        return data

    def _verify_sealed_files(self, root: Path, files: list[dict[str, object]]) -> None:
        expected = {str(entry["path"]): entry for entry in files}
        actual: set[str] = set()
        for current, directories, filenames in os.walk(root, followlinks=False):
            current_path = Path(current)
            self._require_private_path(current_path, directory=True, read_only=True)
            for name in directories:
                self._require_private_path(current_path / name, directory=True, read_only=True)
            for name in filenames:
                path = current_path / name
                self._require_private_path(path, directory=False, read_only=True)
                relative = path.relative_to(root).as_posix()
                entry = expected.get(relative)
                if entry is None:
                    raise IntakeViolation("sealed snapshot contains an unregistered file")
                data = path.read_bytes()
                if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                    raise IntakeViolation("sealed snapshot bytes do not match the manifest")
                actual.add(relative)
        if actual != set(expected):
            raise IntakeViolation("sealed snapshot is missing an admitted file")

    @staticmethod
    def _require_private_path(path: Path, *, directory: bool, read_only: bool) -> None:
        try:
            details = path.lstat()
        except OSError as error:
            raise IntakeViolation("sealed snapshot path is absent") from error
        expected = stat.S_ISDIR(details.st_mode) if directory else stat.S_ISREG(details.st_mode)
        if not expected or stat.S_ISLNK(details.st_mode) or details.st_mode & 0o077:
            raise IntakeViolation("sealed snapshot permissions are invalid")
        if read_only and details.st_mode & 0o222:
            raise IntakeViolation("sealed snapshot must be read-only")

    @staticmethod
    def _make_read_only(root: Path) -> None:
        for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            os.chmod(path, 0o400 if path.is_file() else 0o500)
        os.chmod(root, 0o500)

    @staticmethod
    def _discard(root: Path) -> None:
        for current, directories, filenames in os.walk(root, topdown=False):
            path = Path(current)
            for name in filenames:
                os.chmod(path / name, 0o600)
            for name in directories:
                os.chmod(path / name, 0o700)
        os.chmod(root, 0o700)
        import shutil

        shutil.rmtree(root)
