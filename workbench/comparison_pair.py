"""Digest-bound base/candidate comparison pairs over sealed manifests."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .intake import IntakeViolation, RepositoryIntake, RepositorySnapshot


class ComparisonPairViolation(ValueError):
    """Raised when B1 would use a mutable or incompatible comparison."""


@dataclass(frozen=True)
class ComparisonPair:
    pair_digest: str
    repository_identity: str
    base_snapshot_id: str
    candidate_snapshot_id: str
    diff: dict[str, list[object]]
    _authority_token: object = field(default=None, repr=False, compare=False)

    def is_authorized(self) -> bool:
        return self._authority_token is _PAIR_AUTHORITY


_PAIR_AUTHORITY = object()


def _manifest_files(snapshot: RepositorySnapshot) -> dict[str, str]:
    try:
        document = json.loads(snapshot.manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ComparisonPairViolation("sealed snapshot manifest is unreadable") from error
    if document.get("snapshot_id") != snapshot.snapshot_id or document.get("repository_identity") != snapshot.repository_identity:
        raise ComparisonPairViolation("snapshot does not bind to its sealed manifest")
    files = document.get("files")
    if not isinstance(files, list):
        raise ComparisonPairViolation("snapshot manifest has no file inventory")
    result: dict[str, str] = {}
    for entry in files:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str) or not isinstance(entry.get("sha256"), str):
            raise ComparisonPairViolation("snapshot manifest has an invalid file entry")
        result[entry["path"]] = entry["sha256"]
    return result


def build_comparison_pair(
    intake: RepositoryIntake,
    base_snapshot_id: str,
    candidate_snapshot_id: str,
) -> ComparisonPair:
    """Build B1 input only from snapshots re-resolved by the intake authority."""
    try:
        base = intake.resolve_snapshot(base_snapshot_id)
        candidate = intake.resolve_snapshot(candidate_snapshot_id)
    except IntakeViolation as error:
        raise ComparisonPairViolation("comparison pair requires intact sealed snapshots") from error
    if base.repository_identity != candidate.repository_identity or base.profile != candidate.profile:
        raise ComparisonPairViolation("comparison pair roots/profile must identify the same admitted repository")
    base_files = _manifest_files(base)
    candidate_files = _manifest_files(candidate)
    deleted = sorted(set(base_files) - set(candidate_files))
    added = sorted(set(candidate_files) - set(base_files))
    renamed: list[dict[str, str]] = []
    remaining_deleted = set(deleted)
    remaining_added = set(added)
    deleted_by_digest: dict[str, list[str]] = {}
    added_by_digest: dict[str, list[str]] = {}
    for source in deleted:
        deleted_by_digest.setdefault(base_files[source], []).append(source)
    for target in added:
        added_by_digest.setdefault(candidate_files[target], []).append(target)
    for digest, source_paths in deleted_by_digest.items():
        target_paths = added_by_digest.get(digest, [])
        if len(source_paths) == len(target_paths) == 1:
            source = source_paths[0]
            target = target_paths[0]
            renamed.append({"from": source, "to": target})
            remaining_deleted.discard(source)
            remaining_added.discard(target)
    modified = sorted(path for path in set(base_files) & set(candidate_files) if base_files[path] != candidate_files[path])
    diff: dict[str, list[object]] = {
        "added": sorted(remaining_added),
        "modified": modified,
        "deleted": sorted(remaining_deleted),
        "renamed": sorted(renamed, key=lambda item: (item["from"], item["to"])),
    }
    payload = {
        "schema_version": "sentinel-workbench-comparison-pair/v1",
        "repository_identity": base.repository_identity,
        "base_snapshot_id": base.snapshot_id,
        "candidate_snapshot_id": candidate.snapshot_id,
        "diff": diff,
    }
    return ComparisonPair(
        hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest(),
        base.repository_identity,
        base.snapshot_id,
        candidate.snapshot_id,
        diff,
        _PAIR_AUTHORITY,
    )
