"""Stable investigation-unit identifiers derived from sealed evidence."""
from __future__ import annotations

import hashlib
import json
import re


class UnitViolation(ValueError):
    """Raised when a unit cannot be bound to a sealed source range."""


_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def build_unit_id(
    *,
    repository_identity: str,
    snapshot_id: str,
    path: str,
    start_line: int,
    end_line: int,
    dependency_context_digest: str,
) -> str:
    if (
        not isinstance(repository_identity, str)
        or not repository_identity
        or not isinstance(path, str)
        or not path
        or path.startswith("/")
        or ".." in path.split("/")
        or not isinstance(start_line, int)
        or not isinstance(end_line, int)
        or start_line < 1
        or end_line < start_line
        or _DIGEST.fullmatch(snapshot_id or "") is None
        or _DIGEST.fullmatch(dependency_context_digest or "") is None
    ):
        raise UnitViolation("investigation unit requires a sealed repository range and digests")
    payload = {
        "schema_version": "sentinel-workbench-unit/v1",
        "repository_identity": repository_identity,
        "snapshot_id": snapshot_id,
        "path": path,
        "start_line": start_line,
        "end_line": end_line,
        "dependency_context_digest": dependency_context_digest,
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return f"unit-v1:{digest}"
