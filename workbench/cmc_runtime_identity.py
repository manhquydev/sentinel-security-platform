"""Bound runtime identity for the optional local CMC smoke profile."""
from __future__ import annotations

import re
from dataclasses import dataclass


class RuntimeIdentityViolation(ValueError):
    """Raised when a listener cannot be tied to the approved local runtime."""


@dataclass(frozen=True)
class CmcRuntimeIdentity:
    container_image_digest: str
    container_id: str
    published_port: int
    started_at: str

    def __post_init__(self) -> None:
        if (
            re.fullmatch(r"[0-9a-f]{64}", self.container_image_digest or "") is None
            or not self.container_id
            or not isinstance(self.published_port, int)
            or not 1 <= self.published_port <= 65535
            or "T" not in self.started_at
        ):
            raise RuntimeIdentityViolation("CMC runtime identity is invalid")

    def to_mapping(self) -> dict[str, object]:
        return {
            "container_image_digest": self.container_image_digest,
            "container_id": self.container_id,
            "published_port": self.published_port,
            "started_at": self.started_at,
        }
