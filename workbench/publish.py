"""Independent reproduction gate for any public Workbench claim."""
from __future__ import annotations

from typing import Mapping


class PublicationViolation(ValueError):
    """Raised when public publication lacks a digest-bound independent review."""


def verify_independent_review(
    record: Mapping[str, object],
    *,
    expected_run_digest: str,
    expected_report_digest: str,
    builder_id: str,
) -> bool:
    if (
        set(record) != {"reviewer", "run_digest", "report_digest", "approved"}
        or not isinstance(record["reviewer"], str)
        or record["reviewer"] == builder_id
        or record["run_digest"] != expected_run_digest
        or record["report_digest"] != expected_report_digest
        or record["approved"] is not True
    ):
        raise PublicationViolation("public claims require an independent digest-bound reproduction record")
    return True
