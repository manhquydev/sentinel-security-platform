"""Claim-bounded public text for Workbench evidence states."""
from __future__ import annotations

from typing import Mapping

from .result_state import ResultState, render_result_state


class ReportingViolation(ValueError):
    """Raised when report language would exceed the measured evidence."""


def render_public_summary(document: Mapping[str, object]) -> str:
    result = render_result_state(document)
    if result.kind == ResultState.CASE_STUDY_ONLY:
        return "CMC inventory/workflow case study only; not comparative evidence and not an efficacy claim."
    if result.kind in {ResultState.NO_ELIGIBLE_CORPUS, ResultState.NOT_MEASURED, ResultState.INSTRUMENT_INVALID}:
        return f"Research result unavailable ({result.reason_code}); no effectiveness claim is rendered."
    if result.kind == ResultState.UNDERPOWERED:
        return f"Descriptive result only ({result.reason_code}); not an efficacy claim."
    if result.kind != ResultState.NAMED_CONTRAST:
        raise ReportingViolation("unknown renderer state")
    return (
        f"Eligible-corpus result for B3−B2 recall_at_12: {result.outcome}. "
        "B1 descriptive-only; B0/B1/B2/B3 controls, equal human-review budget, "
        "B3 input/compute budget, k=3, calibration/power lineage, and claim bound are required beside this result."
    )
