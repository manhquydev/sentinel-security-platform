"""CMC packaging gate: no catalog/action/demo unless value is actually measured."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from statistics import median
from typing import Any, Mapping

from .contracts import ContractViolation, _canonical_digest, _positive_int, _require


class CmcValueGate(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_RUN = "not-run"
    INVALID = "invalid"


@dataclass(frozen=True)
class CmcGateRecord:
    status: CmcValueGate
    numerator: int
    denominator: int
    threshold: dict[str, int]
    timing_summary: dict[str, float]
    reason: str | None

    @property
    def digest(self) -> str:
        return _canonical_digest(
            {
                "status": self.status,
                "numerator": self.numerator,
                "denominator": self.denominator,
                "threshold": self.threshold,
                "timing_summary": self.timing_summary,
                "reason": self.reason,
            }
        )


def not_run_cmc_value_gate(reason: str) -> CmcGateRecord:
    """Record the explicit negative state before a valid census exists."""
    if not isinstance(reason, str) or not reason:
        raise ContractViolation("not-run CMC value gate requires a reason")
    return CmcGateRecord(CmcValueGate.NOT_RUN, 0, 0, {}, {}, reason)


def evaluate_cmc_value_gate(document: Mapping[str, Any]) -> CmcGateRecord:
    if document.get("schema_version") != "sentinel-workbench-cmc-census/v1":
        return CmcGateRecord(CmcValueGate.INVALID, 0, 0, {}, {}, "invalid-schema-version")
    if "status" in document:
        raise ContractViolation("value gate status is derived from an immutable census, never caller-supplied")
    try:
        decision_volume = _positive_int(_require(document, "decision_volume"), "decision_volume")
        review_seconds = _require(document, "review_seconds")
        minimum_volume = _positive_int(_require(document, "minimum_decision_volume"), "minimum_decision_volume")
        maximum_median = _positive_int(
            _require(document, "maximum_median_review_seconds"), "maximum_median_review_seconds"
        )
        if not isinstance(review_seconds, list) or not review_seconds:
            raise ContractViolation("review_seconds must be a non-empty timed sample")
        if not all(isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0 for value in review_seconds):
            raise ContractViolation("review_seconds must be non-negative numbers")
        if not 20 <= len(review_seconds) <= 30:
            raise ContractViolation("review_seconds must contain the preregistered 20–30 fixed-context decisions")
    except ContractViolation as error:
        return CmcGateRecord(CmcValueGate.INVALID, 0, 0, {}, {}, str(error))
    timing = {
        "median_seconds": float(median(review_seconds)),
        "minimum_seconds": float(min(review_seconds)),
        "maximum_seconds": float(max(review_seconds)),
        "sample_count": float(len(review_seconds)),
    }
    threshold = {"minimum_decision_volume": minimum_volume, "maximum_median_review_seconds": maximum_median}
    if decision_volume < minimum_volume:
        return CmcGateRecord(CmcValueGate.FAILED, decision_volume, len(review_seconds), threshold, timing, "decision-volume-below-threshold")
    if timing["median_seconds"] > maximum_median:
        return CmcGateRecord(CmcValueGate.FAILED, decision_volume, len(review_seconds), threshold, timing, "review-time-above-threshold")
    return CmcGateRecord(CmcValueGate.PASSED, decision_volume, len(review_seconds), threshold, timing, None)


def assert_cmc_feature_allowed(gate: CmcGateRecord, feature: str) -> None:
    if feature not in {"catalog", "approval", "dispatch", "demo"}:
        raise ContractViolation(f"unsupported CMC feature: {feature}")
    if gate.status != CmcValueGate.PASSED:
        raise ContractViolation(f"CMC {feature} is disabled while cmc_value_gate is {gate.status}")
