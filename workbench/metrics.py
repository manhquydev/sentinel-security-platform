"""Measurement metadata and exclusive result rendering helpers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .result_state import RenderedResult, render_result_state


class MetricsViolation(ValueError):
    """Raised when a metric record is incomplete or claim-bound incorrectly."""


@dataclass(frozen=True)
class ArmMetric:
    arm: str
    repository_id: str
    analysis_mask_digest: str
    selected_count: int
    truth_recalled: int
    truth_total: int
    elapsed_seconds: float
    token_count: int | None = None
    cost_cents: float | None = None

    @property
    def recall_at_12(self) -> float:
        if self.truth_total <= 0 or self.selected_count != 12:
            raise MetricsViolation("recall_at_12 requires twelve reviewed packets and a truth denominator")
        return self.truth_recalled / self.truth_total

    def to_record(self) -> dict[str, object]:
        if self.arm not in {"B0", "B1", "B2", "B3"} or self.truth_recalled < 0 or self.truth_total <= 0:
            raise MetricsViolation("metric arm or truth counts are invalid")
        if self.selected_count != 12 or self.elapsed_seconds < 0:
            raise MetricsViolation("metric resource contract is invalid")
        record: dict[str, object] = {
            "schema_version": "sentinel-workbench-arm-metric/v1",
            "arm": self.arm,
            "repository_id": self.repository_id,
            "analysis_mask_digest": self.analysis_mask_digest,
            "selected_count": self.selected_count,
            "truth_recalled": self.truth_recalled,
            "truth_total": self.truth_total,
            "recall_at_12": self.recall_at_12,
            "elapsed_seconds": self.elapsed_seconds,
        }
        if self.token_count is not None:
            record["token_count"] = self.token_count
        if self.cost_cents is not None:
            record["cost_cents"] = self.cost_cents
        return record


def render_metric_result(document: Mapping[str, object]) -> RenderedResult:
    """Delegate all public state decisions to the exclusive renderer."""
    try:
        return render_result_state(document)
    except Exception as error:
        raise MetricsViolation("metric result does not satisfy the renderer state contract") from error
