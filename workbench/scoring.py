"""Grouped, paired B3−B2 bootstrap for the sole inferential contrast."""
from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Mapping, Sequence


class ScoringViolation(ValueError):
    """Raised when a comparative inference lacks its frozen common evidence."""


@dataclass(frozen=True)
class PairedContrast:
    contrast_id: str
    lower: float
    upper: float
    observed_delta: float
    label: str
    repository_count: int
    bootstrap_resamples: int
    seed: int


def paired_b3_b2_bootstrap(
    rows: Sequence[Mapping[str, object]],
    *,
    resamples: int = 10_000,
    seed: int = 20260804,
) -> PairedContrast:
    if len(rows) < 20 or not isinstance(resamples, int) or resamples != 10_000 or seed != 20260804:
        raise ScoringViolation("B3−B2 inference requires the frozen 20-repository / 10,000-resample protocol")
    seen: set[str] = set()
    masks: set[str] = set()
    deltas: list[float] = []
    for row in rows:
        required = {
            "repository_id",
            "b2_recall_at_12",
            "b3_recall_at_12",
            "shared_analysis_mask_digest",
            "b3_readings_complete",
        }
        if not isinstance(row, Mapping) or set(row) != required:
            raise ScoringViolation("paired result row has an invalid shape")
        repository = row["repository_id"]
        b2 = row["b2_recall_at_12"]
        b3 = row["b3_recall_at_12"]
        mask = row["shared_analysis_mask_digest"]
        if (
            not isinstance(repository, str)
            or not repository
            or repository in seen
            or not isinstance(b2, (int, float))
            or not isinstance(b3, (int, float))
            or not 0 <= float(b2) <= 1
            or not 0 <= float(b3) <= 1
            or not isinstance(mask, str)
            or len(mask) != 64
            or row["b3_readings_complete"] != 3
        ):
            raise ScoringViolation("paired result row lacks a common mask or complete B3 readings")
        seen.add(repository)
        masks.add(mask)
        deltas.append(float(b3) - float(b2))
    if len(masks) != 1:
        raise ScoringViolation("all arms and repositories must share one frozen analysis mask")
    rng = random.Random(seed)
    samples = sorted(
        sum(deltas[rng.randrange(len(deltas))] for _ in deltas) / len(deltas)
        for _ in range(resamples)
    )
    lower = samples[math.floor((resamples - 1) * 0.025)]
    upper = samples[math.ceil((resamples - 1) * 0.975)]
    observed = sum(deltas) / len(deltas)
    if lower > 0.02:
        label = "win"
    elif upper < -0.02:
        label = "loss"
    elif lower >= -0.02 and upper <= 0.02:
        label = "tie"
    else:
        label = "inconclusive"
    return PairedContrast("B3-B2:recall_at_12", lower, upper, observed, label, len(deltas), resamples, seed)
