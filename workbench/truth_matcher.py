"""Frozen-truth worklist matcher and deterministic measurement records."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .contracts import TruthManifest


class TruthMatcherViolation(ValueError):
    """Raised when scoring would use an unsealed or non-common proposal universe."""


@dataclass(frozen=True)
class TruthMatchResult:
    recalled_vulnerability_ids: tuple[str, ...]
    duplicate_unit_ids: tuple[str, ...]
    adjudicated_negative_unit_ids: tuple[str, ...]
    not_measured_unit_ids: tuple[str, ...]
    recall_at_12: float
    precision_at_12: float


def match_worklist(
    truth: TruthManifest,
    *,
    proposal_ids: Iterable[str],
    admitted_unit_ids: set[str] | frozenset[str],
) -> TruthMatchResult:
    proposals = tuple(proposal_ids)
    if not proposals or len(proposals) > 12 or not admitted_unit_ids or not all(
        isinstance(item, str) and item and item in admitted_unit_ids for item in proposals
    ):
        raise TruthMatcherViolation("truth scoring requires at most twelve proposals in the frozen analysis mask")
    by_unit: dict[str, str] = {}
    for defect in truth.defects:
        vulnerability_id = defect["vulnerability_id"]
        by_unit[defect["canonical_unit_id"]] = vulnerability_id
        for alternative in defect["allowed_alternatives"]:
            by_unit[alternative] = vulnerability_id
    recalled: list[str] = []
    duplicates: list[str] = []
    negatives: list[str] = []
    unmeasured: list[str] = []
    claimed: set[str] = set()
    for unit_id in proposals:
        vulnerability = by_unit.get(unit_id)
        if vulnerability is not None:
            if vulnerability in claimed:
                duplicates.append(unit_id)
            else:
                claimed.add(vulnerability)
                recalled.append(vulnerability)
        elif unit_id in truth.negative_universe_unit_ids:
            negatives.append(unit_id)
        else:
            unmeasured.append(unit_id)
    true_positive = len(recalled)
    return TruthMatchResult(
        tuple(recalled),
        tuple(duplicates),
        tuple(negatives),
        tuple(unmeasured),
        true_positive / len(truth.defects),
        true_positive / len(proposals),
    )
