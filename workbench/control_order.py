"""Frozen B2 deterministic control order."""
from __future__ import annotations

from typing import Sequence


class ControlOrderViolation(ValueError):
    """Raised when B2 cannot replay the frozen equal review budget."""


def select_b2_stable_order(unit_ids: Sequence[str], *, budget: int = 12) -> tuple[str, ...]:
    if not isinstance(budget, int) or isinstance(budget, bool) or budget != 12:
        raise ControlOrderViolation("B2 must use the frozen twelve-packet review budget")
    if not all(isinstance(item, str) and item for item in unit_ids) or len(set(unit_ids)) != len(unit_ids):
        raise ControlOrderViolation("B2 needs unique stable unit IDs")
    ordered = tuple(sorted(unit_ids))
    if len(ordered) < budget:
        raise ControlOrderViolation("B2 has fewer than twelve admissible packets")
    return ordered[:budget]
