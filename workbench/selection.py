"""Conservative B1 graph closure over a verified comparison pair."""
from __future__ import annotations

from collections import deque
from typing import Mapping, Sequence


class SelectionViolation(ValueError):
    """Raised when B1 selection would silently narrow incomplete graph evidence."""


def conservative_b1_closure(
    *,
    changed_units: set[str],
    all_units: Sequence[str],
    graph: Mapping[str, Mapping[str, object]],
) -> tuple[str, ...]:
    if not changed_units or not all_units or not all(isinstance(unit, str) and unit for unit in all_units):
        raise SelectionViolation("B1 needs changed units and a complete sealed candidate universe")
    universe = tuple(dict.fromkeys(all_units))
    if len(universe) != len(all_units) or not changed_units.issubset(universe):
        raise SelectionViolation("B1 changed units must belong to the candidate universe")
    selected = set(changed_units)
    queue = deque(sorted(changed_units))
    while queue:
        unit = queue.popleft()
        entry = graph.get(unit)
        if entry is None or entry.get("complete") is not True:
            return universe
        neighbors = entry.get("neighbors")
        if not isinstance(neighbors, list) or not all(isinstance(item, str) and item in selected | set(universe) for item in neighbors):
            return universe
        for neighbor in neighbors:
            if neighbor not in selected:
                selected.add(neighbor)
                queue.append(neighbor)
    return tuple(unit for unit in universe if unit in selected)
