from __future__ import annotations

import pytest

from workbench.control_order import ControlOrderViolation, select_b2_stable_order
from workbench.selection import SelectionViolation, conservative_b1_closure
from workbench.units import build_unit_id


def test_unit_id_is_snapshot_and_context_digest_bound():
    first = build_unit_id(
        repository_identity="repo-a",
        snapshot_id="a" * 64,
        path="src/app.ts",
        start_line=3,
        end_line=8,
        dependency_context_digest="b" * 64,
    )
    second = build_unit_id(
        repository_identity="repo-a",
        snapshot_id="c" * 64,
        path="src/app.ts",
        start_line=3,
        end_line=8,
        dependency_context_digest="b" * 64,
    )
    assert first != second
    assert first.startswith("unit-v1:")


def test_b1_closure_expands_unknown_edges_and_b2_uses_stable_ties():
    units = ["config", "middleware", "route", "sink", "unrelated"]
    selected = conservative_b1_closure(
        changed_units={"sink"},
        all_units=units,
        graph={
            "sink": {"neighbors": ["middleware"], "complete": True},
            "middleware": {"neighbors": ["route"], "complete": True},
            "route": {"neighbors": ["config"], "complete": False},
        },
    )
    assert selected == tuple(units)
    assert select_b2_stable_order(["z", "a", "m"] + [f"unit-{index}" for index in range(12)], budget=12)[0] == "a"
    with pytest.raises(ControlOrderViolation):
        select_b2_stable_order(["a"], budget=12)


def test_b1_refuses_missing_universe_instead_of_silently_narrowing():
    with pytest.raises(SelectionViolation):
        conservative_b1_closure(
            changed_units={"sink"},
            all_units=[],
            graph={"sink": {"neighbors": [], "complete": False}},
        )
