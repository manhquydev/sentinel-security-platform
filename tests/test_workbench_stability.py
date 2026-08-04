from __future__ import annotations

import pytest

from workbench.stability import StabilityViolation, validate_canaries


def test_canary_gate_requires_positive_negative_and_stability_controls():
    responses = {
        "positive": {"proposal_ids": ["unit-positive"]},
        "negative": {"proposal_ids": []},
        "stability": {"proposal_ids": ["unit-stable"]},
    }
    assert validate_canaries(responses, expected={"positive": {"unit-positive"}, "negative": set(), "stability": {"unit-stable"}})


def test_canary_gate_fails_on_missing_or_changed_controls():
    with pytest.raises(StabilityViolation):
        validate_canaries({"positive": {"proposal_ids": ["unit-positive"]}}, expected={})
    with pytest.raises(StabilityViolation):
        validate_canaries(
            {
                "positive": {"proposal_ids": ["unit-positive"]},
                "negative": {"proposal_ids": ["unit-negative"]},
                "stability": {"proposal_ids": ["unit-stable"]},
            },
            expected={"positive": {"unit-positive"}, "negative": set(), "stability": {"unit-stable"}},
        )
