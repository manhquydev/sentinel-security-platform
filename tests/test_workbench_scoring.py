from __future__ import annotations

import pytest

from workbench.scoring import ScoringViolation, paired_b3_b2_bootstrap


def rows(delta: float = 0.03):
    return [
        {
            "repository_id": f"repo-{index:02}",
            "b2_recall_at_12": 0.40,
            "b3_recall_at_12": 0.40 + delta,
            "shared_analysis_mask_digest": "a" * 64,
            "b3_readings_complete": 3,
        }
        for index in range(20)
    ]


def test_grouped_bootstrap_is_deterministic_and_labels_only_named_b3_minus_b2_contrast():
    first = paired_b3_b2_bootstrap(rows())
    second = paired_b3_b2_bootstrap(rows())
    assert first == second
    assert first.contrast_id == "B3-B2:recall_at_12"
    assert first.label == "win"
    assert first.lower > 0.02


def test_missing_repositories_masks_or_b3_readings_prevents_an_inferential_label():
    with pytest.raises(ScoringViolation):
        paired_b3_b2_bootstrap(rows()[:19])
    invalid = rows()
    invalid[0]["b3_readings_complete"] = 2
    with pytest.raises(ScoringViolation):
        paired_b3_b2_bootstrap(invalid)
    invalid = rows()
    invalid[1]["shared_analysis_mask_digest"] = "b" * 64
    with pytest.raises(ScoringViolation):
        paired_b3_b2_bootstrap(invalid)
