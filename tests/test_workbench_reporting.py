from __future__ import annotations

import pytest

from workbench.publish import PublicationViolation, verify_independent_review
from workbench.reporting import ReportingViolation, render_public_summary


def test_reporting_never_claims_effectiveness_for_cmc_or_underpowered_states():
    cmc = render_public_summary({"kind": "case-study-only", "reason_code": "cmc-inventory-only"})
    assert "improved" not in cmc.lower()
    assert "CMC inventory" in cmc
    underpowered = render_public_summary({"kind": "underpowered/descriptive", "reason_code": "insufficient-paired-repositories"})
    assert "not an efficacy claim" in underpowered


def test_reporting_names_only_b3_minus_b2_and_all_required_controls_for_a_valid_effect():
    text = render_public_summary(
        {
            "kind": "named-contrast",
            "corpus_admission_outcome": "corpus-only",
            "contrast": "B3-B2",
            "metric": "recall_at_12",
            "interval": {"lower": 0.03, "upper": 0.05},
        }
    )
    assert "B3−B2" in text
    assert "B1 descriptive-only" in text
    assert "k=3" in text


def test_publication_requires_digest_bound_independent_reproduction():
    with pytest.raises(PublicationViolation):
        verify_independent_review(
            {"reviewer": "builder", "run_digest": "a" * 64, "report_digest": "b" * 64, "approved": True},
            expected_run_digest="a" * 64,
            expected_report_digest="b" * 64,
            builder_id="builder",
        )
