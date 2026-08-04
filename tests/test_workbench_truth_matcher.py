from __future__ import annotations

import pytest

from workbench.contracts import TruthManifest
from workbench.truth_matcher import TruthMatcherViolation, match_worklist


def truth() -> TruthManifest:
    return TruthManifest.from_mapping(
        {
            "schema_version": "sentinel-workbench-truth-manifest/v1",
            "candidate_snapshot_digest": "a" * 64,
            "negative_universe_unit_ids": ["negative"],
            "control_audit": {"auditor": "independent", "outcome_blind": True, "unplanted_control_ids": ["control"]},
            "defects": [
                {
                    "vulnerability_id": "vuln-1",
                    "class": "injection",
                    "precondition": "route",
                    "canonical_unit_id": "canonical",
                    "allowed_alternatives": ["alternative"],
                    "provenance": "fixture",
                    "license": "fixture",
                }
            ],
        }
    )


def test_truth_matcher_claims_once_and_retains_negative_and_unmeasured_output():
    result = match_worklist(
        truth(),
        proposal_ids=("alternative", "canonical", "negative", "unmeasured"),
        admitted_unit_ids={"canonical", "alternative", "negative", "unmeasured"},
    )
    assert result.recalled_vulnerability_ids == ("vuln-1",)
    assert result.duplicate_unit_ids == ("canonical",)
    assert result.adjudicated_negative_unit_ids == ("negative",)
    assert result.not_measured_unit_ids == ("unmeasured",)
    assert result.recall_at_12 == 1.0


def test_truth_matcher_refuses_a_proposal_outside_the_shared_analysis_mask():
    with pytest.raises(TruthMatcherViolation):
        match_worklist(truth(), proposal_ids=("outside",), admitted_unit_ids={"canonical"})
