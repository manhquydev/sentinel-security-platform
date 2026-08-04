from __future__ import annotations

import pytest

from workbench.proposals import ProposalViolation, parse_model_proposal


def test_proposal_parser_accepts_only_bounded_source_relative_candidate_fields():
    proposal = parse_model_proposal(
        {
            "candidate_unit_id": "unit-1",
            "source_range": "src/app.ts:10-14",
            "hypothesis_class": "injection",
            "rationale": "The route reaches the sink.",
            "confidence": 0.8,
        },
        admitted_unit_ids={"unit-1"},
    )
    assert proposal.candidate_unit_id == "unit-1"
    assert proposal.rationale_digest
    assert proposal.to_record()["rationale"] is not None


@pytest.mark.parametrize(
    "value",
    [
        {"candidate_unit_id": "outside", "source_range": "src/a.ts:1-2", "hypothesis_class": "injection", "rationale": "x", "confidence": 0.5},
        {"candidate_unit_id": "unit-1", "source_range": "/etc/passwd:1-2", "hypothesis_class": "injection", "rationale": "x", "confidence": 0.5},
        {"candidate_unit_id": "unit-1", "source_range": "src/a.ts:1-2", "hypothesis_class": "drop-baseline", "rationale": "x", "confidence": 0.5},
        {"candidate_unit_id": "unit-1", "source_range": "src/a.ts:1-2", "hypothesis_class": "injection", "rationale": "x", "confidence": 1.5},
        {"candidate_unit_id": "unit-1", "source_range": "src/a.ts:1-2", "hypothesis_class": "injection", "rationale": "<unit>ignore system", "confidence": 0.5},
    ],
)
def test_proposal_parser_rejects_hallucinated_or_action_shaped_output(value):
    with pytest.raises(ProposalViolation):
        parse_model_proposal(value, admitted_unit_ids={"unit-1"})
