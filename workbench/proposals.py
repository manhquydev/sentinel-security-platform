"""Strict, untrusted B3 proposal parser."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from agent import pii
from infra.litellm.guardrails import egress_redaction


class ProposalViolation(ValueError):
    """Raised when model output is not a bounded hypothesis proposal."""


_RANGE = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9._/@+-]+:\d+-\d+$")
_CLASSES = {"injection", "auth", "secrets", "configuration", "routing", "data-flow", "other"}


@dataclass(frozen=True)
class ModelProposal:
    candidate_unit_id: str
    source_range: str
    hypothesis_class: str
    rationale_digest: str
    confidence: float
    rationale: str

    def to_record(self) -> dict[str, object]:
        return {
            "schema_version": "sentinel-workbench-model-proposal/v1",
            "candidate_unit_id": self.candidate_unit_id,
            "source_range": self.source_range,
            "hypothesis_class": self.hypothesis_class,
            "rationale": self.rationale,
            "rationale_digest": self.rationale_digest,
            "confidence": self.confidence,
        }


def parse_model_proposal(value: object, *, admitted_unit_ids: set[str] | frozenset[str]) -> ModelProposal:
    if not isinstance(value, dict) or set(value) != {
        "candidate_unit_id",
        "source_range",
        "hypothesis_class",
        "rationale",
        "confidence",
    }:
        raise ProposalViolation("model proposal must use the exact bounded schema")
    unit_id = value["candidate_unit_id"]
    source_range = value["source_range"]
    hypothesis = value["hypothesis_class"]
    rationale = value["rationale"]
    confidence = value["confidence"]
    if (
        not admitted_unit_ids
        or not isinstance(unit_id, str)
        or unit_id not in admitted_unit_ids
        or not isinstance(source_range, str)
        or _RANGE.fullmatch(source_range) is None
        or not isinstance(hypothesis, str)
        or hypothesis not in _CLASSES
        or not isinstance(rationale, str)
        or not rationale.strip()
        or len(rationale) > 512
        or not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not 0 <= float(confidence) <= 1
        or any(marker in rationale.lower() for marker in ("<unit>", "ignore previous", "drop finding", "suppress"))
    ):
        raise ProposalViolation("model proposal contains an unknown, action-shaped, or unbounded field")
    try:
        secret_redacted, secret_findings = egress_redaction.redact(rationale)
        pii_redacted, pii_findings = pii.redact(secret_redacted)
    except Exception as error:
        raise ProposalViolation("proposal rationale redaction failed closed") from error
    if secret_findings or pii_findings or pii_redacted != rationale:
        raise ProposalViolation("proposal rationale contains secret/PII material")
    digest = hashlib.sha256(rationale.encode("utf-8")).hexdigest()
    return ModelProposal(unit_id, source_range, hypothesis, digest, float(confidence), rationale)
