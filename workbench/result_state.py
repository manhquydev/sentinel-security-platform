"""Exclusive rendering state for Workbench results."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from .contracts import ContractViolation


class ResultState(StrEnum):
    NO_ELIGIBLE_CORPUS = "no-eligible-corpus"
    CASE_STUDY_ONLY = "case-study-only"
    NOT_MEASURED = "not-measured"
    INSTRUMENT_INVALID = "instrument-invalid"
    UNDERPOWERED = "underpowered/descriptive"
    NAMED_CONTRAST = "named-contrast"


@dataclass(frozen=True)
class RenderedResult:
    kind: ResultState
    reason_code: str | None = None
    contrast: str | None = None
    metric: str | None = None
    outcome: str | None = None

    @property
    def suppresses_comparative_language(self) -> bool:
        return self.kind != ResultState.NAMED_CONTRAST


def render_result_state(document: Mapping[str, Any]) -> RenderedResult:
    kind = document.get("kind")
    valid = {state.value for state in ResultState}
    if kind not in valid:
        raise ContractViolation("renderer state must choose one recognised disposition")
    if kind != ResultState.NAMED_CONTRAST:
        reason = document.get("reason_code")
        if not isinstance(reason, str) or not reason:
            raise ContractViolation("non-comparative renderer state requires a reason code")
        extras = set(document) - {"kind", "reason_code"}
        if extras:
            raise ContractViolation("non-comparative renderer must suppress intervals and comparative copy")
        return RenderedResult(ResultState(kind), reason_code=reason)
    if set(document) != {"kind", "corpus_admission_outcome", "contrast", "metric", "interval"}:
        raise ContractViolation("named contrast renderer must contain only its claim-bound fields")
    if document["corpus_admission_outcome"] != "corpus-only":
        raise ContractViolation("only an admitted corpus may render a named comparative result")
    if document["contrast"] != "B3-B2" or document["metric"] != "recall_at_12":
        raise ContractViolation("renderer cannot turn a B1 comparison into an AI win")
    interval = document["interval"]
    if not isinstance(interval, Mapping) or set(interval) != {"lower", "upper"}:
        raise ContractViolation("named contrast must contain both interval bounds")
    lower, upper = interval["lower"], interval["upper"]
    if not all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in (lower, upper)) or lower > upper:
        raise ContractViolation("named contrast interval is invalid")
    if lower > 0.02:
        outcome = "win"
    elif upper < -0.02:
        outcome = "loss"
    elif lower >= -0.02 and upper <= 0.02:
        outcome = "tie"
    else:
        outcome = "inconclusive"
    return RenderedResult(ResultState.NAMED_CONTRAST, contrast="B3-B2", metric="recall_at_12", outcome=outcome)
