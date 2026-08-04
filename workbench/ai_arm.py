"""Constrained B3 three-reading consensus worklist."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .analysis_population import SelectionManifest
from .b3_dispatcher import B3Dispatcher


class AIArmViolation(ValueError):
    """Raised when B3 cannot complete its fixed information/resource contract."""


@dataclass(frozen=True)
class B3Consensus:
    readings: int
    requests: int
    consensus_unit_ids: tuple[str, ...]
    recurrence: Mapping[str, int]
    non_answer_count: int
    config_digest: str


def run_b3_consensus(
    *,
    run_id: str,
    selection: SelectionManifest,
    dispatcher: B3Dispatcher,
    config_digest: str,
) -> B3Consensus:
    if not isinstance(run_id, str) or not run_id or not selection.is_authorized() or type(dispatcher) is not B3Dispatcher:
        raise AIArmViolation("B3 requires a labelled run, host-owned selection, and host dispatcher")
    ids = sorted(selection.unit_ids)
    if len(ids) < 12 or len(config_digest) != 64:
        raise AIArmViolation("B3 requires at least twelve frozen units and a config digest")
    recurrence: dict[str, int] = {unit_id: 0 for unit_id in ids}
    non_answers = 0
    for reading in range(1, 4):
        for unit_id in ids:
            try:
                receipt = dispatcher.dispatch(
                    run_id=run_id,
                    selection=selection,
                    reading=reading,
                    unit_id=unit_id,
                )
            except Exception as error:
                raise AIArmViolation("B3 host dispatch failed closed") from error
            if receipt.status != "succeeded" or receipt.unit_id != unit_id or receipt.reading != reading:
                raise AIArmViolation("B3 host dispatch returned an invalid receipt")
            if not receipt.proposal_ids:
                non_answers += 1
            for proposal_id in receipt.proposal_ids:
                recurrence[proposal_id] = recurrence.get(proposal_id, 0) + 1
    consensus = tuple(sorted((unit_id for unit_id, count in recurrence.items() if count >= 2), key=lambda item: (-recurrence[item], item)))
    if len(consensus) < 12:
        raise AIArmViolation("B3 consensus worklist is short and therefore instrument-invalid")
    return B3Consensus(3, len(ids) * 3, consensus[:12], {key: value for key, value in recurrence.items() if value}, non_answers, config_digest)
