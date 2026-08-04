"""Deterministic arm admission and execution receipts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .intake import IntakeViolation, RepositoryIntake
from .metrics import ArmMetric
from .run_ledger import RunLedger


class DeterministicRunnerViolation(ValueError):
    """Raised when a B0/B1/B2 run lacks a verified sealed input or completion."""


@dataclass(frozen=True)
class DeterministicRun:
    run_id: str
    arm: str
    snapshot_id: str
    status: str
    metric: dict[str, object] | None
    reason_code: str | None


class DeterministicRunner:
    """Record control-arm completion only after the sealed snapshot gate passes."""

    def __init__(self, intake: RepositoryIntake, ledger: RunLedger) -> None:
        self._intake = intake
        self._ledger = ledger

    def admit(self, *, run_id: str, arm: str, snapshot_id: str) -> None:
        if arm not in {"B0", "B1", "B2"}:
            raise DeterministicRunnerViolation("deterministic runner only admits B0/B1/B2")
        try:
            self._intake.resolve_snapshot(snapshot_id)
        except IntakeViolation as error:
            raise DeterministicRunnerViolation("deterministic runner requires an intact sealed snapshot") from error

    def record_incomplete(self, *, run_id: str, arm: str, snapshot_id: str, reason_code: str) -> DeterministicRun:
        if not reason_code:
            raise DeterministicRunnerViolation("incomplete control run requires a reason code")
        self._ledger.append(
            run_id,
            {
                "record_id": f"{run_id}:{arm}:incomplete",
                "schema_version": "sentinel-workbench-run-receipt/v1",
                "arm": arm,
                "snapshot_id": snapshot_id,
                "status": "incomplete",
                "reason_code": reason_code,
            },
        )
        return DeterministicRun(run_id, arm, snapshot_id, "incomplete", None, reason_code)

    def record_metric(self, *, run_id: str, metric: ArmMetric) -> DeterministicRun:
        document = metric.to_record()
        self._ledger.append(
            run_id,
            {"record_id": f"{run_id}:{metric.arm}:{metric.repository_id}", **document},
        )
        return DeterministicRun(run_id, metric.arm, "", "succeeded", document, None)
