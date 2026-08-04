from __future__ import annotations

from pathlib import Path

import pytest

from workbench.artifacts import PrivateArtifactStore
from workbench.intake import RepositoryIntake
from workbench.metrics import ArmMetric, MetricsViolation
from workbench.run_ledger import LedgerViolation, RunLedger
from workbench.runner import DeterministicRunner


def fixture_store(tmp_path: Path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.ts").write_text("export const app = true;\n", encoding="utf-8")
    store = RepositoryIntake(
        evidence_root=tmp_path / "evidence",
        approved_roots={"repo": root},
        profile="typescript",
    )
    return store, store.seal_registered_root("repo", repository_identity="fixture")


def test_deterministic_runner_requires_sealed_input_and_records_incomplete_without_calling_it_clean(tmp_path):
    store, snapshot = fixture_store(tmp_path)
    artifacts = PrivateArtifactStore(tmp_path / "artifacts")
    run = artifacts.begin_run("run-1")
    ledger = RunLedger(tmp_path / "ledger.jsonl", artifacts)
    runner = DeterministicRunner(store, ledger)
    receipt = runner.record_incomplete(
        run_id=run,
        arm="B0",
        snapshot_id=snapshot.snapshot_id,
        reason_code="scanner-not-ready",
    )
    assert receipt.status == "incomplete"
    with pytest.raises(Exception):
        runner.admit(run_id=run, arm="B0", snapshot_id="0" * 64)


def test_metrics_and_ledger_are_bounded_and_append_only(tmp_path):
    artifacts = PrivateArtifactStore(tmp_path / "artifacts")
    run = artifacts.begin_run("run-1")
    ledger = RunLedger(tmp_path / "ledger.jsonl", artifacts)
    metric = ArmMetric("B2", "repo-1", "a" * 64, 12, 3, 4, 1.5)
    ledger.append(run, {"record_id": "r1", **metric.to_record()})
    with pytest.raises(LedgerViolation):
        ledger.append(run, {"record_id": "r1", **metric.to_record()})
    with pytest.raises(MetricsViolation):
        ArmMetric("B2", "repo-1", "a" * 64, 11, 3, 4, 1.5).to_record()
