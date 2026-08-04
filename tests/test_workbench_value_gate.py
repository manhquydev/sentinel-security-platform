from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from workbench.contracts import ContractViolation
from workbench.value_gate import CmcValueGate, assert_cmc_feature_allowed, evaluate_cmc_value_gate, not_run_cmc_value_gate

ROOT = Path(__file__).resolve().parents[1]


def census(decisions: int = 24, seconds: list[int] | None = None) -> dict:
    return {
        "schema_version": "sentinel-workbench-cmc-census/v1",
        "decision_volume": decisions,
        "review_seconds": seconds or [60] * 24,
        "minimum_decision_volume": 20,
        "maximum_median_review_seconds": 90,
    }


def test_value_gate_persists_passed_and_terminal_digest():
    gate = evaluate_cmc_value_gate(census())
    assert gate.status == CmcValueGate.PASSED
    assert gate.numerator == 24
    assert gate.denominator == 24
    assert gate.digest
    assert gate.timing_summary["median_seconds"] == 60


@pytest.mark.parametrize(
    ("document", "status"),
    [
        (census(decisions=19), CmcValueGate.FAILED),
        (census(seconds=[91] * 24), CmcValueGate.FAILED),
        ({"schema_version": "sentinel-workbench-cmc-census/v1", "decision_volume": 24}, CmcValueGate.INVALID),
    ],
)
def test_value_gate_rejects_bad_measurement_and_remains_research_negative(document, status):
    gate = evaluate_cmc_value_gate(document)
    assert gate.status == status
    assert gate.reason
    for feature in ("catalog", "approval", "dispatch", "demo"):
        with pytest.raises(ContractViolation):
            assert_cmc_feature_allowed(gate, feature)


def test_only_a_passed_gate_permits_cmc_actions():
    gate = evaluate_cmc_value_gate(census())
    for feature in ("catalog", "approval", "dispatch", "demo"):
        assert_cmc_feature_allowed(gate, feature) is None


def test_not_run_is_a_terminal_research_negative_that_blocks_cmc_actions():
    gate = not_run_cmc_value_gate("no-timed-census-record")
    assert gate.status == CmcValueGate.NOT_RUN
    assert gate.reason == "no-timed-census-record"
    for feature in ("catalog", "approval", "dispatch", "demo"):
        with pytest.raises(ContractViolation):
            assert_cmc_feature_allowed(gate, feature)


@pytest.mark.parametrize("sample_count", [19, 31])
def test_value_gate_requires_the_preregistered_20_to_30_timed_review_decisions(sample_count):
    gate = evaluate_cmc_value_gate(census(seconds=[60] * sample_count))
    assert gate.status == CmcValueGate.INVALID
    for feature in ("catalog", "approval", "dispatch", "demo"):
        with pytest.raises(ContractViolation):
            assert_cmc_feature_allowed(gate, feature)


def test_terminal_record_cannot_be_forged_without_measurement_fields():
    with pytest.raises(ContractViolation):
        evaluate_cmc_value_gate(
            {
                "schema_version": "sentinel-workbench-cmc-census/v1",
                "decision_volume": 24,
                "review_seconds": [60] * 24,
                "minimum_decision_volume": 20,
                "maximum_median_review_seconds": 90,
                "status": "passed",
            }
        )


def test_census_script_writes_a_derived_terminal_record(tmp_path):
    source = tmp_path / "census.json"
    output = tmp_path / "cmc-value-gate.json"
    source.write_text(json.dumps(census()), encoding="utf-8")
    completed = subprocess.run(
        ["bash", str(ROOT / "scripts" / "workbench-value-census.sh"), str(source), str(output)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    record = json.loads(output.read_text(encoding="utf-8"))
    assert record["status"] == "passed"
    assert record["digest"]
