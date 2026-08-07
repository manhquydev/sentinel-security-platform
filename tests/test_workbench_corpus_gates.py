from __future__ import annotations

import json
from pathlib import Path

import pytest

from workbench.corpus_gates import (
    MINIMUM_INDEPENDENT_CLUSTERS,
    evaluate_inventory_admission,
)


def _inventory(clusters: list[str]) -> dict:
    entries = []
    for index, cluster in enumerate(clusters):
        entries.append(
            {
                "cve": f"CVE-2020-{index:04d}",
                "repository_cluster": cluster,
                "source_evidence": {
                    "state": "candidate-needs-adjudication",
                    "remaining_gates": [
                        "frozen-truth-manifest",
                        "license-and-authorship-screen",
                        "model-cutoff-contamination-screen",
                        "independent-outcome-blind-control-audit",
                        "separate-non-confirmatory-calibration",
                        "at-least-20-independent-repository-clusters",
                    ],
                },
            }
        )
    return {
        "schema_version": "sentinel-workbench-candidate-corpus-inventory/v1",
        "entries": entries,
        "admission_decision": "not-admitted",
        "comparative_status": "blocked-no-eligible-typescript-corpus",
        "eligible_repository_cluster_count": len(clusters),
    }


def test_two_candidates_remain_not_admitted_even_with_other_evidence(tmp_path):
    truth = tmp_path / "truth.json"
    truth.write_text(json.dumps({"findings": [{"id": "f1"}]}), encoding="utf-8")
    screen = tmp_path / "contam.json"
    screen.write_text(json.dumps({"screened": True}), encoding="utf-8")
    evidence = {
        "truth": {"truth_manifest_path": str(truth)},
        "license_authorship": {"license": "MIT", "authorship": "independent"},
        "contamination": {
            "model_cutoff_contamination": "screened",
            "screen_record_path": str(screen),
        },
        "control_audit": {"outcome_blind": True, "unplanted_control_ids": ["c1"]},
        "calibration": {
            "calibration_is_confirmatory": False,
            "calibration_corpus_digest": "a" * 64,
        },
    }
    ledger = evaluate_inventory_admission(
        _inventory(["github.com/a/one", "github.com/b/two"]),
        gate_evidence=evidence,
    )
    assert ledger["admission_decision"] == "not-admitted"
    assert ledger["independent_repository_cluster_count"] == 2
    assert ledger["independent_repository_cluster_count"] < MINIMUM_INDEPENDENT_CLUSTERS
    assert "at-least-20-independent-repository-clusters" in ledger["remaining_gates"]
    assert ledger["comparative_status"] == "blocked-no-eligible-typescript-corpus"


def test_twenty_clusters_without_other_gates_still_not_admitted():
    clusters = [f"github.com/org/repo{i}" for i in range(20)]
    ledger = evaluate_inventory_admission(_inventory(clusters))
    assert ledger["admission_decision"] == "not-admitted"
    assert ledger["independent_repository_cluster_count"] == 20
    assert "frozen-truth-manifest" in ledger["remaining_gates"]


def test_all_gates_and_twenty_clusters_report_ready_for_catalog_not_auto_written(tmp_path):
    truth = tmp_path / "truth.json"
    truth.write_text(json.dumps({"findings": [{"id": "f1"}], "anchors": ["a1"]}), encoding="utf-8")
    screen = tmp_path / "contam.json"
    screen.write_text(json.dumps({"screened": True, "model": "cutoff-x"}), encoding="utf-8")
    evidence = {
        "truth": {"truth_manifest_path": str(truth)},
        "license_authorship": {"license": "Apache-2.0", "authorship": "independent"},
        "contamination": {
            "model_cutoff_contamination": "screened",
            "screen_record_path": str(screen),
        },
        "control_audit": {"outcome_blind": True, "unplanted_control_ids": ["c1", "c2"]},
        "calibration": {
            "calibration_is_confirmatory": False,
            "calibration_corpus_digest": "b" * 64,
        },
    }
    clusters = [f"github.com/org/repo{i}" for i in range(20)]
    ledger = evaluate_inventory_admission(_inventory(clusters), gate_evidence=evidence)
    assert ledger["admission_decision"] == "admitted-ready-for-catalog"
    assert ledger["remaining_gates"] == []
    assert ledger["comparative_status"] == "eligible-corpus-catalogued"
    # Gate module never mutates catalog; readiness is report-only.
    assert "does not write the catalog" in ledger["notes"]
