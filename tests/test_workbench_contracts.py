from __future__ import annotations

import copy
import json
from pathlib import Path
from types import MappingProxyType

import pytest

from workbench.contracts import (
    ContractViolation,
    ExperimentSpec,
    TruthManifest,
    validate_corpus_catalog,
    validate_publication,
)
from workbench.result_state import ResultState, render_result_state


ROOT = Path(__file__).resolve().parents[1]
EVALUATION = ROOT / "evaluation" / "workbench"


def valid_spec_data() -> dict:
    return {
        "schema_version": "sentinel-workbench-experiment/v1",
        "primary_contrast": "B3-B2",
        "metric": "recall_at_12",
        "b3_readings": 3,
        "b3_consensus_min_readings": 2,
        "review_packets_per_arm": 12,
        "review_seconds_per_packet": 90,
        "b3_context_cap_bytes": 8192,
        "b3_temperature": 0,
        "b3_top_p": 1,
        "b3_output_cap_tokens": 2048,
        "b3_transport": "chat-only",
        "b3_tools_enabled": False,
        "b3_post_dispatch_retry": False,
        "bootstrap_resamples": 10000,
        "bootstrap_seed": 20260804,
        "minimum_paired_repositories": 20,
        "minimum_power": 0.8,
        "minimum_effect": 0.02,
        "calibration_corpus_digest": "c" * 64,
        "calibration_is_confirmatory": False,
    }


def valid_catalog() -> dict:
    return {
        "schema_version": "sentinel-workbench-corpus-catalog/v1",
        "comparative_status": "eligible-corpus-catalogued",
        "corpora": [
            {
                "corpus_id": "cmc-edu",
                "admission_outcome": "case-study-only",
                "base_snapshot_digest": "a" * 64,
                "candidate_snapshot_digest": "b" * 64,
                "pair_digest": "d" * 64,
                "truth_manifest_digest": "e" * 64,
                "base_revision": "base-cmc",
                "candidate_revision": "candidate-cmc",
                "snapshot_method": "sha256(sealed-manifest)",
                "license": "local-authorized",
                "authorship": "maintainer-authorized-local-case-study",
                "model_cutoff_contamination": "unknown",
                "language_counts": {"TypeScript": 1},
                "class_counts": {"CWE-79": 1},
                "repository_count": 1,
                "repository_power": {"paired_repository_count": 1, "minimum_required": 20, "status": "not-applicable-case-study-only"},
            },
            {
                "corpus_id": "independent-ts-calibration",
                "admission_outcome": "corpus-only",
                "base_snapshot_digest": "f" * 64,
                "candidate_snapshot_digest": "1" * 64,
                "pair_digest": "2" * 64,
                "truth_manifest_digest": "3" * 64,
                "base_revision": "base-independent",
                "candidate_revision": "candidate-independent",
                "snapshot_method": "sha256(sealed-manifest)",
                "license": "CC-BY-4.0",
                "authorship": "independent",
                "model_cutoff_contamination": "screened",
                "language_counts": {"TypeScript": 24},
                "class_counts": {"CWE-79": 24},
                "repository_count": 24,
                "repository_power": {"paired_repository_count": 24, "minimum_required": 20, "status": "eligible"},
            },
        ],
    }


def valid_truth_data() -> dict:
    return {
        "schema_version": "sentinel-workbench-truth-manifest/v1",
        "candidate_snapshot_digest": "b" * 64,
        "negative_universe_unit_ids": ["src/clean.ts:1-4"],
        "control_audit": {"auditor": "independent", "outcome_blind": True, "unplanted_control_ids": ["control-1"]},
        "defects": [
            {
                "vulnerability_id": "CWE-79-001",
                "class": "CWE-79",
                "precondition": "rendered attacker-controlled HTML",
                "canonical_unit_id": "src/render.ts:10-20",
                "allowed_alternatives": ["src/render.ts:12-18"],
                "provenance": "independent-adjudication",
                "license": "CC-BY-4.0",
            }
        ],
    }


def publication_manifest(spec: ExperimentSpec) -> dict:
    return {
        "experiment_spec_digest": spec.digest,
        "primary_contrast": "B3-B2",
        "metric": "recall_at_12",
        "analysis_mask_digest": "a" * 64,
        "candidate_truth_denominator_digest": "b" * 64,
        "calibration_corpus_digest": "c" * 64,
        "calibration_is_confirmatory": False,
        "corpus_id": "independent-ts-calibration",
        "corpus_catalog_digest": "catalog-digest-set-by-test",
        "corpus_admission_outcome": "corpus-only",
        "eligible_repositories": 20,
        "power": 0.81,
        "arms": {
            "B0": {"review_packets": 12, "analysis_mask_digest": "a" * 64, "information_inputs": ["candidate-snapshot"]},
            "B1": {"review_packets": 12, "analysis_mask_digest": "a" * 64, "information_inputs": ["pair-diff", "closure"]},
            "B2": {"review_packets": 12, "analysis_mask_digest": "a" * 64, "information_inputs": ["candidate-snapshot", "stable-order"]},
            "B3": {
                "review_packets": 12,
                "analysis_mask_digest": "a" * 64,
                "readings": 3,
                "requests_per_reading": 18,
                "eligible_units": 18,
                "context_cap_bytes": 8192,
                "information_inputs": ["canonical-unit", "sealed-dependency-context"],
                "resource_vector": {"requests": 54, "source_bytes": 1024, "input_tokens": 500, "output_tokens": 200,
                                    "cost": 0.01, "worker_seconds": 3},
            },
        },
        "repository_attempts": [
            {"repository_id": f"repo-{number}", "terminal": "complete", "admissible_units_by_arm": {"B0": 12, "B1": 12, "B2": 12, "B3": 12}}
            for number in range(20)
        ],
        "interval": {"lower": 0.021, "upper": 0.05},
    }


def test_experiment_spec_rejects_every_changed_frozen_value_and_is_digest_stable():
    spec = ExperimentSpec.from_mapping(valid_spec_data())
    assert spec.digest == ExperimentSpec.from_mapping(valid_spec_data()).digest
    assert isinstance(spec.data, MappingProxyType)
    with pytest.raises(TypeError):
        spec.data["metric"] = "precision_at_12"

    mutable = valid_spec_data()
    for key, value in {
        "primary_contrast": "B3-B1",
        "metric": "precision_at_12",
        "b3_readings": 2,
        "review_packets_per_arm": 11,
        "b3_context_cap_bytes": 8193,
        "b3_temperature": 0.1,
        "b3_transport": "completion",
        "b3_tools_enabled": True,
        "b3_post_dispatch_retry": True,
        "bootstrap_resamples": 9999,
        "minimum_paired_repositories": 19,
        "calibration_is_confirmatory": True,
    }.items():
        invalid = copy.deepcopy(mutable)
        invalid[key] = value
        with pytest.raises(ContractViolation):
            ExperimentSpec.from_mapping(invalid)

    invalid = valid_spec_data()
    del invalid["b3_output_cap_tokens"]
    with pytest.raises(ContractViolation):
        ExperimentSpec.from_mapping(invalid)


def test_json_schemas_and_committed_catalog_are_valid_and_cmc_is_case_study_only():
    for filename in ("experiment-spec.schema.json", "truth-manifest.schema.json", "corpus-catalog.schema.json"):
        schema = json.loads((EVALUATION / filename).read_text(encoding="utf-8"))
        assert schema["$schema"].startswith("https://json-schema.org/")

    catalog = json.loads((EVALUATION / "corpus-catalog.json").read_text(encoding="utf-8"))
    validate_corpus_catalog(catalog)
    cmc = next(corpus for corpus in catalog["corpora"] if corpus["corpus_id"] == "cmc-edu")
    assert cmc["admission_outcome"] == "case-study-only"
    assert cmc["truth_status"] == "not-admitted"
    assert catalog["comparative_status"] == "blocked-no-eligible-typescript-corpus"


def test_catalog_rejects_missing_pair_history_or_private_capability_claim():
    catalog = valid_catalog()
    del catalog["corpora"][0]["pair_digest"]
    with pytest.raises(ContractViolation):
        validate_corpus_catalog(catalog)

    catalog = valid_catalog()
    catalog["corpora"][0]["private_code_capability_claim"] = True
    with pytest.raises(ContractViolation):
        validate_corpus_catalog(catalog)

    catalog = valid_catalog()
    catalog["corpora"][1]["admission_outcome"] = "eligible"
    with pytest.raises(ContractViolation):
        validate_corpus_catalog(catalog)
    for field, value in (("authorship", "self-authored"), ("model_cutoff_contamination", "unknown")):
        catalog = valid_catalog()
        catalog["corpora"][1][field] = value
        with pytest.raises(ContractViolation):
            validate_corpus_catalog(catalog)

    for field in ("base_revision", "candidate_revision", "snapshot_method", "repository_power"):
        catalog = valid_catalog()
        del catalog["corpora"][1][field]
        with pytest.raises(ContractViolation):
            validate_corpus_catalog(catalog)


def test_truth_manifest_claims_once_and_unadjudicated_proposals_are_not_measured():
    truth = TruthManifest.from_mapping(valid_truth_data())
    match = truth.match_proposals(["src/render.ts:12-18", "src/render.ts:10-20", "src/unknown.ts:1-2"])
    assert match.claimed_vulnerability_ids == ("CWE-79-001",)
    assert match.not_measured_unit_ids == ("src/unknown.ts:1-2",)
    assert match.duplicate_claim_unit_ids == ("src/render.ts:10-20",)

    bad = valid_truth_data()
    bad["defects"][0].pop("class")
    with pytest.raises(ContractViolation):
        TruthManifest.from_mapping(bad)

    bad = valid_truth_data()
    bad["control_audit"]["unplanted_control_ids"] = []
    with pytest.raises(ContractViolation):
        TruthManifest.from_mapping(bad)


def test_truth_manifest_rejects_an_alternative_span_shared_by_two_defects():
    bad = valid_truth_data()
    bad["defects"].append(
        {
            "vulnerability_id": "CWE-89-001",
            "class": "CWE-89",
            "precondition": "attacker-controlled query fragment",
            "canonical_unit_id": "src/query.ts:20-30",
            "allowed_alternatives": ["src/render.ts:12-18"],
            "provenance": "independent-adjudication",
            "license": "CC-BY-4.0",
        }
    )
    with pytest.raises(ContractViolation):
        TruthManifest.from_mapping(bad)


def test_publication_rejects_pooled_or_b3_input_or_calibration_failures():
    spec = ExperimentSpec.from_mapping(valid_spec_data())
    valid = publication_manifest(spec)
    catalog = valid_catalog()
    valid["corpus_catalog_digest"] = __import__("workbench.contracts", fromlist=["catalog_digest"]).catalog_digest(catalog)
    validate_publication(valid, spec, catalog)

    for mutate in (
        lambda document: document.update({"eligible_repositories": 19}),
        lambda document: document["arms"]["B3"].update({"readings": 2}),
        lambda document: document["arms"]["B3"].update({"requests_per_reading": 17}),
        lambda document: document["arms"]["B3"].update({"context_cap_bytes": 8193}),
        lambda document: document["arms"]["B3"].update({"information_inputs": ["raw-repository-source"]}),
        lambda document: document["arms"]["B1"].update({"analysis_mask_digest": "d" * 64}),
        lambda document: document.update({"corpus_admission_outcome": "case-study-only"}),
        lambda document: document.update({"corpus_catalog_digest": "0" * 64}),
        lambda document: document.update({"calibration_is_confirmatory": True}),
        lambda document: document["repository_attempts"][0]["admissible_units_by_arm"].update({"B1": 11}),
        lambda document: document["repository_attempts"][0].update({"terminal": "missing-b3"}),
    ):
        broken = copy.deepcopy(valid)
        mutate(broken)
        with pytest.raises(ContractViolation):
            validate_publication(broken, spec, catalog)


@pytest.mark.parametrize(
    ("interval", "expected"),
    [
        ({"lower": 0.0201, "upper": 0.07}, "win"),
        ({"lower": -0.07, "upper": -0.0201}, "loss"),
        ({"lower": -0.02, "upper": 0.02}, "tie"),
        ({"lower": -0.02, "upper": 0.04}, "inconclusive"),
    ],
)
def test_renderer_named_contrast_boundaries(interval, expected):
    state = render_result_state(
        {"kind": "named-contrast", "corpus_admission_outcome": "corpus-only", "contrast": "B3-B2", "metric": "recall_at_12", "interval": interval}
    )
    assert state.kind == ResultState.NAMED_CONTRAST
    assert state.outcome == expected


def test_renderer_is_exclusive_and_never_turns_b1_or_absent_claim_bound_into_ai_win():
    state = render_result_state({"kind": "underpowered/descriptive", "reason_code": "insufficient-clusters"})
    assert state.kind == ResultState.UNDERPOWERED
    assert state.suppresses_comparative_language

    for manifest in (
        {"kind": "named-contrast", "corpus_admission_outcome": "case-study-only", "contrast": "B3-B2", "metric": "recall_at_12", "interval": {"lower": 0.1, "upper": 0.2}},
        {"kind": "named-contrast", "corpus_admission_outcome": "corpus-only", "contrast": "B3-B1", "metric": "recall_at_12", "interval": {"lower": 0.1, "upper": 0.2}},
        {"kind": "named-contrast", "corpus_admission_outcome": "corpus-only", "contrast": "B3-B2", "metric": "recall_at_12"},
        {"kind": "instrument-invalid"},
    ):
        with pytest.raises(ContractViolation):
            render_result_state(manifest)
