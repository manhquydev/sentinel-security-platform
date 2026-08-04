from __future__ import annotations

import copy
from pathlib import Path

import pytest

from workbench.analysis_population import AnalysisPopulationViolation, build_selection_manifest
from workbench.comparison_pair import build_comparison_pair
from workbench.contracts import ExperimentSpec
from workbench.intake import RepositoryIntake


def spec() -> ExperimentSpec:
    return ExperimentSpec.from_mapping(
        {
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
    )


def unit_descriptors() -> list[dict[str, object]]:
    return [
        {
            "unit_id": f"src/unit-{index:02}.ts:1-1",
            "path": f"src/unit-{index:02}.ts",
            "start_line": 1,
            "end_line": 1,
            "dependency_paths": ["src/context.ts"],
        }
        for index in range(12)
    ]


def sealed_pair(tmp_path: Path):
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    for root, content in ((base, "false"), (candidate, "true")):
        (root / "src").mkdir(parents=True)
        (root / "src" / "context.ts").write_text("export const context = true;\n", encoding="utf-8")
        for index in range(12):
            (root / "src" / f"unit-{index:02}.ts").write_text(
                f"export const unit{index} = {content};\n",
                encoding="utf-8",
            )
    store = RepositoryIntake(
        evidence_root=tmp_path / "evidence",
        approved_roots={"base": base, "candidate": candidate},
        profile="typescript",
    )
    base_snapshot = store.seal_registered_root("base", repository_identity="fixture")
    candidate_snapshot = store.seal_registered_root("candidate", repository_identity="fixture")
    return store, build_comparison_pair(store, base_snapshot.snapshot_id, candidate_snapshot.snapshot_id)


def test_selection_manifest_binds_stable_full_b3_frame_and_same_mask_to_every_arm(tmp_path):
    store, pair = sealed_pair(tmp_path)
    manifest = build_selection_manifest(spec(), store, pair, unit_descriptors())

    assert manifest.document["unit_ids"] == sorted(item["unit_id"] for item in unit_descriptors())
    assert manifest.document["b3_requests"] == 36
    assert set(manifest.document["arms"]) == {"B0", "B1", "B2", "B3"}
    assert len({entry["analysis_mask_digest"] for entry in manifest.document["arms"].values()}) == 1
    assert "export const unit" not in repr(manifest.document)
    assert manifest.slice_for("src/unit-00.ts:1-1")[0] == "export const unit0 = true;\n"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.pop(),
        lambda value: value.append(dict(value[0])),
        lambda value: value.__setitem__(0, {**value[0], "dependency_context": "x" * 8193}),
    ],
)
def test_selection_manifest_refuses_missing_duplicate_or_oversized_b3_units(tmp_path, mutate):
    store, pair = sealed_pair(tmp_path)
    value = copy.deepcopy(unit_descriptors())
    mutate(value)
    with pytest.raises(AnalysisPopulationViolation):
        build_selection_manifest(spec(), store, pair, value)


def test_selection_rejects_a_forged_pair_handle_even_when_its_candidate_is_valid(tmp_path):
    store, pair = sealed_pair(tmp_path)
    forged = type(pair)(
        pair_digest="d" * 64,
        repository_identity=pair.repository_identity,
        base_snapshot_id="0" * 64,
        candidate_snapshot_id=pair.candidate_snapshot_id,
        diff={},
    )
    with pytest.raises(AnalysisPopulationViolation, match="verified"):
        build_selection_manifest(spec(), store, forged, unit_descriptors())
