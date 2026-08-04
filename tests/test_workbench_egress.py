from __future__ import annotations

import pytest

from workbench.analysis_population import AnalysisPopulationViolation, build_selection_manifest
from workbench.comparison_pair import build_comparison_pair
from workbench.contracts import ExperimentSpec
from workbench.egress import B3Route, EgressViolation, _validate_route, prepare_b3_request, quarantine_response
from workbench.intake import RepositoryIntake


def route(tmp_path) -> B3Route:
    key = tmp_path / "b3-dispatcher.env"
    key.write_text("vk-restricted-only\n", encoding="utf-8")
    key.chmod(0o600)
    return B3Route.from_host_config(
        route_id="workbench-b3-no-trace",
        key_path=key,
        config_digest="a" * 64,
        expected_config_digest="a" * 64,
    )


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


def selection(
    tmp_path,
    *,
    canonical: str = "export const safe = true;\n",
    dependency_context: str = "export const db = true;\n",
):
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    for root in (base, candidate):
        (root / "src").mkdir(parents=True)
        (root / "src" / "context.ts").write_text(dependency_context, encoding="utf-8")
        for index in range(12):
            content = canonical if index == 0 else f"export const unit{index} = true;\n"
            (root / "src" / f"unit-{index}.ts").write_text(content, encoding="utf-8")
    store = RepositoryIntake(
        evidence_root=tmp_path / "evidence",
        approved_roots={"base": base, "candidate": candidate},
        profile="typescript",
    )
    base_snapshot = store.seal_registered_root("base", repository_identity="fixture")
    candidate_snapshot = store.seal_registered_root("candidate", repository_identity="fixture")
    pair = build_comparison_pair(store, base_snapshot.snapshot_id, candidate_snapshot.snapshot_id)
    units = [
        {
            "unit_id": f"src/unit-{index}.ts:1-1",
            "path": f"src/unit-{index}.ts",
            "start_line": 1,
            "end_line": 1,
            "dependency_paths": ["src/context.ts"],
        }
        for index in range(12)
    ]
    return build_selection_manifest(spec(), store, pair, units)


def test_egress_redacts_secret_and_pii_then_persists_metadata_only_digest_record(tmp_path):
    manifest = selection(tmp_path, canonical="const token = 'sk-supersecretvalue012345'; // email alice@example.com\n")
    prepared = prepare_b3_request(
        selection=manifest,
        unit_id="src/unit-0.ts:1-1",
        route=route(tmp_path),
    )

    assert "sk-supersecretvalue012345" not in prepared.prompt
    assert "alice@example.com" not in prepared.prompt
    assert prepared.record["request_digest"]
    assert "prompt" not in prepared.record
    assert prepared.record["redaction_summary"]


def test_public_route_descriptor_is_no_trace_metadata_only_and_never_serializes_the_scoped_key(tmp_path):
    descriptor = route(tmp_path).to_mapping()

    assert descriptor == {
        "route_id": "workbench-b3-no-trace",
        "stream": False,
        "message_body_logging": False,
        "callbacks": [],
        "shared_trace_network": False,
    }
    assert "scoped_key" not in descriptor
    assert "vk-restricted-only" not in repr(route(tmp_path))


@pytest.mark.parametrize(
    "change",
    [
        {"stream": True},
        {"message_body_logging": True},
        {"callbacks": ["langfuse"]},
        {"shared_trace_network": True},
        {"scoped_key": "caller-supplied-key"},
    ],
)
def test_egress_refuses_trace_or_key_fail_open_config(tmp_path, change):
    configured = route(tmp_path).to_mapping()
    configured.update(change)
    with pytest.raises(EgressViolation):
        _validate_route(configured)


def test_public_constructor_cannot_turn_a_caller_supplied_route_id_into_host_authority():
    with pytest.raises(EgressViolation):
        B3Route(route_id="workbench-b3-no-trace")


def test_egress_refuses_oversize_context_and_response_quarantine_rejects_unexpected_fields(tmp_path):
    with pytest.raises(AnalysisPopulationViolation):
        selection(tmp_path, dependency_context="x" * 8193)
    with pytest.raises(EgressViolation):
        quarantine_response(
            {"proposal_ids": ["unit-1"], "raw_provider_body": "secret"},
            admitted_unit_ids={"unit-1"},
        )
    assert quarantine_response({"proposal_ids": ["unit-1"]}, admitted_unit_ids={"unit-1"}).record["response_digest"]


def test_egress_refuses_unredacted_credential_like_material_and_response_ids_outside_the_admitted_frame(tmp_path):
    with pytest.raises(AnalysisPopulationViolation, match="unredacted"):
        selection(
            tmp_path,
            canonical="export const opaque = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';\n",
        )
    with pytest.raises(EgressViolation, match="admitted"):
        quarantine_response(
            {"proposal_ids": ["not-an-admitted-unit"]},
            admitted_unit_ids={"src/unit-01.ts:1-2"},
        )


def test_route_requires_host_configured_restricted_key_and_response_quarantine_requires_frame(tmp_path):
    key = tmp_path / "master.env"
    key.write_text("master-key\n", encoding="utf-8")
    key.chmod(0o600)
    with pytest.raises(EgressViolation, match="restricted"):
        B3Route.from_host_config(
            route_id="workbench-b3-no-trace",
            key_path=key,
            config_digest="a" * 64,
            expected_config_digest="a" * 64,
        )
    with pytest.raises(TypeError):
        quarantine_response({"proposal_ids": ["unit-1"]})
