from __future__ import annotations

import copy
from pathlib import Path

import pytest

from workbench.scanner_contracts import (
    ScannerContractViolation,
    ScannerCapabilityManifest,
    default_engine_statuses,
)


DIGEST = "a" * 64


def engine(engine_id: str, parser: str, **overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "engine": engine_id,
        "language_scope": ["TypeScript"],
        "file_scope": ["**/*.ts"],
        "image": f"example/{engine_id}@sha256:{DIGEST}",
        "image_digest": DIGEST,
        "cli_digest": DIGEST,
        "tool_version": "1.0.0",
        "policy_digest": DIGEST,
        "acquisition": {"ruleset_digest": DIGEST},
        "parser": parser,
        "network_policy": "source-mounted-network-none",
        "unsupported_coverage": ["unsupported-fixtures"],
        "completion": {
            "runner_metadata": "present",
            "raw_artifact": "present",
            "parse": "complete",
        },
    }
    result.update(overrides)
    return result


def manifest() -> dict[str, object]:
    return {
        "schema_version": "sentinel-workbench-scanner-capability/v1",
        "profile": "fixture-typescript",
        "snapshot_id": "b" * 64,
        "config_digest": "c" * 64,
        "engines": [
            engine(
                "codeql",
                "sarif",
                language_scope=["JavaScript", "TypeScript", "GitHub Actions"],
                file_scope=["**/*.js", "**/*.ts", "**/*.tsx", ".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"],
                acquisition={
                    "distribution_digest": DIGEST,
                    "query_suite_digest": DIGEST,
                    "database_creation_policy_digest": DIGEST,
                },
                completion={
                    "runner_metadata": "present",
                    "raw_artifact": "present",
                    "parse": "complete",
                    "database": "complete",
                    "sarif": "present",
                    "conversion": "complete",
                },
            ),
            engine(
                "semgrep",
                "semgrep-json",
                language_scope=["TypeScript", "TSX", "YAML"],
                file_scope=["**/*.ts", "**/*.tsx", "**/*.yml", "**/*.yaml"],
            ),
            engine(
                "trivy",
                "trivy-json",
                language_scope=["filesystem", "config", "secret"],
                file_scope=["**/*"],
                acquisition={"db_snapshot_digest": DIGEST},
                completion={
                    "runner_metadata": "present",
                    "raw_artifact": "present",
                    "parse": "complete",
                    "database": "current",
                },
            ),
        ],
    }


def test_capability_manifest_requires_the_complete_frozen_three_engine_b0_contract():
    parsed = ScannerCapabilityManifest.from_mapping(manifest())

    assert parsed.profile == "fixture-typescript"
    assert [item.engine for item in parsed.engines] == ["codeql", "semgrep", "trivy"]
    assert parsed.run_admission()["state"] == "admitted"


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda value: value["engines"].pop(), "exactly CodeQL, Semgrep and Trivy"),
        (lambda value: value["engines"][0].update(image="example/codeql:latest"), "digest pinned"),
        (lambda value: value["engines"][1].update(policy_digest="not-a-digest"), "sha256"),
        (lambda value: value["engines"][1].pop("acquisition"), "exact v1 fields"),
        (lambda value: value["engines"][1].pop("cli_digest"), "exact v1 fields"),
        (lambda value: value["engines"][0]["completion"].update(database="unfinished"), "completion"),
        (lambda value: value["engines"][0]["completion"].pop("sarif"), "completion"),
        (lambda value: value["engines"][0]["completion"].update(conversion="skipped"), "completion"),
        (lambda value: value["engines"][2]["completion"].pop("runner_metadata"), "completion"),
        (lambda value: value["engines"][2].update(network_policy="networked"), "network"),
    ],
)
def test_missing_or_incomplete_b0_admission_metadata_fails_closed(mutate, expected):
    value = copy.deepcopy(manifest())
    mutate(value)
    with pytest.raises(ScannerContractViolation, match=expected):
        ScannerCapabilityManifest.from_mapping(value)


def test_default_statuses_report_missing_pins_as_not_ready_instead_of_a_clean_outcome(tmp_path):
    pins = tmp_path / "image-pins.env"
    pins.write_text(
        'TRIVY_IMAGE="aquasec/trivy@sha256:' + DIGEST + '"\nSEMGREP_IMAGE=""\n',
        encoding="utf-8",
    )

    statuses = default_engine_statuses(pins)

    assert statuses["codeql"]["state"] == "not-ready"
    assert statuses["semgrep"]["state"] == "not-ready"
    assert statuses["trivy"]["state"] == "not-ready"
    assert all(status["state"] != "clean" for status in statuses.values())


def test_default_statuses_become_ready_when_image_pins_and_frozen_b0_policy_match():
    pins = Path("scanners/image-pins.env")
    policy = Path("scanners/workbench-b0")

    statuses = default_engine_statuses(pins, policy_root=policy)

    assert statuses["codeql"]["state"] == "ready"
    assert statuses["semgrep"]["state"] == "ready"
    assert statuses["trivy"]["state"] == "ready"
    assert all(status["state"] != "clean" for status in statuses.values())
    assert "sha256:" in statuses["semgrep"]["image"]


def test_default_statuses_reject_tampered_frozen_ruleset_digest(tmp_path):
    import hashlib
    import json
    import shutil

    pins = tmp_path / "image-pins.env"
    pins.write_text(Path("scanners/image-pins.env").read_text(encoding="utf-8"), encoding="utf-8")
    policy_root = tmp_path / "workbench-b0"
    shutil.copytree(Path("scanners/workbench-b0"), policy_root)
    ruleset = policy_root / "semgrep" / "frozen.yml"
    ruleset.write_text(ruleset.read_text(encoding="utf-8") + "\n# tamper\n", encoding="utf-8")

    statuses = default_engine_statuses(pins, policy_root=policy_root)

    assert statuses["semgrep"]["state"] == "not-ready"
    assert statuses["semgrep"]["reason"] == "missing-frozen-typescript-yaml-ruleset"
    # Untampered engines remain ready when their files still match.
    assert statuses["codeql"]["state"] == "ready"
    assert statuses["trivy"]["state"] == "ready"
    # policy.json digest fields still point at the pre-tamper ruleset hash
    policy = json.loads((policy_root / "policy.json").read_text(encoding="utf-8"))
    assert policy["engines"]["semgrep"]["acquisition"]["ruleset_digest"] != hashlib.sha256(
        ruleset.read_bytes()
    ).hexdigest()


@pytest.mark.parametrize(
    ("engine_index", "language_scope"),
    [
        (0, ["TypeScript"]),
        (1, ["TypeScript"]),
        (2, ["filesystem"]),
    ],
)
def test_capability_manifest_rejects_a_b0_engine_with_required_scope_removed(engine_index, language_scope):
    value = manifest()
    value["engines"][engine_index]["language_scope"] = language_scope

    with pytest.raises(ScannerContractViolation, match="language scope"):
        ScannerCapabilityManifest.from_mapping(value)
