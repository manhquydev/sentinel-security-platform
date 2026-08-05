from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from workbench.scanner_contracts import ScannerCapabilityManifest
from workbench.scanner_runner import FixtureScannerRunner, RunnerViolation
from workbench.sealed_store import SealedFixtureStore


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "workbench" / "fixtures" / "typescript-graph"
TRIVY_CACHE_FILES = {"db/trivy.db": b"fixture Trivy DB\n"}


def trivy_cache_digest() -> str:
    files = [
        {
            "path": path,
            "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content),
        }
        for path, content in sorted(TRIVY_CACHE_FILES.items())
    ]
    return hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


TRIVY_DB_SNAPSHOT_DIGEST = trivy_cache_digest()


def contract(
    snapshot_id: str, trivy_db_snapshot_digest: str = TRIVY_DB_SNAPSHOT_DIGEST
) -> ScannerCapabilityManifest:
    digest = "a" * 64
    engine = lambda name, parser: {
        "engine": name,
        "language_scope": (
            ["JavaScript", "TypeScript", "GitHub Actions"]
            if name == "codeql"
            else ["TypeScript", "TSX", "YAML"]
            if name == "semgrep"
            else ["filesystem", "config", "secret"]
        ),
        "file_scope": (
            ["**/*.js", "**/*.ts", "**/*.tsx", ".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"]
            if name == "codeql"
            else ["**/*.ts", "**/*.tsx", "**/*.yml", "**/*.yaml"]
            if name == "semgrep"
            else ["**/*"]
        ),
        "image": f"example/{name}@sha256:{digest}",
        "image_digest": digest,
        "cli_digest": digest,
        "tool_version": "1.0.0",
        "policy_digest": digest,
        "acquisition": (
            {
                "distribution_digest": digest,
                "query_suite_digest": digest,
                "database_creation_policy_digest": digest,
            }
            if name == "codeql"
            else {"db_snapshot_digest": trivy_db_snapshot_digest}
            if name == "trivy"
            else {"ruleset_digest": digest}
        ),
        "parser": parser,
        "network_policy": "source-mounted-network-none",
        "unsupported_coverage": ["none"],
        "completion": {
            "runner_metadata": "present",
            "raw_artifact": "present",
            "parse": "complete",
            **({"database": "complete", "sarif": "present", "conversion": "complete"} if name == "codeql" else {}),
            **({"database": "current"} if name == "trivy" else {}),
        },
    }
    return ScannerCapabilityManifest.from_mapping(
        {
            "schema_version": "sentinel-workbench-scanner-capability/v1",
            "profile": "fixture-typescript",
            "snapshot_id": snapshot_id,
            "config_digest": "b" * 64,
            "engines": [engine("codeql", "sarif"), engine("semgrep", "semgrep-json"), engine("trivy", "trivy-json")],
        }
    )


def copied_fixture(tmp_path: Path) -> tuple[SealedFixtureStore, str]:
    fixture_root = tmp_path / "fixtures"
    source = fixture_root / "typescript-graph"
    source.mkdir(parents=True)
    for item in FIXTURE.rglob("*"):
        if item.is_file():
            target = source / item.relative_to(FIXTURE)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(item.read_bytes())
    store = SealedFixtureStore(tmp_path / "private", fixture_root)
    return store, store.seal_fixture(source, fixture_id="typescript-graph").snapshot_id


def prepared_dependencies(tmp_path: Path, capability: ScannerCapabilityManifest) -> Path:
    root = tmp_path / "prepared"
    root.mkdir(mode=0o700)
    for item in capability.engines:
        path = root / item.engine / item.acquisition_digest
        path.mkdir(parents=True, mode=0o700)
        if item.engine == "codeql":
            (path / "query-suite.qls").write_text("- queries: .\n", encoding="utf-8")
            (path / "query-pack").mkdir(mode=0o700)
        elif item.engine == "semgrep":
            (path / "frozen.yml").write_text("rules: []\n", encoding="utf-8")
        else:
            cache = path / "cache"
            for relative, content in TRIVY_CACHE_FILES.items():
                target = cache / relative
                target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                target.write_bytes(content)
                target.chmod(0o600)
            cache.chmod(0o700)
            metadata_path = path / "metadata.json"
            metadata_path.write_text(
                json.dumps(
                    {
                        "db_snapshot_digest": item.acquisition["db_snapshot_digest"],
                        "schema_version": "sentinel-workbench-trivy-db-snapshot/v1",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            metadata_path.chmod(0o600)
    return root


def test_runner_resolves_only_a_registered_sealed_copy_and_network_isolates_source_mounts(tmp_path):
    store, snapshot_id = copied_fixture(tmp_path)
    capability = contract(snapshot_id)
    runner = FixtureScannerRunner(
        store, capability, prepared_dependencies(tmp_path, capability), tmp_path / "raw-artifacts"
    )

    command = runner.command_for("semgrep", snapshot_id)

    assert command[:5] == ("docker", "run", "--rm", "--network", "none")
    assert any(str(store.resolve(snapshot_id).root) in argument and argument.endswith(":/src:ro") for argument in command)
    assert any(argument.endswith(":/rules:ro") for argument in command)
    assert "defectdojo" not in " ".join(command).lower()
    with pytest.raises(RunnerViolation):
        runner.command_for("semgrep", "f" * 64)


def test_runner_refuses_non_manifest_engine_and_does_not_accept_a_direct_path(tmp_path):
    store, snapshot_id = copied_fixture(tmp_path)
    capability = contract(snapshot_id)
    runner = FixtureScannerRunner(
        store, capability, prepared_dependencies(tmp_path, capability), tmp_path / "raw-artifacts"
    )

    with pytest.raises(RunnerViolation):
        runner.command_for("nuclei", snapshot_id)
    with pytest.raises(TypeError):
        runner.command_for("semgrep", FIXTURE)  # type: ignore[arg-type]


def test_runner_quarantines_only_successfully_normalized_raw_artifacts_with_reconciled_counts(tmp_path):
    store, snapshot_id = copied_fixture(tmp_path)
    capability = contract(snapshot_id)
    raw_root = tmp_path / "raw-artifacts"
    runner = FixtureScannerRunner(store, capability, prepared_dependencies(tmp_path, capability), raw_root)

    receipt = runner.capture_raw_artifact(
        "semgrep",
        snapshot_id,
        {
            "results": [
                {
                    "check_id": "fixture.rule",
                    "path": "src/main.ts",
                    "start": {"line": 1},
                    "extra": {"message": "fixture finding", "severity": "WARNING"},
                }
            ],
            "errors": [],
            "paths": {"scanned": ["src/main.ts"]},
        },
    )

    artifact = raw_root / snapshot_id / "semgrep" / f"{receipt['raw_artifact_digest']}.json"
    assert receipt["reported_count"] == receipt["normalized_count"] == 1
    assert artifact.is_file()
    assert artifact.stat().st_mode & 0o077 == 0

    with pytest.raises(RunnerViolation):
        runner.capture_raw_artifact(
            "semgrep",
            snapshot_id,
            {"results": [], "errors": [], "paths": {"scanned": ["src/a.ts"], "skipped": [{"path": "src/b.ts"}]}},
        )


def test_runner_never_attempts_to_analyze_the_read_only_source_mount_as_a_codeql_database(tmp_path):
    store, snapshot_id = copied_fixture(tmp_path)
    capability = contract(snapshot_id)
    runner = FixtureScannerRunner(
        store, capability, prepared_dependencies(tmp_path, capability), tmp_path / "raw-artifacts"
    )

    command = runner.command_for("codeql", snapshot_id)

    script = command[-1]
    assert "codeql database analyze /src" not in script
    assert "codeql database create --db-cluster" in script
    assert "-- /work/database-cluster" in script
    assert "--db-cluster" in script
    assert "--source-root=/src" in script
    assert "--command" not in script
    assert "command true" not in script
    assert "-- /work/database-cluster/javascript-typescript /prepared/query-suite.qls" in script
    assert "-- /work/database-cluster/actions /prepared/query-suite.qls" in script
    assert "--output=/work/javascript-typescript.sarif" in script
    assert "--output=/work/actions.sarif" in script
    assert "/prepared/query-suite.qls" in script
    assert "--search-path=/prepared/query-pack" in script
    assert "--language=javascript-typescript,actions" in script


def test_trivy_fixture_command_freezes_all_scanners_offline_controls_and_a_read_only_cache(tmp_path):
    store, snapshot_id = copied_fixture(tmp_path)
    capability = contract(snapshot_id)
    prepared = prepared_dependencies(tmp_path, capability)
    runner = FixtureScannerRunner(store, capability, prepared, tmp_path / "raw-artifacts")

    command = runner.command_for("trivy", snapshot_id)

    assert "--scanners" in command
    assert command[command.index("--scanners") + 1] == "vuln,misconfig,secret"
    for flag in (
        "--offline-scan",
        "--skip-db-update",
        "--skip-java-db-update",
        "--skip-check-update",
        "--skip-version-check",
        "--disable-telemetry",
    ):
        assert flag in command
    assert (
        f"{prepared / 'trivy' / capability.engine('trivy').acquisition_digest / 'cache'}:"
        "/root/.cache/trivy:ro"
    ) in command


@pytest.mark.parametrize(
    ("metadata", "expected"),
    [
        (None, "incomplete"),
        (
            {
                "schema_version": "sentinel-workbench-trivy-db-snapshot/v1",
                "db_snapshot_digest": "f" * 64,
            },
            "does not match",
        ),
        (
            {
                "db_snapshot_digest": "a" * 64,
                "schema_version": "sentinel-workbench-trivy-db-snapshot/v1",
                "extra": "not allowed",
            },
            "canonical",
        ),
    ],
)
def test_trivy_runner_refuses_missing_or_noncanonical_metadata_not_bound_to_the_manifest(
    tmp_path, metadata, expected
):
    store, snapshot_id = copied_fixture(tmp_path)
    capability = contract(snapshot_id)
    prepared = prepared_dependencies(tmp_path, capability)
    metadata_path = prepared / "trivy" / capability.engine("trivy").acquisition_digest / "metadata.json"
    if metadata is None:
        metadata_path.unlink()
    else:
        metadata_path.write_text(
            json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        metadata_path.chmod(0o600)
    runner = FixtureScannerRunner(store, capability, prepared, tmp_path / "raw-artifacts")

    with pytest.raises(RunnerViolation, match=expected):
        runner.command_for("trivy", snapshot_id)


def test_trivy_runner_refuses_a_nonprivate_prepared_db_manifest(tmp_path):
    store, snapshot_id = copied_fixture(tmp_path)
    capability = contract(snapshot_id)
    prepared = prepared_dependencies(tmp_path, capability)
    metadata_path = prepared / "trivy" / capability.engine("trivy").acquisition_digest / "metadata.json"
    metadata_path.chmod(0o644)
    runner = FixtureScannerRunner(store, capability, prepared, tmp_path / "raw-artifacts")

    with pytest.raises(RunnerViolation, match="private"):
        runner.command_for("trivy", snapshot_id)


def test_trivy_runner_refuses_a_prepared_cache_whose_bytes_do_not_match_its_manifest_digest(tmp_path):
    store, snapshot_id = copied_fixture(tmp_path)
    capability = contract(snapshot_id)
    prepared = prepared_dependencies(tmp_path, capability)
    cache_file = prepared / "trivy" / capability.engine("trivy").acquisition_digest / "cache" / "db" / "trivy.db"
    cache_file.write_bytes(b"substituted DB\n")
    cache_file.chmod(0o600)
    runner = FixtureScannerRunner(store, capability, prepared, tmp_path / "raw-artifacts")

    with pytest.raises(RunnerViolation, match="does not match the admitted DB snapshot"):
        runner.command_for("trivy", snapshot_id)


def test_trivy_runner_refuses_an_empty_prepared_cache(tmp_path):
    store, snapshot_id = copied_fixture(tmp_path)
    capability = contract(snapshot_id)
    prepared = prepared_dependencies(tmp_path, capability)
    cache_file = prepared / "trivy" / capability.engine("trivy").acquisition_digest / "cache" / "db" / "trivy.db"
    cache_file.unlink()
    runner = FixtureScannerRunner(store, capability, prepared, tmp_path / "raw-artifacts")

    with pytest.raises(RunnerViolation, match="empty"):
        runner.command_for("trivy", snapshot_id)


@pytest.mark.parametrize(("missing_member", "member_database"), [
    ("javascript-typescript", "db-javascript"),
    ("actions", "db-actions"),
])
def test_codeql_raw_admission_requires_each_database_cluster_member(
    tmp_path, missing_member, member_database
):
    store, snapshot_id = copied_fixture(tmp_path)
    capability = contract(snapshot_id)
    raw_root = tmp_path / "raw-artifacts"
    runner = FixtureScannerRunner(store, capability, prepared_dependencies(tmp_path, capability), raw_root)
    cluster = raw_root / snapshot_id / "codeql" / capability.engine("codeql").acquisition_digest / "database-cluster"
    for language, database_name in (
        ("javascript-typescript", "db-javascript"),
        ("actions", "db-actions"),
    ):
        database = cluster / language
        database.mkdir(parents=True)
        (database / "codeql-database.yml").write_text("fixture database\n", encoding="utf-8")
        (database / database_name).mkdir()
    (cluster / missing_member / member_database).rmdir()

    with pytest.raises(RunnerViolation, match="completion evidence"):
        runner.capture_raw_artifact(
            "codeql",
            snapshot_id,
            {"runs": [{"invocations": [{"executionSuccessful": True}], "results": []}]},
        )
