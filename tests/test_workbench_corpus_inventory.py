from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from workbench.corpus_inventory import CorpusInventoryViolation, inventory_openssf_benchmark
import workbench.corpus_inventory as corpus_inventory


ROOT = Path(__file__).resolve().parents[1]


def run_git(root: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *arguments],
        text=True,
        stderr=subprocess.STDOUT,
    ).strip()


def commit(root: Path, message: str) -> str:
    run_git(root, "add", ".")
    run_git(
        root,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-m",
        message,
    )
    return run_git(root, "rev-parse", "HEAD")


def benchmark_fixture(
    tmp_path: Path,
    *,
    repository: str,
    pre_patch: str,
    post_patch: str,
    source_extension: str = "ts",
) -> tuple[Path, str]:
    benchmark = tmp_path / "benchmark"
    (benchmark / "CVEs").mkdir(parents=True)
    run_git(benchmark, "init")
    (benchmark / "README.md").write_text("fixture benchmark\n", encoding="utf-8")
    (benchmark / "CVEs" / "CVE-2099-0001.json").write_text(
        json.dumps(
            {
                "CVE": "CVE-2099-0001",
                "state": "PUBLISHED",
                "repository": repository,
                "prePatch": {
                    "commit": pre_patch,
                    "weaknesses": [
                        {
                            "location": {"file": f"src/vulnerable.{source_extension}", "line": 7},
                            "explanation": "fixture truth anchor",
                        }
                    ],
                },
                "postPatch": {"commit": post_patch},
                "CWEs": ["CWE-079"],
            }
        ),
        encoding="utf-8",
    )
    return benchmark, commit(benchmark, "add fixture CVE")


def repository_fixture(
    tmp_path: Path,
    *,
    source_extension: str = "ts",
    extra_typescript: bool = False,
) -> tuple[Path, str, str]:
    repository = tmp_path / "cache" / "example--project"
    repository.mkdir(parents=True)
    run_git(repository, "init")
    (repository / "src").mkdir()
    (repository / "src" / f"vulnerable.{source_extension}").write_text("export const vulnerable = true;\n", encoding="utf-8")
    if extra_typescript:
        (repository / "src" / "unrelated.ts").write_text("export const unrelated = true;\n", encoding="utf-8")
    pre_patch = commit(repository, "vulnerable")
    (repository / "src" / f"vulnerable.{source_extension}").write_text("export const vulnerable = false;\n", encoding="utf-8")
    post_patch = commit(repository, "fixed")
    return repository, pre_patch, post_patch


def inventory_script_module():
    specification = importlib.util.spec_from_file_location(
        "workbench_corpus_inventory_script",
        ROOT / "scripts" / "workbench-corpus-inventory.py",
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_inventory_uses_pinned_benchmark_metadata_and_actual_local_repository_trees(tmp_path: Path):
    _, pre_patch, post_patch = repository_fixture(tmp_path)
    benchmark, benchmark_revision = benchmark_fixture(
        tmp_path,
        repository="https://github.com/example/project.git",
        pre_patch=pre_patch,
        post_patch=post_patch,
    )

    inventory = inventory_openssf_benchmark(
        benchmark,
        expected_revision=benchmark_revision,
        repository_cache=tmp_path / "cache",
    )

    assert inventory["benchmark"]["revision"] == benchmark_revision
    assert inventory["comparative_status"] == "blocked-no-eligible-typescript-corpus"
    assert inventory["admission_decision"] == "not-admitted"
    assert inventory["eligible_repository_cluster_count"] == 1
    entry = inventory["entries"][0]
    assert entry["cve"] == "CVE-2099-0001"
    assert entry["repository_cluster"] == "github.com/example/project"
    assert entry["pre_patch"]["commit"] == pre_patch
    assert entry["post_patch"]["commit"] == post_patch
    assert entry["truth_anchors"] == [
        {"cwe": "CWE-079", "file": "src/vulnerable.ts", "line": 7}
    ]
    assert entry["source_evidence"]["state"] == "candidate-needs-adjudication"
    assert entry["source_evidence"]["pre_patch_language_counts"]["TypeScript"] == 1
    assert "snapshot_digest" not in entry
    assert "truth_manifest_digest" not in entry


def test_inventory_refuses_a_changed_benchmark_checkout(tmp_path: Path):
    _, pre_patch, post_patch = repository_fixture(tmp_path)
    benchmark, _ = benchmark_fixture(
        tmp_path,
        repository="https://github.com/example/project.git",
        pre_patch=pre_patch,
        post_patch=post_patch,
    )

    with pytest.raises(CorpusInventoryViolation, match="revision"):
        inventory_openssf_benchmark(
            benchmark,
            expected_revision="0" * 40,
            repository_cache=tmp_path / "cache",
        )


def test_inventory_reads_metadata_from_the_pinned_tree_not_dirty_checkout_files(tmp_path: Path):
    _, pre_patch, post_patch = repository_fixture(tmp_path)
    benchmark, benchmark_revision = benchmark_fixture(
        tmp_path,
        repository="https://github.com/example/project.git",
        pre_patch=pre_patch,
        post_patch=post_patch,
    )
    metadata = benchmark / "CVEs" / "CVE-2099-0001.json"
    dirty = json.loads(metadata.read_text(encoding="utf-8"))
    dirty["CWEs"] = ["CWE-999"]
    dirty["prePatch"]["weaknesses"][0]["location"]["file"] = "src/UNPINNED-CONTENT.ts"
    metadata.write_text(json.dumps(dirty), encoding="utf-8")

    inventory = inventory_openssf_benchmark(
        benchmark,
        expected_revision=benchmark_revision,
        repository_cache=tmp_path / "empty-cache",
    )

    assert inventory["entries"][0]["truth_anchors"] == [
        {"cwe": "CWE-079", "file": "src/vulnerable.ts", "line": 7}
    ]


def test_inventory_does_not_copy_unbounded_benchmark_explanations_into_its_artifact(tmp_path: Path):
    _, pre_patch, post_patch = repository_fixture(tmp_path)
    benchmark, benchmark_revision = benchmark_fixture(
        tmp_path,
        repository="https://github.com/example/project.git",
        pre_patch=pre_patch,
        post_patch=post_patch,
    )
    metadata = benchmark / "CVEs" / "CVE-2099-0001.json"
    document = json.loads(metadata.read_text(encoding="utf-8"))
    document["prePatch"]["weaknesses"][0]["explanation"] = "WORKBENCH_RAW_SECRET_CANARY"
    metadata.write_text(json.dumps(document), encoding="utf-8")
    benchmark_revision = commit(benchmark, "commit source-like explanation")

    inventory = inventory_openssf_benchmark(
        benchmark,
        expected_revision=benchmark_revision,
        repository_cache=tmp_path / "empty-cache",
    )

    serialized = json.dumps(inventory, sort_keys=True)
    assert "WORKBENCH_RAW_SECRET_CANARY" not in serialized
    assert inventory["entries"][0]["truth_anchors"] == [
        {"cwe": "CWE-079", "file": "src/vulnerable.ts", "line": 7}
    ]


def test_inventory_never_promotes_metadata_without_local_source_evidence(tmp_path: Path):
    repository = "https://github.com/example/project.git"
    benchmark, benchmark_revision = benchmark_fixture(
        tmp_path,
        repository=repository,
        pre_patch="a" * 40,
        post_patch="b" * 40,
    )

    inventory = inventory_openssf_benchmark(
        benchmark,
        expected_revision=benchmark_revision,
        repository_cache=tmp_path / "empty-cache",
    )

    assert inventory["comparative_status"] == "blocked-no-eligible-typescript-corpus"
    assert inventory["eligible_repository_cluster_count"] == 0
    assert inventory["entries"][0]["source_evidence"] == {
        "state": "unresolved-local-source",
        "reason_code": "repository-cache-miss",
    }


def test_inventory_records_malformed_benchmark_metadata_without_relaxing_commit_pinning(tmp_path: Path):
    _, pre_patch, post_patch = repository_fixture(tmp_path)
    benchmark, _ = benchmark_fixture(
        tmp_path,
        repository="https://github.com/example/project.git",
        pre_patch=pre_patch,
        post_patch=post_patch,
    )
    metadata = benchmark / "CVEs" / "CVE-2099-0001.json"
    document = json.loads(metadata.read_text(encoding="utf-8"))
    document["postPatch"]["commit"] = post_patch[:7]
    metadata.write_text(json.dumps(document), encoding="utf-8")
    benchmark_revision = commit(benchmark, "record malformed post-patch reference")

    inventory = inventory_openssf_benchmark(
        benchmark,
        expected_revision=benchmark_revision,
        repository_cache=tmp_path / "cache",
    )

    assert inventory["comparative_status"] == "blocked-no-eligible-typescript-corpus"
    assert inventory["entries"][0] == {
        "cve": "CVE-2099-0001",
        "source_evidence": {
            "state": "metadata-invalid",
            "reason_code": "postPatch.commit must be a lowercase full git revision",
        },
    }


def test_inventory_records_valid_json_that_is_not_an_object_as_metadata_invalid(tmp_path: Path):
    _, pre_patch, post_patch = repository_fixture(tmp_path)
    benchmark, _ = benchmark_fixture(
        tmp_path,
        repository="https://github.com/example/project.git",
        pre_patch=pre_patch,
        post_patch=post_patch,
    )
    (benchmark / "CVEs" / "CVE-2099-0002.json").write_text("[]", encoding="utf-8")
    benchmark_revision = commit(benchmark, "record non-object metadata")

    inventory = inventory_openssf_benchmark(
        benchmark,
        expected_revision=benchmark_revision,
        repository_cache=tmp_path / "cache",
    )

    assert inventory["entries"][1] == {
        "cve": "invalid-metadata:CVEs/CVE-2099-0002.json",
        "source_evidence": {
            "state": "metadata-invalid",
            "reason_code": "benchmark metadata must be an object: CVEs/CVE-2099-0002.json",
        },
    }


def test_inventory_records_an_object_without_a_usable_cve_as_metadata_invalid(tmp_path: Path):
    _, pre_patch, post_patch = repository_fixture(tmp_path)
    benchmark, _ = benchmark_fixture(
        tmp_path,
        repository="https://github.com/example/project.git",
        pre_patch=pre_patch,
        post_patch=post_patch,
    )
    metadata = benchmark / "CVEs" / "CVE-2099-0001.json"
    document = json.loads(metadata.read_text(encoding="utf-8"))
    document["CVE"] = None
    metadata.write_text(json.dumps(document), encoding="utf-8")
    benchmark_revision = commit(benchmark, "record invalid cve identifier")

    inventory = inventory_openssf_benchmark(
        benchmark,
        expected_revision=benchmark_revision,
        repository_cache=tmp_path / "cache",
    )

    assert inventory["entries"][0] == {
        "cve": "invalid-metadata:CVEs/CVE-2099-0001.json",
        "source_evidence": {
            "state": "metadata-invalid",
            "reason_code": "CVE must be a labelled string",
        },
    }


def test_inventory_uses_actual_tree_extensions_not_benchmark_language_prose(tmp_path: Path):
    _, pre_patch, post_patch = repository_fixture(tmp_path, source_extension="js")
    benchmark, benchmark_revision = benchmark_fixture(
        tmp_path,
        repository="https://github.com/example/project.git",
        pre_patch=pre_patch,
        post_patch=post_patch,
        source_extension="js",
    )

    inventory = inventory_openssf_benchmark(
        benchmark,
        expected_revision=benchmark_revision,
        repository_cache=tmp_path / "cache",
    )

    assert inventory["eligible_repository_cluster_count"] == 0
    assert inventory["entries"][0]["source_evidence"]["state"] == "not-typescript-at-pre-and-post-patch"


def test_inventory_requires_typescript_truth_anchors_not_only_an_unrelated_typescript_file(tmp_path: Path):
    _, pre_patch, post_patch = repository_fixture(tmp_path, source_extension="js", extra_typescript=True)
    benchmark, benchmark_revision = benchmark_fixture(
        tmp_path,
        repository="https://github.com/example/project.git",
        pre_patch=pre_patch,
        post_patch=post_patch,
        source_extension="js",
    )

    inventory = inventory_openssf_benchmark(
        benchmark,
        expected_revision=benchmark_revision,
        repository_cache=tmp_path / "cache",
    )

    assert inventory["eligible_repository_cluster_count"] == 0
    assert inventory["entries"][0]["source_evidence"] == {
        "state": "not-typescript-truth-anchor",
        "non_typescript_truth_anchor_paths": ["src/vulnerable.js"],
    }


def test_inventory_requires_the_declared_pre_patch_to_be_an_ancestor_of_post_patch(tmp_path: Path):
    repository, pre_patch, _ = repository_fixture(tmp_path)
    run_git(repository, "checkout", "--orphan", "unrelated")
    run_git(repository, "rm", "-rf", ".")
    (repository / "src").mkdir()
    (repository / "src" / "vulnerable.ts").write_text("export const unrelated = true;\n", encoding="utf-8")
    unrelated_post_patch = commit(repository, "unrelated post-patch")
    benchmark, benchmark_revision = benchmark_fixture(
        tmp_path,
        repository="https://github.com/example/project.git",
        pre_patch=pre_patch,
        post_patch=unrelated_post_patch,
    )

    inventory = inventory_openssf_benchmark(
        benchmark,
        expected_revision=benchmark_revision,
        repository_cache=tmp_path / "cache",
    )

    assert inventory["eligible_repository_cluster_count"] == 0
    assert inventory["entries"][0]["source_evidence"] == {
        "state": "unresolved-local-source",
        "reason_code": "pre-patch-is-not-ancestor-of-post-patch",
    }


def test_git_evidence_disables_lazy_fetch_and_inherited_git_configuration(monkeypatch, tmp_path: Path):
    captured: dict[str, object] = {}

    class Completed:
        returncode = 0
        stdout = "ok\n"

    def fake_run(*arguments, **kwargs):
        captured.update(kwargs)
        return Completed()

    monkeypatch.setattr(corpus_inventory.subprocess, "run", fake_run)

    assert corpus_inventory._git(tmp_path, "rev-parse", "HEAD") == "ok"
    environment = captured["env"]
    assert environment["GIT_NO_LAZY_FETCH"] == "1"
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_GLOBAL"] == os.devnull


def test_inventory_publication_cannot_replace_a_record_created_during_publish(tmp_path: Path, monkeypatch):
    script = inventory_script_module()
    output = tmp_path / "inventory.json"

    def racer(source, destination):
        output.write_text("racer-won\n", encoding="utf-8")
        raise FileExistsError

    monkeypatch.setattr(script.os, "link", racer)

    with pytest.raises(CorpusInventoryViolation, match="existing inventory"):
        script.write_exclusive(output, {"status": "not-admitted"})

    assert output.read_text(encoding="utf-8") == "racer-won\n"


def test_inventory_cli_loads_the_local_workbench_package_without_pythonpath(tmp_path: Path):
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)

    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "workbench-corpus-inventory.py"), "--help"],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "--expected-revision" in completed.stdout
