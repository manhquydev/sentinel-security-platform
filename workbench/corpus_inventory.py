"""Read-only, fail-closed candidate inventory for the OpenSSF CVE Benchmark.

This is an admission aid, not a corpus admission path.  It never downloads
repositories, seals source, scans source, writes a corpus catalog, or creates
truth/snapshot digests.  A metadata record becomes a candidate only when the
referenced commits and TypeScript trees are already present in a local cache;
the remaining truth, licence, authorship, contamination, and calibration gates
remain intentionally unresolved.
"""
from __future__ import annotations

import json
import os
import subprocess
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Mapping
from urllib.parse import urlparse


class CorpusInventoryViolation(ValueError):
    """Raised when benchmark metadata cannot be inventoryed reproducibly."""


_LANGUAGE_BY_SUFFIX = {
    ".ts": "TypeScript",
    ".tsx": "TSX",
    ".js": "JavaScript",
    ".jsx": "JSX",
}


def _git_environment() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "LC_ALL": "C",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
    }


def _git_result(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        capture_output=True,
        text=True,
        env=_git_environment(),
    )


def _git(root: Path, *arguments: str) -> str:
    completed = _git_result(root, *arguments)
    if completed.returncode:
        raise CorpusInventoryViolation("required local git evidence is unavailable")
    return completed.stdout.strip()


def _required_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise CorpusInventoryViolation(f"{label} must be a labelled string")
    return value


def _required_commit(value: object, label: str) -> str:
    commit = _required_text(value, label)
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise CorpusInventoryViolation(f"{label} must be a lowercase full git revision")
    return commit


def _repository_parts(repository: object) -> tuple[str, str, str]:
    url = _required_text(repository, "repository")
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise CorpusInventoryViolation("repository must be a canonical HTTPS repository URL")
    path = parsed.path.removesuffix(".git").strip("/")
    pieces = path.split("/")
    if len(pieces) != 2 or not all(piece and piece not in {".", ".."} for piece in pieces):
        raise CorpusInventoryViolation("repository URL must identify one owner/repository pair")
    host = parsed.hostname.lower()
    owner, name = pieces
    return url, f"{host}/{owner}/{name}", f"{owner}--{name}"


def _paths_at_commit(repository: Path, commit: str) -> tuple[str, ...]:
    _git(repository, "cat-file", "-e", f"{commit}^{{commit}}")
    output = _git(repository, "ls-tree", "-r", "--name-only", commit)
    return tuple(path for path in output.splitlines() if path)


def _is_ancestor(repository: Path, ancestor: str, descendant: str) -> bool:
    return _git_result(repository, "merge-base", "--is-ancestor", ancestor, descendant).returncode == 0


def _language_counts(paths: tuple[str, ...]) -> dict[str, int]:
    counts = Counter(
        language
        for path in paths
        if (language := _LANGUAGE_BY_SUFFIX.get(PurePosixPath(path).suffix.lower())) is not None
    )
    return dict(sorted(counts.items()))


def _truth_anchors(document: Mapping[str, Any], cwes: tuple[str, ...]) -> list[dict[str, object]]:
    pre_patch = document.get("prePatch")
    if not isinstance(pre_patch, Mapping):
        raise CorpusInventoryViolation("prePatch must be an object")
    weaknesses = pre_patch.get("weaknesses")
    if not isinstance(weaknesses, list) or not weaknesses:
        raise CorpusInventoryViolation("prePatch.weaknesses must be a non-empty list")
    anchors: list[dict[str, object]] = []
    for weakness in weaknesses:
        if not isinstance(weakness, Mapping):
            raise CorpusInventoryViolation("weakness must be an object")
        location = weakness.get("location")
        if not isinstance(location, Mapping):
            raise CorpusInventoryViolation("weakness.location must be an object")
        source_path = _required_text(location.get("file"), "weakness.location.file")
        normalized = PurePosixPath(source_path)
        if normalized.is_absolute() or ".." in normalized.parts or str(normalized) in {"", "."}:
            raise CorpusInventoryViolation("weakness.location.file must be a safe repository-relative path")
        line = location.get("line")
        if not isinstance(line, int) or isinstance(line, bool) or line <= 0:
            raise CorpusInventoryViolation("weakness.location.line must be a positive integer")
        for cwe in cwes:
            anchors.append({"cwe": cwe, "file": str(normalized), "line": line})
    return anchors


def _entry(document: Mapping[str, Any], repository_cache: Path) -> dict[str, object]:
    cve = _required_text(document.get("CVE"), "CVE")
    if not cve.startswith("CVE-"):
        raise CorpusInventoryViolation("CVE must use a CVE identifier")
    repository_url, cluster, cache_name = _repository_parts(document.get("repository"))
    pre_patch = document.get("prePatch")
    post_patch = document.get("postPatch")
    if not isinstance(pre_patch, Mapping) or not isinstance(post_patch, Mapping):
        raise CorpusInventoryViolation("prePatch and postPatch must be objects")
    pre_commit = _required_commit(pre_patch.get("commit"), "prePatch.commit")
    post_commit = _required_commit(post_patch.get("commit"), "postPatch.commit")
    raw_cwes = document.get("CWEs")
    if not isinstance(raw_cwes, list) or not raw_cwes or not all(isinstance(item, str) and item.startswith("CWE-") for item in raw_cwes):
        raise CorpusInventoryViolation("CWEs must be a non-empty labelled list")
    cwes = tuple(sorted(set(raw_cwes)))
    anchors = _truth_anchors(document, cwes)
    result: dict[str, object] = {
        "cve": cve,
        "repository": repository_url,
        "repository_cluster": cluster,
        "pre_patch": {"commit": pre_commit},
        "post_patch": {"commit": post_commit},
        "truth_anchors": anchors,
    }

    repository = repository_cache / cache_name
    if not repository.is_dir():
        result["source_evidence"] = {
            "state": "unresolved-local-source",
            "reason_code": "repository-cache-miss",
        }
        return result

    try:
        pre_paths = _paths_at_commit(repository, pre_commit)
        post_paths = _paths_at_commit(repository, post_commit)
    except CorpusInventoryViolation:
        result["source_evidence"] = {
            "state": "unresolved-local-source",
            "reason_code": "referenced-commit-unavailable",
        }
        return result
    if not _is_ancestor(repository, pre_commit, post_commit):
        result["source_evidence"] = {
            "state": "unresolved-local-source",
            "reason_code": "pre-patch-is-not-ancestor-of-post-patch",
        }
        return result

    pre_counts = _language_counts(pre_paths)
    post_counts = _language_counts(post_paths)
    missing_anchor_paths = sorted({str(anchor["file"]) for anchor in anchors} - set(pre_paths))
    if missing_anchor_paths:
        result["source_evidence"] = {
            "state": "unresolved-local-source",
            "reason_code": "pre-patch-truth-anchor-missing",
            "missing_truth_anchor_paths": missing_anchor_paths,
        }
        return result
    if pre_counts.get("TypeScript", 0) <= 0 or post_counts.get("TypeScript", 0) <= 0:
        result["source_evidence"] = {
            "state": "not-typescript-at-pre-and-post-patch",
            "pre_patch_language_counts": pre_counts,
            "post_patch_language_counts": post_counts,
        }
        return result
    non_typescript_truth_anchors = sorted(
        {
            str(anchor["file"])
            for anchor in anchors
            if PurePosixPath(str(anchor["file"])).suffix.lower() not in {".ts", ".tsx"}
        }
    )
    if non_typescript_truth_anchors:
        result["source_evidence"] = {
            "state": "not-typescript-truth-anchor",
            "non_typescript_truth_anchor_paths": non_typescript_truth_anchors,
        }
        return result
    result["source_evidence"] = {
        "state": "candidate-needs-adjudication",
        "pre_patch_language_counts": pre_counts,
        "post_patch_language_counts": post_counts,
        "remaining_gates": [
            "frozen-truth-manifest",
            "license-and-authorship-screen",
            "model-cutoff-contamination-screen",
            "independent-outcome-blind-control-audit",
            "separate-non-confirmatory-calibration",
            "at-least-20-independent-repository-clusters",
        ],
    }
    return result


def inventory_openssf_benchmark(
    benchmark_root: Path | str,
    *,
    expected_revision: str,
    repository_cache: Path | str,
) -> dict[str, object]:
    """Inventory one pinned local checkout without fetching any source."""

    benchmark = Path(benchmark_root).resolve()
    cache = Path(repository_cache).resolve()
    expected = _required_commit(expected_revision, "expected_revision")
    if not benchmark.is_dir():
        raise CorpusInventoryViolation("benchmark root must be a local git checkout")
    revision = _git(benchmark, "rev-parse", "HEAD")
    if revision != expected:
        raise CorpusInventoryViolation("benchmark revision does not match the required pinned revision")

    entries: list[dict[str, object]] = []
    seen_cves: set[str] = set()
    metadata_paths = tuple(
        path
        for path in _git(benchmark, "ls-tree", "-r", "--name-only", expected, "--", "CVEs").splitlines()
        if path.startswith("CVEs/") and path.endswith(".json")
    )
    if not metadata_paths:
        raise CorpusInventoryViolation("pinned benchmark revision contains no CVE metadata")
    for metadata_path in metadata_paths:
        try:
            document = json.loads(_git(benchmark, "show", f"{expected}:{metadata_path}"))
        except json.JSONDecodeError as error:
            raise CorpusInventoryViolation(f"invalid pinned benchmark metadata: {metadata_path}") from error
        if not isinstance(document, Mapping):
            entry = {
                "cve": f"invalid-metadata:{metadata_path}",
                "source_evidence": {
                    "state": "metadata-invalid",
                    "reason_code": f"benchmark metadata must be an object: {metadata_path}",
                },
            }
        else:
            try:
                entry = _entry(document, cache)
            except CorpusInventoryViolation as error:
                raw_cve = document.get("CVE")
                cve = raw_cve if isinstance(raw_cve, str) and raw_cve else f"invalid-metadata:{metadata_path}"
                entry = {
                    "cve": cve,
                    "source_evidence": {
                        "state": "metadata-invalid",
                        "reason_code": str(error),
                    },
                }
        cve = entry["cve"]
        if cve in seen_cves:
            raise CorpusInventoryViolation("benchmark metadata contains a duplicate CVE")
        seen_cves.add(cve)
        entries.append(entry)

    candidate_clusters = sorted(
        {
            str(entry["repository_cluster"])
            for entry in entries
            if isinstance(entry["source_evidence"], Mapping)
            and entry["source_evidence"].get("state") == "candidate-needs-adjudication"
        }
    )
    return {
        "schema_version": "sentinel-workbench-candidate-corpus-inventory/v1",
        "benchmark": {
            "name": "OpenSSF CVE Benchmark",
            "revision": revision,
            "metadata_path": "CVEs",
        },
        "comparative_status": "blocked-no-eligible-typescript-corpus",
        "admission_decision": "not-admitted",
        "eligible_repository_cluster_count": len(candidate_clusters),
        "entries": entries,
    }
