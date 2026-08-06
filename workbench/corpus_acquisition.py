"""Fail-closed public-git acquisition for OpenSSF CVE Benchmark source caches.

This module only materializes local git evidence used by corpus inventory. It
never seals source, runs scanners, admits a corpus catalog, or claims efficacy.
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable
from urllib.parse import urlparse

from .corpus_inventory import (
    CorpusInventoryViolation,
    _git,
    _git_environment,
    _git_result,
    _repository_parts,
    _required_commit,
    _required_text,
)

_HEX40 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class CorpusAcquisitionViolation(ValueError):
    """Raised when public cache acquisition cannot proceed safely."""


@dataclass(frozen=True)
class AcquisitionReceipt:
    """Source-less evidence that a public repository revision is cached locally."""

    repository_url: str
    cache_name: str
    path: str
    head_commit: str
    kind: str


def _require_https_git_url(url: str, label: str) -> str:
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not parsed.path
    ):
        raise CorpusAcquisitionViolation(f"{label} must be a credential-free HTTPS git URL")
    return url


def _run_git(root: Path | None, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    command = ["git", *arguments] if root is None else ["git", "-C", str(root), *arguments]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        env=_git_environment(),
    )
    if check and completed.returncode:
        detail = (completed.stderr or completed.stdout or "git failed").strip().splitlines()
        message = detail[-1] if detail else "git failed"
        raise CorpusAcquisitionViolation(message)
    return completed


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    if path.is_symlink() or not path.is_dir():
        raise CorpusAcquisitionViolation("cache path must be a private directory")


def acquire_benchmark(
    *,
    cache_root: Path | str,
    benchmark_url: str,
    expected_revision: str,
) -> AcquisitionReceipt:
    """Clone or update the OpenSSF CVE Benchmark checkout at an exact revision."""
    root = Path(cache_root).expanduser().resolve()
    _ensure_private_dir(root)
    url = _require_https_git_url(benchmark_url, "benchmark_url")
    revision = _required_commit(expected_revision, "expected_revision")
    benchmark_dir = root / "benchmark" / "ossf-cve-benchmark"
    _ensure_private_dir(benchmark_dir.parent)
    if benchmark_dir.exists() and not (benchmark_dir / ".git").exists():
        raise CorpusAcquisitionViolation("benchmark path exists but is not a git checkout")
    if not (benchmark_dir / ".git").exists():
        _run_git(None, "clone", "--filter=blob:none", url, str(benchmark_dir))
    else:
        _run_git(benchmark_dir, "remote", "set-url", "origin", url)
        _run_git(benchmark_dir, "fetch", "--filter=blob:none", "origin", revision)
    # Force the pinned revision: partial/filter clones can leave an unclean index.
    _run_git(benchmark_dir, "checkout", "-f", "--detach", revision)
    _run_git(benchmark_dir, "reset", "--hard", revision)
    _run_git(benchmark_dir, "clean", "-fdx")
    head = _git(benchmark_dir, "rev-parse", "HEAD")
    if head != revision:
        raise CorpusAcquisitionViolation("benchmark checkout did not land on the expected revision")
    return AcquisitionReceipt(
        repository_url=url,
        cache_name="ossf-cve-benchmark",
        path=str(benchmark_dir),
        head_commit=head,
        kind="benchmark",
    )


def _repository_urls_from_benchmark(benchmark_dir: Path, revision: str) -> list[str]:
    paths = _git(benchmark_dir, "ls-tree", "-r", "--name-only", revision, "--", "CVEs").splitlines()
    urls: list[str] = []
    seen: set[str] = set()
    for metadata_path in paths:
        if not metadata_path.startswith("CVEs/") or not metadata_path.endswith(".json"):
            continue
        try:
            import json

            document = json.loads(_git(benchmark_dir, "show", f"{revision}:{metadata_path}"))
        except Exception:
            continue
        if not isinstance(document, dict):
            continue
        try:
            repository_url, _cluster, _cache_name = _repository_parts(document.get("repository"))
        except CorpusInventoryViolation:
            continue
        if repository_url not in seen:
            seen.add(repository_url)
            urls.append(repository_url)
    return urls


def _commits_for_repository(benchmark_dir: Path, revision: str, repository_url: str) -> set[str]:
    import json

    commits: set[str] = set()
    paths = _git(benchmark_dir, "ls-tree", "-r", "--name-only", revision, "--", "CVEs").splitlines()
    for metadata_path in paths:
        if not metadata_path.startswith("CVEs/") or not metadata_path.endswith(".json"):
            continue
        try:
            document = json.loads(_git(benchmark_dir, "show", f"{revision}:{metadata_path}"))
        except Exception:
            continue
        if not isinstance(document, dict):
            continue
        try:
            url, _, _ = _repository_parts(document.get("repository"))
        except CorpusInventoryViolation:
            continue
        if url != repository_url:
            continue
        for key in ("prePatch", "postPatch"):
            block = document.get(key)
            if not isinstance(block, dict):
                continue
            commit = block.get("commit")
            if isinstance(commit, str) and len(commit) == 40:
                commits.add(commit.lower())
    return commits


def _is_git_dir(path: Path) -> bool:
    """True for a worktree checkout or a bare repository directory."""
    if (path / ".git").exists():
        return True
    return (path / "HEAD").is_file() and (path / "objects").is_dir() and (path / "refs").is_dir()


def acquire_repository(
    *,
    cache_root: Path | str,
    repository_url: str,
    required_commits: Iterable[str] = (),
) -> AcquisitionReceipt:
    """Clone or update one public repository into the owner--name cache layout.

    Repositories are stored as bare clones so partial/filter clones do not leave
    a dirty worktree that confuses subsequent fetch/checkout steps. Inventory
    only needs ``cat-file`` / ``ls-tree`` against commits.
    """
    root = Path(cache_root).expanduser().resolve()
    _ensure_private_dir(root)
    try:
        url, _cluster, cache_name = _repository_parts(repository_url)
    except CorpusInventoryViolation as error:
        raise CorpusAcquisitionViolation(str(error)) from error
    if not _SAFE_NAME.match(cache_name.replace("--", "-")) and "--" not in cache_name:
        raise CorpusAcquisitionViolation("unsafe repository cache name")
    repo_root = root / "repositories" / cache_name
    _ensure_private_dir(repo_root.parent)
    if repo_root.exists() and not _is_git_dir(repo_root):
        raise CorpusAcquisitionViolation(f"repository cache path is not a git checkout: {cache_name}")
    if not _is_git_dir(repo_root):
        # Remove a partial failed directory so clone can recreate it cleanly.
        if repo_root.exists():
            raise CorpusAcquisitionViolation(f"refusing to clobber non-git path: {cache_name}")
        try:
            _run_git(
                None,
                "clone",
                "--bare",
                "--filter=blob:none",
                url,
                str(repo_root),
            )
        except CorpusAcquisitionViolation:
            # Leave no half-written cache on failure.
            if repo_root.exists():
                import shutil

                shutil.rmtree(repo_root, ignore_errors=True)
            raise
    else:
        # Bare or worktree: keep origin current without requiring a clean index.
        remotes = _run_git(repo_root, "remote", check=False).stdout.split()
        if "origin" in remotes:
            _run_git(repo_root, "remote", "set-url", "origin", url)
        else:
            _run_git(repo_root, "remote", "add", "origin", url)
        _run_git(repo_root, "fetch", "--filter=blob:none", "--prune", "origin", check=False)
    missing = []
    for commit in required_commits:
        digest = _required_commit(commit, "required_commit")
        if _git_result(repo_root, "cat-file", "-e", f"{digest}^{{commit}}").returncode != 0:
            try:
                _run_git(repo_root, "fetch", "--filter=blob:none", "origin", digest)
            except CorpusAcquisitionViolation:
                missing.append(digest)
                continue
        if _git_result(repo_root, "cat-file", "-e", f"{digest}^{{commit}}").returncode != 0:
            missing.append(digest)
    if missing:
        raise CorpusAcquisitionViolation(
            f"required commits unavailable for {cache_name}: {','.join(missing[:3])}"
        )
    head = _git(repo_root, "rev-parse", "HEAD")
    return AcquisitionReceipt(
        repository_url=url,
        cache_name=cache_name,
        path=str(repo_root),
        head_commit=head,
        kind="repository",
    )


def acquire_openssf_corpus(
    *,
    cache_root: Path | str,
    benchmark_url: str,
    expected_revision: str,
    max_repositories: int | None = None,
) -> dict[str, object]:
    """Acquire the benchmark and zero or more public repository caches."""
    if max_repositories is not None and max_repositories < 0:
        raise CorpusAcquisitionViolation("max_repositories must be non-negative")
    root = Path(cache_root).expanduser().resolve()
    benchmark = acquire_benchmark(
        cache_root=root,
        benchmark_url=benchmark_url,
        expected_revision=expected_revision,
    )
    revision = benchmark.head_commit
    benchmark_dir = Path(benchmark.path)
    urls = _repository_urls_from_benchmark(benchmark_dir, revision)
    if max_repositories is not None:
        urls = urls[:max_repositories]
    receipts: list[dict[str, object]] = []
    failures: list[dict[str, str]] = []
    for url in urls:
        commits = _commits_for_repository(benchmark_dir, revision, url)
        try:
            receipt = acquire_repository(
                cache_root=root,
                repository_url=url,
                required_commits=commits,
            )
            receipts.append(
                {
                    "repository_url": receipt.repository_url,
                    "cache_name": receipt.cache_name,
                    "path": receipt.path,
                    "head_commit": receipt.head_commit,
                    "kind": receipt.kind,
                    "required_commit_count": len(commits),
                }
            )
        except (CorpusAcquisitionViolation, CorpusInventoryViolation) as error:
            failures.append({"repository_url": url, "reason": str(error)})
    return {
        "schema_version": "sentinel-workbench-corpus-acquisition-receipt/v1",
        "benchmark": {
            "repository_url": benchmark.repository_url,
            "path": benchmark.path,
            "revision": benchmark.head_commit,
        },
        "repository_cache_root": str(root / "repositories"),
        "acquired_repositories": receipts,
        "failed_repositories": failures,
        "admission_decision": "not-admitted",
        "notes": "Acquisition only materializes local git evidence; inventory and claim gates remain separate.",
    }
