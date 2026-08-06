#!/usr/bin/env python3
"""Acquire OpenSSF CVE Benchmark git evidence into a local cache (no admission)."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from workbench.corpus_acquisition import CorpusAcquisitionViolation, acquire_openssf_corpus

DEFAULT_BENCHMARK_URL = "https://github.com/ossf-cve-benchmark/ossf-cve-benchmark.git"
DEFAULT_REVISION = "91c59fd54b2b768c0f310bb0027d2ac59cdf74d4"


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Clone the pinned OpenSSF CVE Benchmark and optional public repository "
            "caches for inventory. Never seals, scans, or admits a comparative corpus."
        )
    )
    parser.add_argument(
        "--cache-root",
        type=Path,
        default=Path.home() / ".cache" / "sentinel-workbench",
        help="private local cache root (default: ~/.cache/sentinel-workbench)",
    )
    parser.add_argument("--benchmark-url", default=DEFAULT_BENCHMARK_URL)
    parser.add_argument("--expected-revision", default=DEFAULT_REVISION)
    parser.add_argument(
        "--max-repositories",
        type=int,
        default=0,
        help="maximum repository caches to acquire (0 = benchmark only)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="optional exclusive JSON receipt path",
    )
    parser.add_argument(
        "--replace-output",
        action="store_true",
        help="allow replacing an existing receipt path (still refuses symlinks)",
    )
    return parser.parse_args()


def write_exclusive(path: Path, document: dict[str, object], *, replace: bool = False) -> None:
    if path.is_symlink():
        raise CorpusAcquisitionViolation("refusing to write through a symlink receipt path")
    if path.exists() and not replace:
        raise CorpusAcquisitionViolation("refusing to replace an existing acquisition receipt")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
        os.chmod(temporary, 0o600)
        if replace and path.exists():
            os.replace(temporary, path)
        else:
            os.link(temporary, path)
            temporary.unlink(missing_ok=True)
        os.chmod(path, 0o600)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def main() -> int:
    args = arguments()
    max_repositories = None if args.max_repositories < 0 else args.max_repositories
    try:
        receipt = acquire_openssf_corpus(
            cache_root=args.cache_root,
            benchmark_url=args.benchmark_url,
            expected_revision=args.expected_revision,
            max_repositories=max_repositories,
        )
    except CorpusAcquisitionViolation as error:
        print(f"FATAL: {error}", file=sys.stderr)
        return 2
    text = json.dumps(receipt, sort_keys=True, indent=2)
    print(text)
    if args.output is not None:
        try:
            write_exclusive(args.output, receipt, replace=args.replace_output)
        except CorpusAcquisitionViolation as error:
            print(f"FATAL: {error}", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
