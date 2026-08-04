#!/usr/bin/env python3
"""Write one immutable, source-less candidate inventory from local checkouts."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from workbench.corpus_inventory import CorpusInventoryViolation, inventory_openssf_benchmark


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inventory a pinned local OpenSSF CVE Benchmark checkout without downloading, scanning, or sealing source."
    )
    parser.add_argument("--benchmark", type=Path, required=True, help="local OpenSSF CVE Benchmark checkout")
    parser.add_argument("--expected-revision", required=True, help="exact benchmark git revision")
    parser.add_argument("--repository-cache", type=Path, required=True, help="read-only owner--repository local git cache")
    parser.add_argument("--output", type=Path, required=True, help="new JSON candidate inventory path")
    return parser.parse_args()


def write_exclusive(path: Path, document: dict[str, object]) -> None:
    if path.exists() or path.is_symlink():
        raise CorpusInventoryViolation("refusing to replace an existing inventory record")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
        os.chmod(temporary, 0o600)
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise CorpusInventoryViolation("refusing to replace an existing inventory record") from error
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    temporary.unlink(missing_ok=True)


def main() -> int:
    parsed = arguments()
    try:
        document = inventory_openssf_benchmark(
            parsed.benchmark,
            expected_revision=parsed.expected_revision,
            repository_cache=parsed.repository_cache,
        )
        write_exclusive(parsed.output, document)
    except CorpusInventoryViolation as error:
        raise SystemExit(f"refused: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
