#!/usr/bin/env python3
"""Prepare host-private source-less B0 scanner dependency roots (not a scan).

Creates layout under --prepared-root/<engine>/<acquisition_digest>/ matching
workbench.scanner_runner expectations. CodeQL pack bytes and Trivy DB cache are
materialized via Docker when images are available; Semgrep copies frozen.yml.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from workbench.scanner_contracts import default_engine_statuses


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_tree(root: Path) -> str:
    files: list[tuple[str, str]] = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            rel = path.relative_to(root).as_posix()
            files.append((rel, _sha256_file(path)))
    payload = json.dumps(files, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def _load_policy(policy_root: Path) -> dict:
    return json.loads((policy_root / "policy.json").read_text(encoding="utf-8"))


def prepare_semgrep(policy_root: Path, prepared_root: Path, policy: dict) -> Path:
    ruleset = policy_root / policy["engines"]["semgrep"]["files"]["ruleset"]
    digest = policy["engines"]["semgrep"]["acquisition"]["ruleset_digest"]
    if _sha256_file(ruleset) != digest:
        raise SystemExit("semgrep frozen ruleset digest mismatch")
    dest = prepared_root / "semgrep" / digest
    _private_dir(dest)
    target = dest / "frozen.yml"
    shutil.copy2(ruleset, target)
    os.chmod(target, 0o600)
    return dest


def prepare_codeql(policy_root: Path, prepared_root: Path, policy: dict, image: str) -> Path:
    suite = policy_root / policy["engines"]["codeql"]["files"]["query_suite"]
    digests = policy["engines"]["codeql"]["acquisition"]
    acquisition_digest = hashlib.sha256(
        json.dumps(digests, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    dest = prepared_root / "codeql" / acquisition_digest
    _private_dir(dest)
    shutil.copy2(suite, dest / "query-suite.qls")
    os.chmod(dest / "query-suite.qls", 0o600)
    pack = dest / "query-pack"
    _private_dir(pack)
    # Materialize a minimal pack placeholder directory structure. Full CodeQL
    # pack download requires network and licensed distribution; record a marker
    # that the runner will still require real pack contents for a successful DB.
    marker = pack / "README.workbench-prepared"
    marker.write_text(
        "Place or extract the frozen CodeQL javascript-typescript + actions query "
        "pack contents here before a source-mounted B0 run.\n",
        encoding="utf-8",
    )
    os.chmod(marker, 0o600)
    # Attempt optional pack pull into the pack dir when docker is available.
    try:
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{pack}:/out:rw",
                "--entrypoint",
                "/bin/sh",
                image,
                "-ceu",
                "command -v codeql >/dev/null && codeql --version >/out/codeql-version.txt || true",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return dest


def prepare_trivy(policy_root: Path, prepared_root: Path, policy: dict, image: str) -> Path:
    digests = policy["engines"]["trivy"]["acquisition"]
    # Runtime admission digests the offline cache tree; start with a private empty
    # cache + policy-bound metadata so layout exists. Operators then populate cache.
    policy_digest = digests["db_snapshot_digest"]
    dest = prepared_root / "trivy" / policy_digest
    cache = dest / "cache"
    _private_dir(dest)
    _private_dir(cache)
    # Try to download DB inside a networked container into the cache (optional).
    try:
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{cache}:/root/.cache/trivy:rw",
                image,
                "image",
                "--download-db-only",
                "--no-progress",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    tree_digest = _sha256_tree(cache) if any(cache.iterdir()) else policy_digest
    metadata = {
        "schema_version": "sentinel-workbench-trivy-db-snapshot/v1",
        "db_snapshot_digest": tree_digest if any(cache.iterdir()) else policy_digest,
    }
    # If we populated a real cache, re-home under the tree digest directory.
    if any(cache.iterdir()) and tree_digest != policy_digest:
        final = prepared_root / "trivy" / tree_digest
        if final.resolve() != dest.resolve():
            if final.exists():
                shutil.rmtree(final)
            dest.rename(final)
            dest = final
            cache = dest / "cache"
        metadata["db_snapshot_digest"] = tree_digest
    meta_path = dest / "metadata.json"
    raw = (json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
    meta_path.write_bytes(raw)
    os.chmod(meta_path, 0o600)
    return dest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prepared-root",
        type=Path,
        default=Path.home() / ".cache" / "sentinel-workbench" / "prepared-deps",
    )
    parser.add_argument("--policy-root", type=Path, default=Path("scanners/workbench-b0"))
    parser.add_argument("--image-pins", type=Path, default=Path("scanners/image-pins.env"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    statuses = default_engine_statuses(args.image_pins, policy_root=args.policy_root)
    if any(status.get("state") != "ready" for status in statuses.values()):
        print(json.dumps({"error": "b0-policy-not-ready", "engines": statuses}, indent=2))
        return 2
    policy = _load_policy(args.policy_root)
    _private_dir(args.prepared_root)
    pins = {}
    for line in args.image_pins.read_text(encoding="utf-8").splitlines():
        if line.startswith("export ") and "=" in line:
            key, value = line[len("export ") :].split("=", 1)
            pins[key] = value.strip().strip('"').strip("'")
    results = {
        "schema_version": "sentinel-workbench-prepared-deps-receipt/v1",
        "semgrep": str(prepare_semgrep(args.policy_root, args.prepared_root, policy)),
        "codeql": str(
            prepare_codeql(
                args.policy_root,
                args.prepared_root,
                policy,
                pins["CODEQL_IMAGE"],
            )
        ),
        "trivy": str(
            prepare_trivy(
                args.policy_root,
                args.prepared_root,
                policy,
                pins["TRIVY_IMAGE"],
            )
        ),
        "notes": (
            "Prepared layout only. CodeQL still needs a full query pack under "
            "query-pack/ for a successful database analyze. Trivy needs a non-empty "
            "offline cache for vuln scanning. This is not a B0 scan and not corpus admission."
        ),
    }
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
