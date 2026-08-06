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
    """Copy javascript (+ shared) qlpacks from the pinned CodeQL image into query-pack/.

    The runner mounts query-pack as CodeQL --search-path. Packs come from the
    digest-pinned container (offline copy after image pull), not an unpinned
    network fetch.
    """
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
    if pack.exists():
        shutil.rmtree(pack)
    _private_dir(pack)
    # Copy qlpacks out of the pinned image. Requires Docker and a pulled pin.
    # POSIX /bin/sh (dash) — no bash pipefail in the pinned CodeQL image.
    script = r"""
set -eu
ROOT=/usr/local/codeql-home
test -d "$ROOT/codeql-repo/javascript/ql"
test -d "$ROOT/codeql-repo/shared"
# Layout so --search-path=/prepared/query-pack resolves codeql/javascript-* packs.
mkdir -p /out
# Clear previous partial materialization without deleting the mount point.
find /out -mindepth 1 -maxdepth 1 -exec rm -rf {} +
cp -a "$ROOT/codeql-repo/javascript" /out/javascript
cp -a "$ROOT/codeql-repo/shared" /out/shared
if [ -f "$ROOT/codeql-repo/codeql-workspace.yml" ]; then
  cp -a "$ROOT/codeql-repo/codeql-workspace.yml" /out/codeql-workspace.yml
fi
codeql version >/out/codeql-version.txt 2>&1 || true
# Structural proof only: avoid resolve-qlpacks dual-root collisions with the
# image's built-in search path. Runner uses --search-path=/prepared/query-pack.
test -f /out/javascript/ql/src/qlpack.yml
test -d /out/javascript/ql/lib
test -d /out/shared
count=$(find /out -type f | wc -l)
test "$count" -gt 20
printf 'files=%s\n' "$count" >/out/pack-manifest.txt
"""
    try:
        completed = subprocess.run(
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
                script,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as error:
        raise SystemExit(f"codeql pack materialization failed: {error}") from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "docker failed").strip()[-500:]
        raise SystemExit(f"codeql pack materialization failed: {detail}")
    # Harden permissions on the host copy.
    for path in pack.rglob("*"):
        if path.is_file():
            os.chmod(path, 0o600)
        elif path.is_dir():
            os.chmod(path, 0o700)
    os.chmod(pack, 0o700)
    file_count = sum(1 for p in pack.rglob("*") if p.is_file())
    if file_count < 20:
        raise SystemExit(f"codeql query-pack too small after materialization ({file_count} files)")
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
            "Prepared source-less dependency roots from frozen policy + pinned images. "
            "CodeQL query-pack is copied from the digest-pinned container (javascript + shared). "
            "Trivy offline DB is host-private. This is not a B0 scan and not corpus admission."
        ),
    }
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
