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
from workbench.scanner_runner import FixtureScannerRunner, RunnerViolation


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _harden_private_tree(root: Path) -> None:
    """Make a prepared tree privately mode-matched for runner verification."""
    for path in root.rglob("*"):
        if path.is_symlink():
            raise SystemExit(f"prepared tree contains a symbolic link: {path}")
        if path.is_file():
            os.chmod(path, 0o600)
        elif path.is_dir():
            os.chmod(path, 0o700)
    os.chmod(root, 0o700)


def _sha256_tree(root: Path) -> str:
    """Match FixtureScannerRunner._private_tree_digest exactly (path/sha256/bytes)."""
    _harden_private_tree(root)
    try:
        return FixtureScannerRunner._private_tree_digest(root, "prepared Trivy database cache")
    except RunnerViolation as error:
        raise SystemExit(str(error)) from error


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def _load_policy(policy_root: Path) -> dict:
    return json.loads((policy_root / "policy.json").read_text(encoding="utf-8"))


def _acquisition_digest(acquisition: dict) -> str:
    """Match ScannerEngineCapability.acquisition_digest (canonical map digest)."""
    return hashlib.sha256(
        json.dumps(acquisition, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def prepare_semgrep(policy_root: Path, prepared_root: Path, policy: dict) -> Path:
    ruleset = policy_root / policy["engines"]["semgrep"]["files"]["ruleset"]
    ruleset_digest = policy["engines"]["semgrep"]["acquisition"]["ruleset_digest"]
    if _sha256_file(ruleset) != ruleset_digest:
        raise SystemExit("semgrep frozen ruleset digest mismatch")
    acquisition = {"ruleset_digest": ruleset_digest}
    dest = prepared_root / "semgrep" / _acquisition_digest(acquisition)
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
    digests = dict(policy["engines"]["codeql"]["acquisition"])
    dest = prepared_root / "codeql" / _acquisition_digest(digests)
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
test -d "$ROOT/codeql-repo/misc/suite-helpers"
# Layout so --search-path=/prepared/query-pack resolves codeql/javascript-* packs.
# javascript-queries depends on suite-helpers (misc/), util/typos (shared/).
mkdir -p /out
# Clear previous partial materialization without deleting the mount point.
find /out -mindepth 1 -maxdepth 1 -exec rm -rf {} +
cp -a "$ROOT/codeql-repo/javascript" /out/javascript
cp -a "$ROOT/codeql-repo/shared" /out/shared
mkdir -p /out/misc
cp -a "$ROOT/codeql-repo/misc/suite-helpers" /out/misc/suite-helpers
if [ -f "$ROOT/codeql-repo/codeql-workspace.yml" ]; then
  cp -a "$ROOT/codeql-repo/codeql-workspace.yml" /out/codeql-workspace.yml
fi
codeql version >/out/codeql-version.txt 2>&1 || true
# Structural proof only: avoid resolve-qlpacks dual-root collisions with the
# image's built-in search path. Runner uses --search-path=/prepared/query-pack.
test -f /out/javascript/ql/src/qlpack.yml
test -d /out/javascript/ql/lib
test -d /out/shared
test -f /out/misc/suite-helpers/qlpack.yml
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
    """Prepare offline Trivy cache under runner acquisition_digest directory name."""
    # Stage under a temp name, then rehome to acquisition_digest({db_snapshot_digest: tree}).
    staging = prepared_root / "trivy" / ".staging"
    if staging.exists():
        shutil.rmtree(staging)
    cache = staging / "cache"
    _private_dir(staging)
    _private_dir(cache)
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
        # Docker often leaves root-owned DB files; re-own for host-private mode + hashing.
        if any(cache.rglob("*")):
            uid, gid = os.getuid(), os.getgid()
            subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{cache}:/cache",
                    "alpine:3.20",
                    "sh",
                    "-ceu",
                    f"find /cache -type d -exec chmod 700 {{}} +; "
                    f"find /cache -type f -exec chmod 600 {{}} +; "
                    f"chown -R {uid}:{gid} /cache",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    if not any(cache.rglob("*")):
        # Keep a private empty layout so operators can populate later; use policy file
        # digest as placeholder tree identity (will not match a real scan until filled).
        tree_digest = policy["engines"]["trivy"]["acquisition"]["db_snapshot_digest"]
    else:
        tree_digest = _sha256_tree(cache)
    acquisition = {"db_snapshot_digest": tree_digest}
    dest = prepared_root / "trivy" / _acquisition_digest(acquisition)
    if dest.exists():
        shutil.rmtree(dest)
    staging.rename(dest)
    cache = dest / "cache"
    metadata = {
        "schema_version": "sentinel-workbench-trivy-db-snapshot/v1",
        "db_snapshot_digest": tree_digest,
    }
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
            "CodeQL query-pack is copied from the digest-pinned container (javascript + shared + suite-helpers). "
            "Trivy offline DB is host-private. This is not a B0 scan and not corpus admission."
        ),
    }
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
