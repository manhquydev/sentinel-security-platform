"""Inspect host-private prepared B0 dependency roots (not a scan result)."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

from .scanner_contracts import default_engine_statuses


def _policy(policy_root: Path) -> Mapping[str, Any]:
    return json.loads((policy_root / "policy.json").read_text(encoding="utf-8"))


def _private_dir(path: Path) -> bool:
    try:
        st = path.stat()
    except OSError:
        return False
    return path.is_dir() and not path.is_symlink() and (st.st_mode & 0o077) == 0


def _private_file(path: Path) -> bool:
    try:
        st = path.stat()
    except OSError:
        return False
    return path.is_file() and not path.is_symlink() and (st.st_mode & 0o077) == 0


def _codeql_acquisition_digest(policy: Mapping[str, Any]) -> str:
    digests = policy["engines"]["codeql"]["acquisition"]
    return hashlib.sha256(
        json.dumps(digests, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _semgrep_ready(prepared_root: Path, policy: Mapping[str, Any]) -> tuple[bool, str]:
    digest = policy["engines"]["semgrep"]["acquisition"]["ruleset_digest"]
    path = prepared_root / "semgrep" / digest / "frozen.yml"
    if not _private_file(path):
        return False, "missing-prepared-semgrep-ruleset"
    if path.stat().st_size < 32:
        return False, "empty-prepared-semgrep-ruleset"
    return True, "prepared-semgrep-ruleset-present"


def _codeql_ready(prepared_root: Path, policy: Mapping[str, Any]) -> tuple[bool, str]:
    digest = _codeql_acquisition_digest(policy)
    root = prepared_root / "codeql" / digest
    suite = root / "query-suite.qls"
    pack = root / "query-pack"
    if not _private_file(suite):
        return False, "missing-prepared-codeql-query-suite"
    if not _private_dir(pack):
        return False, "missing-prepared-codeql-query-pack"
    # Require real pack material, not a single README marker.
    files = [p for p in pack.rglob("*") if p.is_file() and p.name != "README.workbench-prepared"]
    if len(files) < 20:
        return False, "incomplete-codeql-query-pack"
    # javascript queries pack path as extracted from the pinned image
    if not (pack / "javascript" / "ql" / "src").is_dir() and not any(
        "javascript-queries" in p.as_posix() or p.name == "qlpack.yml" for p in pack.rglob("qlpack.yml")
    ):
        return False, "codeql-query-pack-missing-javascript-queries"
    return True, "prepared-codeql-query-pack-present"


def _trivy_ready(prepared_root: Path, policy: Mapping[str, Any]) -> tuple[bool, str]:
    # Prefer any trivy prepared root that has canonical metadata + non-empty cache.
    base = prepared_root / "trivy"
    if not base.is_dir():
        return False, "missing-prepared-trivy-root"
    candidates = [p for p in base.iterdir() if p.is_dir() and not p.is_symlink()]
    if not candidates:
        return False, "missing-prepared-trivy-snapshot"
    for dest in candidates:
        meta = dest / "metadata.json"
        cache = dest / "cache"
        if not _private_file(meta) or not _private_dir(cache):
            continue
        try:
            document = json.loads(meta.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if document.get("schema_version") != "sentinel-workbench-trivy-db-snapshot/v1":
            continue
        if not any(cache.rglob("*")):
            continue
        return True, "prepared-trivy-offline-db-present"
    return False, "incomplete-trivy-offline-db"


def prepared_deps_statuses(
    prepared_root: Path | str,
    *,
    policy_root: Path | str | None = None,
) -> dict[str, dict[str, str]]:
    """Return per-engine prepared-deps readiness (host-local layout only)."""
    root = Path(prepared_root).expanduser().resolve()
    policy_path = Path(policy_root) if policy_root is not None else Path("scanners/workbench-b0")
    policy = _policy(policy_path)
    checkers = {
        "codeql": _codeql_ready,
        "semgrep": _semgrep_ready,
        "trivy": _trivy_ready,
    }
    statuses: dict[str, dict[str, str]] = {}
    for engine, checker in checkers.items():
        ok, reason = checker(root, policy)
        statuses[engine] = {
            "state": "ready" if ok else "not-ready",
            "reason": reason,
        }
    return statuses


def b0_readiness(
    *,
    image_pins_path: Path | str = "scanners/image-pins.env",
    policy_root: Path | str = "scanners/workbench-b0",
    prepared_root: Path | str | None = None,
) -> dict[str, object]:
    """Dual-layer B0 readiness: policy freeze vs prepared source-less deps.

    Neither layer is a clean B0 scan outcome or corpus admission.
    """
    pins = Path(image_pins_path)
    policy = Path(policy_root)
    prepared = (
        Path(prepared_root).expanduser()
        if prepared_root is not None
        else Path.home() / ".cache" / "sentinel-workbench" / "prepared-deps"
    )
    policy_status = default_engine_statuses(pins, policy_root=policy)
    deps_status = prepared_deps_statuses(prepared, policy_root=policy)
    policy_ready = all(item.get("state") == "ready" for item in policy_status.values())
    deps_ready = all(item.get("state") == "ready" for item in deps_status.values())
    if not policy_ready:
        overall = "not-ready"
    elif deps_ready:
        overall = "prepared-deps-ready"
    else:
        overall = "policy-ready"
    return {
        "schema_version": "sentinel-workbench-b0-readiness/v1",
        "overall": overall,
        "policy": policy_status,
        "prepared_deps": deps_status,
        "prepared_root": str(prepared),
        "notes": (
            "policy-ready means image pins + frozen policy digests. "
            "prepared-deps-ready means host-private query-pack/ruleset/offline-DB layout. "
            "Neither is a clean B0 scan result or corpus admission."
        ),
    }
