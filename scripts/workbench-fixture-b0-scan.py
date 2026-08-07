#!/usr/bin/env python3
"""Run a fixture-only B0 engine command against a sealed typescript-graph snapshot.

Wires SealedFixtureStore + prepared-deps + FixtureScannerRunner. Executes Docker
when available; always fail-closed. This is not comparative corpus admission.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from workbench.prepared_deps import b0_readiness
from workbench.scanner_contracts import ScannerCapabilityManifest
from workbench.scanner_runner import FixtureScannerRunner, RunnerViolation
from workbench.sealed_store import SealedFixtureStore, SealedStoreViolation


def _load_pins(path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("export ") or "=" not in line:
            continue
        key, value = line[len("export ") :].split("=", 1)
        pins[key] = value.strip().strip('"').strip("'")
    return pins


def _image_digest(image: str) -> str:
    marker = "@sha256:"
    if marker not in image:
        raise SystemExit(f"image is not digest-pinned: {image}")
    return image.rsplit(marker, 1)[1]


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _build_capability(
    *,
    snapshot_id: str,
    pins: dict[str, str],
    policy: dict,
    trivy_db_snapshot_digest: str,
) -> ScannerCapabilityManifest:
    digest = "b" * 64  # non-image cli/policy placeholders for fixture run metadata
    engines = []
    for name, parser, image_key, acquisition in (
        (
            "codeql",
            "sarif",
            "CODEQL_IMAGE",
            dict(policy["engines"]["codeql"]["acquisition"]),
        ),
        (
            "semgrep",
            "semgrep-json",
            "SEMGREP_IMAGE",
            dict(policy["engines"]["semgrep"]["acquisition"]),
        ),
        (
            "trivy",
            "trivy-json",
            "TRIVY_IMAGE",
            {"db_snapshot_digest": trivy_db_snapshot_digest},
        ),
    ):
        image = pins[image_key]
        engines.append(
            {
                "engine": name,
                "language_scope": (
                    ["JavaScript", "TypeScript", "GitHub Actions"]
                    if name == "codeql"
                    else ["TypeScript", "TSX", "YAML"]
                    if name == "semgrep"
                    else ["filesystem", "config", "secret"]
                ),
                "file_scope": (
                    [
                        "**/*.js",
                        "**/*.ts",
                        "**/*.tsx",
                        ".github/workflows/**/*.yml",
                        ".github/workflows/**/*.yaml",
                    ]
                    if name == "codeql"
                    else ["**/*.ts", "**/*.tsx", "**/*.yml", "**/*.yaml"]
                    if name == "semgrep"
                    else ["**/*"]
                ),
                "image": image,
                "image_digest": _image_digest(image),
                "cli_digest": digest,
                "tool_version": "fixture-b0",
                "policy_digest": digest,
                "acquisition": acquisition,
                "parser": parser,
                "network_policy": "source-mounted-network-none",
                "unsupported_coverage": ["fixture-only"],
                "completion": {
                    "runner_metadata": "present",
                    "raw_artifact": "present",
                    "parse": "complete",
                    **(
                        {
                            "database": "complete",
                            "sarif": "present",
                            "conversion": "complete",
                        }
                        if name == "codeql"
                        else {}
                    ),
                    **({"database": "current"} if name == "trivy" else {}),
                },
            }
        )
    return ScannerCapabilityManifest.from_mapping(
        {
            "schema_version": "sentinel-workbench-scanner-capability/v1",
            "profile": "fixture-typescript",
            "snapshot_id": snapshot_id,
            "config_digest": digest,
            "engines": engines,
        }
    )


def _trivy_tree_digest(prepared_root: Path, capability: ScannerCapabilityManifest) -> str:
    item = capability.engine("trivy")
    meta = prepared_root / "trivy" / item.acquisition_digest / "metadata.json"
    if not meta.is_file():
        # Fall back to any prepared trivy metadata for wiring scripts that re-home digests.
        for candidate in (prepared_root / "trivy").glob("*/metadata.json"):
            document = json.loads(candidate.read_text(encoding="utf-8"))
            if document.get("schema_version") == "sentinel-workbench-trivy-db-snapshot/v1":
                return document["db_snapshot_digest"]
        raise SystemExit("trivy prepared metadata missing; run workbench-prepare-scanner-deps.py")
    return json.loads(meta.read_text(encoding="utf-8"))["db_snapshot_digest"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("semgrep", "trivy", "codeql", "all"), default="semgrep")
    parser.add_argument(
        "--evidence-root",
        type=Path,
        default=Path.home() / ".cache" / "sentinel-workbench" / "fixture-evidence",
    )
    parser.add_argument(
        "--prepared-root",
        type=Path,
        default=Path.home() / ".cache" / "sentinel-workbench" / "prepared-deps",
    )
    parser.add_argument("--execute", action="store_true", help="run Docker commands (default: print only)")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)

    readiness = b0_readiness(prepared_root=args.prepared_root)
    if readiness["overall"] not in {"policy-ready", "prepared-deps-ready"}:
        print(json.dumps({"error": "b0-not-policy-ready", "readiness": readiness}, indent=2))
        return 2

    pins = _load_pins(Path("scanners/image-pins.env"))
    policy = json.loads(Path("scanners/workbench-b0/policy.json").read_text(encoding="utf-8"))
    fixture_root = Path("workbench/fixtures")
    store = SealedFixtureStore(args.evidence_root, fixture_root)
    try:
        sealed = store.seal_fixture(fixture_root / "typescript-graph", fixture_id="typescript-graph")
    except SealedStoreViolation as error:
        print(f"FATAL: {error}", file=sys.stderr)
        return 2

    # Bootstrap trivy digest from prepared metadata then rebuild capability.
    # Temporary capability acquisition for path probe:
    bootstrap = _build_capability(
        snapshot_id=sealed.snapshot_id,
        pins=pins,
        policy=policy,
        trivy_db_snapshot_digest="0" * 64,
    )
    # Discover prepared trivy tree digest for real capability.
    trivy_digest = None
    for meta in args.prepared_root.glob("trivy/*/metadata.json"):
        try:
            document = json.loads(meta.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if document.get("schema_version") == "sentinel-workbench-trivy-db-snapshot/v1":
            trivy_digest = document["db_snapshot_digest"]
            break
    if trivy_digest is None:
        print("FATAL: trivy prepared deps missing", file=sys.stderr)
        return 2

    capability = _build_capability(
        snapshot_id=sealed.snapshot_id,
        pins=pins,
        policy=policy,
        trivy_db_snapshot_digest=trivy_digest,
    )
    # Symlink/copy prepared roots under acquisition_digest if prepare used matching layout.
    raw_root = args.evidence_root / "raw-artifacts"
    raw_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(raw_root, 0o700)
    runner = FixtureScannerRunner(store, capability, args.prepared_root, raw_root)

    engines = ["semgrep", "trivy", "codeql"] if args.engine == "all" else [args.engine]
    report: dict[str, object] = {
        "schema_version": "sentinel-workbench-fixture-b0-scan-receipt/v1",
        "snapshot_id": sealed.snapshot_id,
        "fixture_id": "typescript-graph",
        "readiness_overall": readiness["overall"],
        "admission_decision": "not-admitted",
        "engines": {},
    }
    for engine in engines:
        try:
            command = runner.command_for(engine, sealed.snapshot_id)
        except RunnerViolation as error:
            report["engines"][engine] = {"state": "command-refused", "reason": str(error)}
            continue
        entry: dict[str, object] = {
            "state": "command-ready",
            "command": list(command),
            "network_none": "--network" in command and "none" in command,
        }
        if args.execute:
            try:
                completed = subprocess.run(command, capture_output=True, text=True, timeout=900)
            except (OSError, subprocess.TimeoutExpired) as error:
                entry.update({"state": "execute-failed", "reason": str(error)})
            else:
                entry["exit_code"] = completed.returncode
                entry["stdout_bytes"] = len(completed.stdout.encode("utf-8", errors="replace"))
                entry["stderr_tail"] = (completed.stderr or "")[-400:]
                if engine in {"semgrep", "trivy"} and completed.stdout.strip():
                    try:
                        payload = json.loads(completed.stdout)
                        receipt = runner.capture_raw_artifact(engine, sealed.snapshot_id, payload)
                        entry["state"] = "executed-and-quarantined"
                        entry["receipt"] = receipt
                    except Exception as error:  # normalization fail-closed
                        entry["state"] = "executed-normalize-failed"
                        entry["reason"] = str(error)
                elif engine == "codeql":
                    # SARIF written inside work mount; capture requires on-disk DB evidence.
                    entry["state"] = "executed-codeql-pending-capture"
                else:
                    entry["state"] = "executed-empty-output"
        report["engines"][engine] = entry

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
