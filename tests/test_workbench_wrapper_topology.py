from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DIGEST = "a" * 64


def fake_docker(tmp_path: Path, report: str) -> Path:
    command_log = tmp_path / "docker-argv.txt"
    path = tmp_path / "docker"
    path.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"printf '%s\\n' \"$@\" > {command_log}\n"
        f"printf '%s\\n' {report!r}\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return command_log


def environment(tmp_path: Path) -> dict[str, str]:
    result = dict(os.environ)
    result["PATH"] = f"{tmp_path}:{result['PATH']}"
    return result


def isolated_semgrep_wrapper(tmp_path: Path) -> Path:
    scanners = tmp_path / "scanners"
    scanners.mkdir()
    for name in ("run-semgrep.sh", "write-status.sh"):
        target = scanners / name
        shutil.copy2(ROOT / "scanners" / name, target)
        target.chmod(0o755)
    (scanners / "image-pins.env").write_text(
        f'export SEMGREP_IMAGE="example/semgrep@sha256:{DIGEST}"\n',
        encoding="utf-8",
    )
    return scanners / "run-semgrep.sh"


def test_semgrep_workbench_source_mount_is_network_isolated(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.ts").write_text("const ok = true;\n", encoding="utf-8")
    rule = tmp_path / "frozen.yml"
    rule.write_text("rules: []\n", encoding="utf-8")
    checksum = hashlib.sha256(rule.read_bytes()).hexdigest()
    (tmp_path / "CHECKSUMS.txt").write_text(f"{checksum}  frozen.yml\n", encoding="utf-8")
    log = fake_docker(tmp_path, '{"results":[],"errors":[],"paths":{"scanned":["/src/app.ts"]}}')
    out = tmp_path / "out.json"

    subprocess.run(
        [str(isolated_semgrep_wrapper(tmp_path)), str(out)],
        check=True,
        env={
            **environment(tmp_path),
            "TARGET_SRC": str(source),
            "SEMGREP_RULESET": str(rule),
            "WORKBENCH_SOURCE_MOUNT": "1",
        },
        capture_output=True,
        text=True,
    )

    assert "--network\nnone\n" in log.read_text(encoding="utf-8")
    assert "/src:ro" in log.read_text(encoding="utf-8")


def test_trivy_workbench_filesystem_source_mount_is_network_isolated_and_invalid_flag_refuses(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.ts").write_text("const ok = true;\n", encoding="utf-8")
    log = fake_docker(tmp_path, '{"Results":[]}')
    out = tmp_path / "out.json"
    base_env = {
        **environment(tmp_path),
        "TARGET_SRC": str(source),
        "TRIVY_IMAGE": f"example/trivy@sha256:{DIGEST}",
    }

    subprocess.run(
        [str(ROOT / "scanners" / "run-trivy.sh"), str(out)],
        check=True,
        env={**base_env, "WORKBENCH_SOURCE_MOUNT": "1"},
        capture_output=True,
        text=True,
    )
    assert "--network\nnone\n" in log.read_text(encoding="utf-8")

    refused = subprocess.run(
        [str(ROOT / "scanners" / "run-trivy.sh"), str(tmp_path / "refused.json")],
        env={**base_env, "WORKBENCH_SOURCE_MOUNT": "yes"},
        capture_output=True,
        text=True,
    )
    assert refused.returncode != 0
    assert "WORKBENCH_SOURCE_MOUNT" in refused.stderr


def test_preflight_reports_capability_states_only_and_never_fabricates_a_scan_outcome():
    import json

    result = subprocess.run(
        [str(ROOT / "scripts" / "workbench-scanner-preflight.sh"), "--fixture-profile", "typescript"],
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["kind"] == "capability-status-not-scan-result"
    assert set(payload["engines"]) == {"codeql", "semgrep", "trivy"}
    assert all(engine["state"] in {"ready", "not-ready"} for engine in payload["engines"].values())
    assert "clean" not in result.stdout.lower()
    # Ready is policy readiness only — never a fabricated B0 scan verdict.
    assert "findings" not in result.stdout.lower()


def test_broker_launcher_is_honest_that_the_host_owns_an_available_loopback_listener():
    result = subprocess.run(
        [str(ROOT / "scripts" / "workbench-broker.sh"), "--check"],
        check=True,
        capture_output=True,
        text=True,
    )

    assert '"state": "loopback-http-listener-available"' in result.stdout
