from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_broker_launcher_advertises_a_loopback_http_adapter_without_starting_it():
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "workbench-broker.sh"), "--check"],
        check=True,
        capture_output=True,
        text=True,
    )

    assert '"state": "loopback-http-listener-available"' in result.stdout


def test_broker_launcher_refuses_to_serve_without_its_host_owned_configuration():
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "workbench-broker.sh"), "--serve"],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": __import__("os").environ["PATH"]},
    )

    assert result.returncode == 2
    assert "WORKBENCH_STARTUP_CAPABILITY" not in result.stderr
