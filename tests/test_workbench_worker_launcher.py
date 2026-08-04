from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_worker_launcher_refuses_to_start_without_the_host_broker_configuration():
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "workbench-worker.sh"), "--serve"],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": __import__("os").environ["PATH"]},
    )

    assert result.returncode == 2
    assert "WORKBENCH_STARTUP_CAPABILITY" not in result.stderr
