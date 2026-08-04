from __future__ import annotations

import subprocess
from pathlib import Path
import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_b3_gateway_static_isolation_contract():
    subprocess.run(["bash", str(ROOT / "tests" / "workbench-b3-gateway-isolation-test.sh")], check=True)


def test_artifact_guard_accepts_metadata_and_rejects_a_raw_canary(tmp_path):
    clean = tmp_path / "clean.json"
    clean.write_text('{"request_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n', encoding="utf-8")
    subprocess.run(["bash", str(ROOT / "scripts" / "workbench-artifact-guard.sh"), str(clean)], check=True)

    leaky = tmp_path / "leaky.json"
    leaky.write_text('{"detail":"WORKBENCH_RAW_SOURCE_CANARY"}\n', encoding="utf-8")
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "workbench-artifact-guard.sh"), str(leaky)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1


def test_web_compose_is_loopback_nonroot_and_has_no_privileged_mounts():
    document = yaml.safe_load((ROOT / "infra" / "workbench" / "docker-compose.yml").read_text(encoding="utf-8"))
    web = document["services"]["web"]
    assert web["ports"] == ["127.0.0.1:4173:4173"]
    assert web["user"] == "10001:10001"
    assert web["read_only"] is True
    assert web["networks"] == ["workbench-web"]
    assert web["environment"]["WORKBENCH_BROKER_ORIGIN"] == "${WORKBENCH_BROKER_ORIGIN:-}"
    surface = repr(web).lower()
    for forbidden in ("docker.sock", "b3_litellm_virtual_key", "infra/.env", "evidence"):
        assert forbidden not in surface


def test_workbench_up_generates_a_one_time_fragment_capability_for_the_host_broker_before_compose():
    source = (ROOT / "scripts" / "workbench-up.sh").read_text(encoding="utf-8")

    assert "WORKBENCH_STARTUP_CAPABILITY" in source
    assert "workbench-broker.sh" in source and "--serve" in source
    assert "workbench-worker.sh" in source and "--serve" in source
    assert 'bash "$ROOT/scripts/workbench-broker.sh" --serve' in source
    assert 'bash "$ROOT/scripts/workbench-worker.sh" --serve' in source
    assert "#startup_capability=" in source
