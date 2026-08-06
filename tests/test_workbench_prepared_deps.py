from __future__ import annotations

from pathlib import Path

from workbench.prepared_deps import b0_readiness, prepared_deps_statuses


def test_prepared_deps_statuses_report_not_ready_for_empty_root(tmp_path):
    statuses = prepared_deps_statuses(tmp_path / "empty", policy_root=Path("scanners/workbench-b0"))
    assert set(statuses) == {"codeql", "semgrep", "trivy"}
    assert all(item["state"] == "not-ready" for item in statuses.values())


def test_b0_readiness_exposes_dual_layers_without_claiming_a_clean_scan():
    readiness = b0_readiness(
        image_pins_path=Path("scanners/image-pins.env"),
        policy_root=Path("scanners/workbench-b0"),
        prepared_root=Path.home() / ".cache" / "sentinel-workbench" / "prepared-deps",
    )
    assert readiness["schema_version"] == "sentinel-workbench-b0-readiness/v1"
    assert readiness["overall"] in {"not-ready", "policy-ready", "prepared-deps-ready"}
    notes = readiness["notes"].lower()
    assert "neither is a clean" in notes or "not a clean" in notes
    assert set(readiness["policy"]) == {"codeql", "semgrep", "trivy"}
    assert set(readiness["prepared_deps"]) == {"codeql", "semgrep", "trivy"}
