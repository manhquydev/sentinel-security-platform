import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
EXPORTER = ROOT / "attack-surface" / "export-baseline.py"
MANIFEST = ROOT / "attack-surface" / "target-manifest.json"
OBSERVATIONS = ROOT / "attack-surface" / "observations" / "juice-shop-df1b6bbd8bce.json"
BASELINE = ROOT / "attack-surface" / "baselines" / "juice-shop-df1b6bbd8bce.json"


def run_export(*args, cwd=ROOT):
    return subprocess.run(
        [sys.executable, str(EXPORTER), *map(str, args)],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def test_repository_baseline_is_schema_valid_and_deterministic(tmp_path):
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    for output in (first, second):
        result = run_export(
            "build",
            "--manifest",
            MANIFEST,
            "--observations",
            OBSERVATIONS,
            "--output",
            output,
        )
        assert result.returncode == 0, result.stderr
    assert first.read_bytes() == second.read_bytes()
    assert json.loads(first.read_text())["target"]["image_digest"].startswith("sha256:")


def test_export_rejects_digest_mismatch(tmp_path):
    observations = json.loads(OBSERVATIONS.read_text())
    observations["target_digest"] = "sha256:" + "0" * 64
    bad = tmp_path / "observations.json"
    bad.write_text(json.dumps(observations))
    result = run_export("build", "--manifest", MANIFEST, "--observations", bad, "--output", tmp_path / "out.json")
    assert result.returncode != 0
    assert "digest" in result.stderr.lower()


def test_export_rejects_duplicate_composite_key(tmp_path):
    observations = json.loads(OBSERVATIONS.read_text())
    observations["observations"].append(dict(observations["observations"][0]))
    bad = tmp_path / "observations.json"
    bad.write_text(json.dumps(observations))
    result = run_export("build", "--manifest", MANIFEST, "--observations", bad, "--output", tmp_path / "out.json")
    assert result.returncode != 0
    assert "duplicate" in result.stderr.lower()


@pytest.mark.parametrize("path", ["/reset/0123456789abcdef0123456789abcdef", "/x;sid=secret", "/x?token=secret"])
def test_export_rejects_path_tokens(tmp_path, path):
    observations = json.loads(OBSERVATIONS.read_text())
    observations["observations"][0]["path"] = path
    bad = tmp_path / "observations.json"
    bad.write_text(json.dumps(observations))
    result = run_export("build", "--manifest", MANIFEST, "--observations", bad, "--output", tmp_path / "out.json")
    assert result.returncode != 0
    assert "path" in result.stderr.lower() or "token" in result.stderr.lower()


def test_export_rejects_semgrep_and_forbidden_values(tmp_path):
    observations = json.loads(OBSERVATIONS.read_text())
    observations["observations"][0]["evidence_source"] = "semgrep"
    observations["observations"][0]["parameters"] = [{"name": "password", "type": "string", "value": "secret"}]
    bad = tmp_path / "observations.json"
    bad.write_text(json.dumps(observations))
    result = run_export("build", "--manifest", MANIFEST, "--observations", bad, "--output", tmp_path / "out.json")
    assert result.returncode != 0


def test_export_rejects_stale_evidence_hash(tmp_path):
    observations = json.loads(OBSERVATIONS.read_text())
    observations["observations"][0]["source_sha256"] = "0" * 64
    bad = tmp_path / "observations.json"
    bad.write_text(json.dumps(observations))
    result = run_export("build", "--manifest", MANIFEST, "--observations", bad, "--output", tmp_path / "out.json")
    assert result.returncode != 0
    assert "hash" in result.stderr.lower()


def test_build_does_not_touch_scanner_outputs(tmp_path):
    before = None
    scanner_output = ROOT / "scanners" / "out" / "nuclei.san.jsonl"
    if scanner_output.exists():
        before = hashlib.sha256(scanner_output.read_bytes()).hexdigest()
    result = run_export("build", "--manifest", MANIFEST, "--observations", OBSERVATIONS, "--output", tmp_path / "out.json")
    assert result.returncode == 0, result.stderr
    if before:
        assert hashlib.sha256(scanner_output.read_bytes()).hexdigest() == before


def test_build_does_not_change_protected_week1_files(tmp_path):
    protected = []
    patterns = [
        ".github/**",
        "infra/systemd/**",
        "infra/defectdojo/lake-baseline.json",
        "docs/plans/active/week1-ci-orchestration-and-scanner-hardening.md",
        "scripts/scan-and-import.sh",
        "scripts/verify-lake.sh",
        "scripts/README.md",
        "scanners/**",
        "tests/**",
    ]
    for pattern in patterns:
        protected.extend(Path(path) for path in subprocess.check_output(["git", "ls-files", "--", pattern], text=True).splitlines())
    protected.extend(Path(path) for path in (ROOT / "scanners" / "out").glob("*") if path.is_file())
    before = {path: hashlib.sha256(path.read_bytes()).digest() for path in protected}
    result = run_export("build", "--manifest", MANIFEST, "--observations", OBSERVATIONS, "--output", tmp_path / "out.json")
    assert result.returncode == 0, result.stderr
    assert {path: hashlib.sha256(path.read_bytes()).digest() for path in protected} == before


def test_runtime_preflight_rejects_non_loopback_manifest(tmp_path):
    manifest = json.loads(MANIFEST.read_text())
    manifest["target"]["origin"] = "http://example.invalid:13000"
    bad = tmp_path / "manifest.json"
    bad.write_text(json.dumps(manifest))
    result = run_export("verify-runtime", "--manifest", bad)
    assert result.returncode != 0
    assert "loopback" in result.stderr.lower()
