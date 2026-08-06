"""Assert scanner image digests stay single-sourced from scanners/image-pins.env."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PINS = ROOT / "scanners" / "image-pins.env"
_PIN = re.compile(
    r'^export\s+(TRIVY_IMAGE|JUICE_SHOP_IMAGE|NUCLEI_IMAGE|SEMGREP_IMAGE|ZAP_IMAGE|CODEQL_IMAGE)='
    r'(?:"([^"]+)"|\'([^\']+)\')\s*$'
)
_SHA = re.compile(r"@sha256:([0-9a-f]{64})\b")


def _load_pins() -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in PINS.read_text(encoding="utf-8").splitlines():
        match = _PIN.fullmatch(line.strip())
        if not match:
            continue
        value = match.group(2) if match.group(2) is not None else match.group(3)
        assert value and "@sha256:" in value, f"{match.group(1)} must be digest-pinned"
        pins[match.group(1)] = value
    return pins


def test_image_pins_env_exports_all_expected_digest_pinned_images():
    pins = _load_pins()
    for name in (
        "TRIVY_IMAGE",
        "JUICE_SHOP_IMAGE",
        "NUCLEI_IMAGE",
        "SEMGREP_IMAGE",
        "ZAP_IMAGE",
        "CODEQL_IMAGE",
    ):
        assert name in pins, f"missing {name} in scanners/image-pins.env"
        assert _SHA.search(pins[name])


def test_ci_trivy_digest_matches_image_pins_env():
    pins = _load_pins()
    workflow = (ROOT / ".github" / "workflows" / "security-scan.yml").read_text(encoding="utf-8")
    pin_digest = _SHA.search(pins["TRIVY_IMAGE"])
    assert pin_digest is not None
    # CI may hardcode the same digest; require the pins digest appears in the workflow.
    assert pin_digest.group(1) in workflow, "CI Trivy digest drifted from scanners/image-pins.env"


def test_juice_shop_compose_digest_matches_image_pins_env():
    pins = _load_pins()
    compose = (ROOT / "infra" / "harness" / "juice-shop.compose.yml").read_text(encoding="utf-8")
    pin_digest = _SHA.search(pins["JUICE_SHOP_IMAGE"])
    assert pin_digest is not None
    assert pin_digest.group(1) in compose, "Juice Shop compose digest drifted from image-pins.env"
