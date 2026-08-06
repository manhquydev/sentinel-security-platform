"""Metadata-only view state for the browser."""
from __future__ import annotations

from pathlib import Path
from typing import Mapping

from ..result_state import render_result_state
from ..reporting import render_public_summary
from ..scanner_contracts import default_engine_statuses


def _b0_control_from_preflight(
    *,
    image_pins_path: Path | str | None = None,
    policy_root: Path | str | None = None,
) -> dict[str, object]:
    """Surface policy readiness only — never a clean B0 scan outcome."""
    pins = Path(image_pins_path) if image_pins_path is not None else Path("scanners/image-pins.env")
    statuses = default_engine_statuses(pins, policy_root=policy_root)
    ready = [engine for engine, status in statuses.items() if status.get("state") == "ready"]
    not_ready = [engine for engine, status in statuses.items() if status.get("state") != "ready"]
    if not_ready:
        reasons = ", ".join(
            f"{engine}:{statuses[engine].get('reason', 'not-ready')}" for engine in not_ready
        )
        return {
            "state": "not-ready",
            "detail": (
                "B0 policy preflight is not complete for every engine "
                f"({reasons}). This is not a scan result."
            ),
            "engines": statuses,
        }
    return {
        "state": "policy-ready",
        "detail": (
            "B0 image pins and frozen policy digests are present for "
            f"{', '.join(ready)}. Policy-ready is not a clean baseline scan and does not "
            "prove prepared query-pack or offline DB dependency roots."
        ),
        "engines": statuses,
    }


def build_view_state(
    *,
    research: Mapping[str, object],
    cmc_gate: Mapping[str, object],
    image_pins_path: Path | str | None = None,
    policy_root: Path | str | None = None,
) -> dict[str, object]:
    rendered = render_result_state(research)
    enabled = cmc_gate.get("status") == "passed"
    return {
        "research": {
            "state": rendered.kind.value,
            "reason_code": rendered.reason_code,
            "comparative_language": not rendered.suppresses_comparative_language,
            "operator_summary": render_public_summary(research),
            "controls": {
                "B0": _b0_control_from_preflight(
                    image_pins_path=image_pins_path,
                    policy_root=policy_root,
                ),
                "B1": {
                    "state": "not-measured",
                    "detail": "A sealed base/candidate comparison pair is required before deterministic incremental selection.",
                },
                "B2": {
                    "state": "not-measured",
                    "detail": "The frozen stable-order control requires the same admitted sealed evidence.",
                },
                "B3": {
                    "state": "disabled",
                    "detail": "No eligible independent TypeScript corpus with frozen truth and calibration record is admitted.",
                },
            },
            "b3_egress_notice": "selected redacted source is sent to the configured cloud model.",
        },
        "cmc": {
            "enabled": enabled,
            "status": cmc_gate.get("status"),
            "reason": cmc_gate.get("reason"),
            "classification": "case-study-only",
            "detail": (
                "CMC inventory/workflow evidence cannot support recall, precision, false-negative, AI-effect, "
                "or Sentinel capstone claims."
            ),
        },
    }
