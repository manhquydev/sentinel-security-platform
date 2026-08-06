"""Metadata-only view state for the browser."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping

from ..prepared_deps import b0_readiness
from ..result_state import render_result_state
from ..reporting import render_public_summary


def _b0_control(
    *,
    image_pins_path: Path | str | None = None,
    policy_root: Path | str | None = None,
    prepared_root: Path | str | None = None,
) -> dict[str, object]:
    """Dual B0 card: policy freeze vs prepared source-less deps (never a clean scan)."""
    pins = Path(image_pins_path) if image_pins_path is not None else Path("scanners/image-pins.env")
    policy = Path(policy_root) if policy_root is not None else Path("scanners/workbench-b0")
    prepared = prepared_root
    if prepared is None:
        prepared = os.environ.get(
            "WORKBENCH_PREPARED_DEPS_ROOT",
            str(Path.home() / ".cache" / "sentinel-workbench" / "prepared-deps"),
        )
    readiness = b0_readiness(
        image_pins_path=pins,
        policy_root=policy,
        prepared_root=prepared,
    )
    overall = str(readiness["overall"])
    if overall == "prepared-deps-ready":
        detail = (
            "B0 policy pins/digests are ready and host-private prepared dependency roots "
            "are present (query-pack/ruleset/offline DB layout). This is still not a clean "
            "baseline scan result and not corpus admission."
        )
    elif overall == "policy-ready":
        detail = (
            "B0 image pins and frozen policy digests are present, but prepared dependency "
            "roots are incomplete. Policy-ready is not a clean scan; prepare deps before "
            "source-mounted B0 runs."
        )
    else:
        detail = (
            "B0 policy preflight is incomplete for one or more engines. "
            "This is not a scan result."
        )
    return {
        "state": overall,
        "detail": detail,
        "policy": readiness["policy"],
        "prepared_deps": readiness["prepared_deps"],
        "prepared_root": readiness["prepared_root"],
        "notes": readiness["notes"],
    }


def build_view_state(
    *,
    research: Mapping[str, object],
    cmc_gate: Mapping[str, object],
    image_pins_path: Path | str | None = None,
    policy_root: Path | str | None = None,
    prepared_root: Path | str | None = None,
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
                "B0": _b0_control(
                    image_pins_path=image_pins_path,
                    policy_root=policy_root,
                    prepared_root=prepared_root,
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
