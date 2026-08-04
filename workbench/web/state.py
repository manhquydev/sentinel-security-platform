"""Metadata-only view state for the browser."""
from __future__ import annotations

from typing import Mapping

from ..result_state import render_result_state
from ..reporting import render_public_summary


def build_view_state(*, research: Mapping[str, object], cmc_gate: Mapping[str, object]) -> dict[str, object]:
    rendered = render_result_state(research)
    enabled = cmc_gate.get("status") == "passed"
    return {
        "research": {
            "state": rendered.kind.value,
            "reason_code": rendered.reason_code,
            "comparative_language": not rendered.suppresses_comparative_language,
            "operator_summary": render_public_summary(research),
            "controls": {
                "B0": {
                    "state": "not-ready",
                    "detail": "Scanner policy pins and frozen database/rules snapshots are not approved, so no baseline scan result exists.",
                },
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
