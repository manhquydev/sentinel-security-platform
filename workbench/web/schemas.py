"""Small typed browser payload validators."""
from __future__ import annotations

from ..contracts import ContractViolation


def validate_launch_payload(payload: object) -> dict[str, str]:
    if not isinstance(payload, dict) or set(payload) != {"profile_id", "comparison_id", "mode"}:
        raise ContractViolation("launch payload must contain only immutable IDs and mode")
    if (
        not all(isinstance(payload[key], str) and payload[key] for key in payload)
        or payload["mode"] not in {"fixture", "research"}
        or "/" in payload["profile_id"]
        or "/" in payload["comparison_id"]
    ):
        raise ContractViolation("launch payload contains an invalid ID or mode")
    return payload
