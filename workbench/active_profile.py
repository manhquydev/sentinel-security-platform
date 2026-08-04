"""Fail-closed CMC smoke-profile catalog admission."""
from __future__ import annotations

from typing import Mapping

from .value_gate import CmcValueGate


class ActiveProfileViolation(ValueError):
    """Raised when CMC transport is not explicitly eligible and contracted."""


def materialize_active_catalog(gate: object, contract: Mapping[str, object]) -> dict[str, object]:
    if getattr(gate, "status", None) != CmcValueGate.PASSED and getattr(gate, "status", None) != "passed":
        raise ActiveProfileViolation("CMC value gate has not passed; no catalog may be materialized")
    required = {
        "schema_version",
        "startup_command",
        "origin",
        "method",
        "content_type",
        "synthetic_data",
        "non_mutating",
        "runtime_identity",
    }
    if (
        set(contract) != required
        or contract["schema_version"] != "sentinel-workbench-cmc-contract/v1"
        or contract["origin"] is None
        or not isinstance(contract["origin"], str)
        or not contract["origin"].startswith("http://127.0.0.1:")
        or contract["method"] != "GET"
        or contract["content_type"] != "application/json"
        or contract["synthetic_data"] is not True
        or contract["non_mutating"] is not True
    ):
        raise ActiveProfileViolation("CMC startup/endpoint contract is not an exact local synthetic non-mutating profile")
    return {
        "schema_version": "sentinel-workbench-active-catalog/v1",
        "origin": contract["origin"],
        "method": contract["method"],
        "request_path": "/",
        "runtime_identity": contract["runtime_identity"],
    }
