from __future__ import annotations

import pytest

from workbench.active_profile import ActiveProfileViolation, materialize_active_catalog
from workbench.value_gate import not_run_cmc_value_gate


def contract():
    return {
        "schema_version": "sentinel-workbench-cmc-contract/v1",
        "startup_command": "docker compose up cmc-local",
        "origin": "http://127.0.0.1:8088",
        "method": "GET",
        "content_type": "application/json",
        "synthetic_data": True,
        "non_mutating": True,
        "runtime_identity": "cmc-local-fixture",
    }


def test_cmc_catalog_is_not_materialized_without_passed_value_gate():
    with pytest.raises(ActiveProfileViolation, match="value gate"):
        materialize_active_catalog(not_run_cmc_value_gate("no-census"), contract())


def test_cmc_contract_requires_exact_loopback_synthetic_non_mutating_endpoint():
    gate = type("Gate", (), {"status": "passed"})()
    broken = contract()
    broken["origin"] = "http://cmc.local:8088"
    with pytest.raises(ActiveProfileViolation):
        materialize_active_catalog(gate, broken)
