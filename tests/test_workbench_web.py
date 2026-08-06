from __future__ import annotations

import pytest

from workbench.contracts import ContractViolation
from workbench.result_state import ResultState
from workbench.web.api import ProfileRegistry, WorkbenchAPI


def test_web_api_accepts_only_immutable_profile_and_comparison_ids_and_separates_cmc_gate():
    registry = ProfileRegistry(
        profiles={
            "fixture-profile": {
                "profile_id": "fixture-profile",
                "comparison_id": "b" * 64,
                "config_digest": "a" * 64,
            }
        }
    )
    api = WorkbenchAPI(registry=registry, cmc_gate={"status": "not-run", "reason": "no-timed-census-record"})
    view = api.view()
    assert view["cmc"]["enabled"] is False
    assert view["research"]["state"] == ResultState.NOT_MEASURED.value
    with pytest.raises(ContractViolation):
        api.launch({"profile_id": "../etc", "comparison_id": "b" * 64, "mode": "fixture"})


def test_web_view_exposes_only_the_configured_loopback_broker_origin_not_a_worker_endpoint():
    api = WorkbenchAPI(
        registry=ProfileRegistry(profiles={}),
        cmc_gate={"status": "not-run", "reason": "no-timed-census-record"},
        broker_origin="http://127.0.0.1:4174",
    )

    view = api.view()
    assert view["broker"] == {"origin": "http://127.0.0.1:4174"}
    assert view["fixture_transport"]["enabled"] is True
    assert "containment" in view["fixture_transport"]["detail"].lower()
    assert "not ready" not in view["fixture_transport"]["detail"].lower()
    assert set(view["fixture_transport"]["command"]) == {
        "schema_version",
        "command",
        "profile",
        "pair_digest",
        "config_digest",
    }


def test_browser_view_makes_the_current_non_comparative_evidence_and_cmc_boundary_plain():
    view = WorkbenchAPI(
        registry=ProfileRegistry(profiles={}),
        cmc_gate={"status": "not-run", "reason": "no-timed-census-record"},
    ).view()

    assert view["research"]["operator_summary"].endswith("no effectiveness claim is rendered.")
    # B0 card follows preflight policy readiness (ready ≠ clean scan).
    assert view["research"]["controls"]["B0"]["state"] in {"policy-ready", "not-ready"}
    assert "engines" in view["research"]["controls"]["B0"]
    assert view["research"]["controls"]["B3"]["state"] == "disabled"
    assert view["research"]["b3_egress_notice"] == "selected redacted source is sent to the configured cloud model."
    assert view["cmc"]["classification"] == "case-study-only"
    assert view["cmc"]["enabled"] is False
