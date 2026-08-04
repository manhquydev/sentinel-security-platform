from __future__ import annotations

import inspect

import pytest

from workbench.b3_dispatcher import B3Dispatcher, B3DispatcherViolation
from workbench.b3_attempt_store import B3AttemptStore
from workbench.egress import B3Route


def route(tmp_path):
    key = tmp_path / "b3.env"
    key.write_text("vk-restricted-only\n", encoding="utf-8")
    key.chmod(0o600)
    return B3Route.from_host_config(
        route_id="workbench-b3-no-trace",
        key_path=key,
        config_digest="a" * 64,
        expected_config_digest="a" * 64,
    )


def selection_stub():
    # The real sealed selection factory is exercised in Phase 3 tests. This
    # test only verifies the dispatcher gate with an authorized test object.
    from workbench.analysis_population import SelectionManifest
    from types import MappingProxyType
    from workbench.analysis_population import _SELECTION_AUTHORITY

    return SelectionManifest(
        MappingProxyType({"schema_version": "test", "unit_ids": ["unit-1"]}),
        MappingProxyType({"unit-1": ("const x = true;\n", "")}),
        _SELECTION_AUTHORITY,
    )


def test_dispatch_checks_route_health_and_fixed_parameters_before_and_after_attempt_state(tmp_path):
    dispatcher = B3Dispatcher.for_fixture(
        route=route(tmp_path),
        attempt_store=B3AttemptStore(tmp_path / "attempts.sqlite"),
        healthcheck=lambda _route: True,
        config_digest="a" * 64,
        responses=[{"proposal_ids": ["unit-1"]}],
    )
    receipt = dispatcher.dispatch(run_id="run-1", selection=selection_stub(), reading=1, unit_id="unit-1")
    assert receipt.status == "succeeded"
    assert receipt.proposal_ids == ("unit-1",)
    assert dispatcher.fixture_calls == 1
    assert "vk-restricted-only" not in repr(dispatcher)


def test_dispatch_fails_closed_on_route_health_or_raw_response(tmp_path):
    selection = selection_stub()
    dispatcher = B3Dispatcher.for_fixture(
        route=route(tmp_path),
        attempt_store=B3AttemptStore(tmp_path / "attempts.sqlite"),
        healthcheck=lambda _route: False,
        config_digest="a" * 64,
        responses=[{"proposal_ids": ["WORKBENCH_RAW_SOURCE_CANARY"]}],
    )
    with pytest.raises(B3DispatcherViolation, match="health"):
        dispatcher.dispatch(run_id="run-1", selection=selection, reading=1, unit_id="unit-1")


def test_live_b3_factory_has_no_caller_client_injection_or_serializable_virtual_key(tmp_path):
    key_path = tmp_path / "host-only-b3.key"
    key_path.write_text("vk-restricted-only\n", encoding="utf-8")
    key_path.chmod(0o600)

    assert "client" not in inspect.signature(B3Dispatcher.__init__).parameters
    dispatcher = B3Dispatcher.from_host_config(
        route_id="workbench-b3-no-trace",
        key_path=key_path,
        attempt_store=B3AttemptStore(tmp_path / "attempts.sqlite"),
        healthcheck=lambda _route: True,
        config_digest="a" * 64,
        expected_config_digest="a" * 64,
    )

    assert "vk-restricted-only" not in repr(dispatcher)
    with pytest.raises(B3DispatcherViolation, match="unknown"):
        dispatcher.dispatch(run_id="run-1", selection=selection_stub(), reading=1, unit_id="unit-1")
