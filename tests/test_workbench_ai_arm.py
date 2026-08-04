from __future__ import annotations

from types import MappingProxyType

import pytest

from workbench.ai_arm import AIArmViolation, run_b3_consensus
from workbench.analysis_population import SelectionManifest, _SELECTION_AUTHORITY
from workbench.b3_dispatcher import B3DispatchReceipt, B3Dispatcher


def selection():
    ids = [f"unit-{index:02}" for index in range(12)]
    return SelectionManifest(
        MappingProxyType({"schema_version": "test", "unit_ids": ids}),
        MappingProxyType({unit: ("export const x = true;\n", "") for unit in ids}),
        _SELECTION_AUTHORITY,
    )


def test_b3_consensus_requires_three_complete_readings_and_keeps_b0_state_untouched():
    one_reading = [{"proposal_ids": [f"unit-{index:02}"]} for index in range(12)]
    responses = one_reading * 3
    dispatcher = B3Dispatcher.for_fixture(responses)
    result = run_b3_consensus(
        run_id="run-1",
        selection=selection(),
        dispatcher=dispatcher,
        config_digest="a" * 64,
    )
    assert dispatcher.fixture_calls == 36
    assert result.consensus_unit_ids == tuple(f"unit-{index:02}" for index in range(12))
    assert result.readings == 3


def test_short_consensus_is_instrument_invalid_not_a_cheaper_arm():
    dispatcher = B3Dispatcher.for_fixture([{"proposal_ids": []}] * 36)
    with pytest.raises(AIArmViolation, match="short"):
        run_b3_consensus(
            run_id="run-1",
            selection=selection(),
            dispatcher=dispatcher,
            config_digest="a" * 64,
        )


def test_b3_consensus_rejects_a_duck_typed_dispatcher_before_it_can_issue_any_call():
    class SubstitutedDispatcher:
        def __init__(self):
            self.calls = 0

        def dispatch(self, **_kwargs):
            self.calls += 1
            raise AssertionError("a substituted dispatcher must never be called")

    dispatcher = SubstitutedDispatcher()
    with pytest.raises(AIArmViolation, match="host dispatcher"):
        run_b3_consensus(
            run_id="run-1",
            selection=selection(),
            dispatcher=dispatcher,
            config_digest="a" * 64,
        )
    assert dispatcher.calls == 0
