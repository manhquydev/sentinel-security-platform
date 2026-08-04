from __future__ import annotations

import pytest

from workbench.b3_attempt_store import AttemptStoreViolation, B3AttemptStore


DIGEST = "a" * 64


def key() -> dict[str, object]:
    return {
        "run_id": "run-1",
        "arm": "B3",
        "replication": 1,
        "selection_manifest_digest": DIGEST,
        "profile": "fixture-profile",
        "unit_id": "unit-1",
    }


def test_attempt_reservation_is_durable_unique_and_unknown_is_never_retried(tmp_path):
    state_path = tmp_path / "private" / "attempts.sqlite"
    store = B3AttemptStore(state_path)
    attempt = store.reserve(**key())

    assert attempt.status == "reserved"
    assert state_path.stat().st_mode & 0o077 == 0
    with pytest.raises(AttemptStoreViolation, match="duplicate"):
        store.reserve(**key())

    store.mark_dispatched(attempt.attempt_id, profile="fixture-profile")
    store.mark_unknown(attempt.attempt_id, reason="transport-lost")
    assert store.status(attempt.attempt_id).status == "unknown"
    with pytest.raises(AttemptStoreViolation, match="unknown"):
        store.retryable(attempt.attempt_id)


def test_each_unit_in_a_reading_has_its_own_exactly_once_reservation(tmp_path):
    store = B3AttemptStore(tmp_path / "private" / "attempts.sqlite")

    first = store.reserve(**key())
    second = store.reserve(**{**key(), "unit_id": "unit-2"})

    assert first.unit_id == "unit-1"
    assert second.unit_id == "unit-2"


def test_dispatch_rechecks_revocation_and_terminal_transition_is_exactly_once(tmp_path):
    store = B3AttemptStore(tmp_path / "private" / "attempts.sqlite")
    attempt = store.reserve(**key())

    store.revoke_profile("fixture-profile")
    with pytest.raises(AttemptStoreViolation, match="revoked"):
        store.mark_dispatched(attempt.attempt_id, profile="fixture-profile")
    assert store.status(attempt.attempt_id).status == "reserved"

    store = B3AttemptStore(tmp_path / "other" / "attempts.sqlite")
    attempt = store.reserve(**key())
    store.mark_dispatched(attempt.attempt_id, profile="fixture-profile")
    assert store.mark_terminal(attempt.attempt_id, status="succeeded").status == "succeeded"
    with pytest.raises(AttemptStoreViolation):
        store.mark_terminal(attempt.attempt_id, status="failed")


def test_reopen_recovers_dispatched_attempt_to_unknown_and_profile_is_bound_at_reservation(tmp_path):
    state_path = tmp_path / "private" / "attempts.sqlite"
    store = B3AttemptStore(state_path)
    attempt = store.reserve(**key())
    with pytest.raises(AttemptStoreViolation, match="profile"):
        store.mark_dispatched(attempt.attempt_id, profile="other-profile")
    store.mark_dispatched(attempt.attempt_id, profile="fixture-profile")

    restarted = B3AttemptStore(state_path)
    assert restarted.status(attempt.attempt_id).status == "unknown"
    with pytest.raises(AttemptStoreViolation, match="unknown"):
        restarted.retryable(attempt.attempt_id)
