from __future__ import annotations

import pytest

from workbench.contracts import ContractViolation
from workbench.host_broker import HostBroker, _SessionState


UI = "http://127.0.0.1:4173"
CONFIG_DIGEST = "a" * 64
PAIR_DIGEST = "b" * 64
CAPABILITY = "capability-once-opaque-32-bytes"


def broker() -> HostBroker:
    return HostBroker(
        ui_origin=UI,
        startup_capability=CAPABILITY,
        config_digest=CONFIG_DIGEST,
        allowed_profiles={"fixture-typescript"},
        allowed_pair_digests={PAIR_DIGEST},
        session_ttl_seconds=300,
    )


def test_bootstrap_is_body_only_one_time_exact_origin_and_issues_host_only_session():
    service = broker()
    session = service.bootstrap(
        origin=UI,
        body={"startup_capability": CAPABILITY},
        request_target="/api/bootstrap",
        request_headers={"content-type": "application/json"},
    )
    assert session.cookie_header.startswith("workbench_session=")
    assert "HttpOnly" in session.cookie_header
    assert "SameSite=Strict" in session.cookie_header
    assert "Path=/api/" in session.cookie_header
    assert session.csrf_token
    with pytest.raises(ContractViolation):
        service.bootstrap(
            origin=UI,
            body={"startup_capability": CAPABILITY},
            request_target="/api/bootstrap",
            request_headers={"content-type": "application/json"},
        )


@pytest.mark.parametrize(
    ("origin", "target", "headers"),
    [
        ("http://evil.example", "/api/bootstrap", {"content-type": "application/json"}),
        (UI, f"/api/bootstrap?startup_capability={CAPABILITY}", {"content-type": "application/json"}),
        (UI, "/api/bootstrap", {"content-type": "application/json", "x-startup-capability": CAPABILITY}),
        (UI, "/api/bootstrap", {"content-type": "application/json", "referer": f"{UI}/#{CAPABILITY}"}),
        ("null", "/api/bootstrap", {"content-type": "application/json"}),
        (f"{UI}, http://evil.example", "/api/bootstrap", {"content-type": "application/json"}),
    ],
)
def test_bootstrap_refuses_capability_leaks_and_wrong_or_duplicate_origins(origin, target, headers):
    with pytest.raises(ContractViolation):
        broker().bootstrap(
            origin=origin,
            body={"startup_capability": CAPABILITY},
            request_target=target,
            request_headers=headers,
        )


def test_credentialed_cors_is_exact_and_never_reflective_or_wildcard():
    service = broker()
    headers = service.cors_headers(UI, method="POST", requested_headers=("content-type", "x-workbench-csrf"))
    assert headers == {
        "Access-Control-Allow-Origin": UI,
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "content-type, x-workbench-csrf",
        "Vary": "Origin",
    }
    for origin in ("*", "null", "http://evil.example", f"{UI}, http://evil.example"):
        with pytest.raises(ContractViolation):
            service.cors_headers(origin, method="POST", requested_headers=("content-type",))
    assert service.cors_headers(UI, method="POST", requested_headers=("content-type",))["Access-Control-Allow-Origin"] == UI
    with pytest.raises(ContractViolation):
        service.cors_headers(UI, method="GET", requested_headers=("content-type",))
    with pytest.raises(ContractViolation):
        service.cors_headers(UI, method="POST", requested_headers=("authorization",))


def test_only_bootstrapped_session_with_csrf_can_submit_allowlisted_typed_worker_command():
    service = broker()
    session = service.bootstrap(
        origin=UI,
        body={"startup_capability": CAPABILITY},
        request_target="/api/bootstrap",
        request_headers={"content-type": "application/json"},
    )
    command = service.submit_command(
        origin=UI,
        session_id=session.session_id,
        csrf_token=session.csrf_token,
        envelope={
            "schema_version": "sentinel-workbench-broker-command/v1",
            "command": "run-fixture-scan",
            "profile": "fixture-typescript",
            "pair_digest": PAIR_DIGEST,
            "config_digest": CONFIG_DIGEST,
        },
    )
    assert command.status == "queued"
    assert command.command_id
    assert service.status(command.command_id).status == "queued"
    assert service.status(command.command_id).to_mapping() == {
        "schema_version": "sentinel-workbench-broker-status/v1",
        "command_id": command.command_id,
        "status": "queued",
    }


@pytest.mark.parametrize(
    ("origin", "session_id", "csrf", "envelope"),
    [
        (UI, "direct-client", "csrf", {"schema_version": "sentinel-workbench-broker-command/v1", "command": "run-fixture-scan", "profile": "fixture-typescript", "pair_digest": PAIR_DIGEST, "config_digest": CONFIG_DIGEST}),
        ("http://evil.example", "missing", "csrf", {"schema_version": "sentinel-workbench-broker-command/v1", "command": "run-fixture-scan", "profile": "fixture-typescript", "pair_digest": PAIR_DIGEST, "config_digest": CONFIG_DIGEST}),
        (UI, "missing", "csrf", {"schema_version": "sentinel-workbench-broker-command/v1", "command": "run-fixture-scan", "profile": "other", "pair_digest": PAIR_DIGEST, "config_digest": CONFIG_DIGEST}),
        (UI, "missing", "csrf", {"schema_version": "sentinel-workbench-broker-command/v1", "command": "run-fixture-scan", "profile": "fixture-typescript", "pair_digest": "c" * 64, "config_digest": CONFIG_DIGEST}),
        (UI, "missing", "csrf", {"schema_version": "sentinel-workbench-broker-command/v1", "command": "run-fixture-scan", "profile": "fixture-typescript", "pair_digest": PAIR_DIGEST, "config_digest": "d" * 64}),
    ],
)
def test_direct_or_mismatched_worker_commands_are_refused(origin, session_id, csrf, envelope):
    with pytest.raises(ContractViolation):
        broker().submit_command(origin=origin, session_id=session_id, csrf_token=csrf, envelope=envelope)


def test_session_fixation_and_csrf_replay_are_refused():
    service = broker()
    session = service.bootstrap(
        origin=UI,
        body={"startup_capability": CAPABILITY},
        request_target="/api/bootstrap",
        request_headers={"content-type": "application/json"},
    )
    with pytest.raises(ContractViolation):
        service.submit_command(
            origin=UI,
            session_id=session.session_id,
            csrf_token="wrong",
            envelope={
                "schema_version": "sentinel-workbench-broker-command/v1",
                "command": "run-fixture-scan",
                "profile": "fixture-typescript",
                "pair_digest": PAIR_DIGEST,
                "config_digest": CONFIG_DIGEST,
            },
        )


@pytest.mark.parametrize("command", ["run-b3-reading", "run-cmc-smoke"])
def test_phase_two_fixture_broker_refuses_non_fixture_worker_commands(command):
    service = broker()
    session = service.bootstrap(
        origin=UI,
        body={"startup_capability": CAPABILITY},
        request_target="/api/bootstrap",
        request_headers={"content-type": "application/json"},
    )

    with pytest.raises(ContractViolation):
        service.submit_command(
            origin=UI,
            session_id=session.session_id,
            csrf_token=session.csrf_token,
            envelope={
                "schema_version": "sentinel-workbench-broker-command/v1",
                "command": command,
                "profile": "fixture-typescript",
                "pair_digest": PAIR_DIGEST,
                "config_digest": CONFIG_DIGEST,
            },
        )


def test_broker_persists_queue_status_and_only_a_worker_claim_can_transition_it(tmp_path):
    state_path = tmp_path / "private" / "broker.sqlite"
    service = HostBroker(
        ui_origin=UI,
        startup_capability=CAPABILITY,
        config_digest=CONFIG_DIGEST,
        allowed_profiles={"fixture-typescript"},
        allowed_pair_digests={PAIR_DIGEST},
        session_ttl_seconds=300,
        state_path=state_path,
    )
    session = service.bootstrap(
        origin=UI,
        body={"startup_capability": CAPABILITY},
        request_target="/api/bootstrap",
        request_headers={"content-type": "application/json"},
    )
    queued = service.submit_command(
        origin=UI,
        session_id=session.session_id,
        csrf_token=session.csrf_token,
        envelope={
            "schema_version": "sentinel-workbench-broker-command/v1",
            "command": "run-fixture-scan",
            "profile": "fixture-typescript",
            "pair_digest": PAIR_DIGEST,
            "config_digest": CONFIG_DIGEST,
        },
    )

    assert state_path.is_file()
    assert state_path.stat().st_mode & 0o077 == 0
    assert service.claim_next_for_worker() == queued.command_id
    assert service.status(queued.command_id).status == "running"
    assert service.finish_worker_command(queued.command_id, succeeded=True).status == "succeeded"

    reloaded = HostBroker(
        ui_origin=UI,
        startup_capability="another-long-opaque-capability",
        config_digest=CONFIG_DIGEST,
        allowed_profiles={"fixture-typescript"},
        allowed_pair_digests={PAIR_DIGEST},
        session_ttl_seconds=300,
        state_path=state_path,
    )
    assert reloaded.status(queued.command_id).status == "succeeded"


def test_phase_three_b3_command_requires_an_explicit_allowed_profile_pair_config_and_selection_frame():
    selection_digest = "c" * 64
    service = HostBroker(
        ui_origin=UI,
        startup_capability=CAPABILITY,
        config_digest=CONFIG_DIGEST,
        allowed_profiles={"research-typescript"},
        allowed_pair_digests={PAIR_DIGEST},
        allowed_commands={"run-b3-reading"},
        allowed_selection_manifest_digests={selection_digest},
        session_ttl_seconds=300,
    )
    session = service.bootstrap(
        origin=UI,
        body={"startup_capability": CAPABILITY},
        request_target="/api/bootstrap",
        request_headers={"content-type": "application/json"},
    )
    envelope = {
        "schema_version": "sentinel-workbench-broker-command/v1",
        "command": "run-b3-reading",
        "profile": "research-typescript",
        "pair_digest": PAIR_DIGEST,
        "config_digest": CONFIG_DIGEST,
        "selection_manifest_digest": selection_digest,
    }
    assert service.submit_command(
        origin=UI,
        session_id=session.session_id,
        csrf_token=session.csrf_token,
        envelope=envelope,
    ).status == "queued"

    with pytest.raises(ContractViolation, match="selection"):
        service.submit_command(
            origin=UI,
            session_id=session.session_id,
            csrf_token=session.csrf_token,
            envelope={**envelope, "selection_manifest_digest": "d" * 64},
        )


def test_duplicate_b3_submit_is_idempotent_and_does_not_enqueue_a_second_provider_call():
    selection_digest = "c" * 64
    service = HostBroker(
        ui_origin=UI,
        startup_capability=CAPABILITY,
        config_digest=CONFIG_DIGEST,
        allowed_profiles={"research-typescript"},
        allowed_pair_digests={PAIR_DIGEST},
        allowed_commands={"run-b3-reading"},
        allowed_selection_manifest_digests={selection_digest},
        session_ttl_seconds=300,
    )
    session = service.bootstrap(
        origin=UI,
        body={"startup_capability": CAPABILITY},
        request_target="/api/bootstrap",
        request_headers={"content-type": "application/json"},
    )
    envelope = {
        "schema_version": "sentinel-workbench-broker-command/v1",
        "command": "run-b3-reading",
        "profile": "research-typescript",
        "pair_digest": PAIR_DIGEST,
        "config_digest": CONFIG_DIGEST,
        "selection_manifest_digest": selection_digest,
    }
    first = service.submit_command(
        origin=UI, session_id=session.session_id, csrf_token=session.csrf_token, envelope=envelope
    )
    second = service.submit_command(
        origin=UI, session_id=session.session_id, csrf_token=session.csrf_token, envelope=envelope
    )
    assert first == second


def test_command_status_is_bound_to_the_session_that_queued_it():
    service = broker()
    session = service.bootstrap(
        origin=UI,
        body={"startup_capability": CAPABILITY},
        request_target="/api/bootstrap",
        request_headers={"content-type": "application/json"},
    )
    queued = service.submit_command(
        origin=UI,
        session_id=session.session_id,
        csrf_token=session.csrf_token,
        envelope={
            "schema_version": "sentinel-workbench-broker-command/v1",
            "command": "run-fixture-scan",
            "profile": "fixture-typescript",
            "pair_digest": PAIR_DIGEST,
            "config_digest": CONFIG_DIGEST,
        },
    )
    assert (
        service.status_for_session(
            origin=UI,
            session_id=session.session_id,
            csrf_token=session.csrf_token,
            command_id=queued.command_id,
        )
        == queued
    )
    service._sessions["different-session"] = _SessionState(session.csrf_token, float("inf"))
    with pytest.raises(ContractViolation, match="owned"):
        service.status_for_session(
            origin=UI,
            session_id="different-session",
            csrf_token=session.csrf_token,
            command_id=queued.command_id,
        )


def test_startup_capability_consumption_survives_a_broker_restart(tmp_path):
    state_path = tmp_path / "private" / "broker.sqlite"
    first = HostBroker(
        ui_origin=UI,
        startup_capability=CAPABILITY,
        config_digest=CONFIG_DIGEST,
        allowed_profiles={"fixture-typescript"},
        allowed_pair_digests={PAIR_DIGEST},
        session_ttl_seconds=300,
        state_path=state_path,
    )
    first.bootstrap(
        origin=UI,
        body={"startup_capability": CAPABILITY},
        request_target="/api/bootstrap",
        request_headers={"content-type": "application/json"},
    )
    restarted = HostBroker(
        ui_origin=UI,
        startup_capability=CAPABILITY,
        config_digest=CONFIG_DIGEST,
        allowed_profiles={"fixture-typescript"},
        allowed_pair_digests={PAIR_DIGEST},
        session_ttl_seconds=300,
        state_path=state_path,
    )
    with pytest.raises(ContractViolation, match="consumed"):
        restarted.bootstrap(
            origin=UI,
            body={"startup_capability": CAPABILITY},
            request_target="/api/bootstrap",
            request_headers={"content-type": "application/json"},
        )


def test_restarted_broker_conservatively_finishes_an_abandoned_running_command(tmp_path):
    state_path = tmp_path / "private" / "broker.sqlite"
    service = HostBroker(
        ui_origin=UI,
        startup_capability=CAPABILITY,
        config_digest=CONFIG_DIGEST,
        allowed_profiles={"fixture-typescript"},
        allowed_pair_digests={PAIR_DIGEST},
        session_ttl_seconds=300,
        state_path=state_path,
    )
    session = service.bootstrap(
        origin=UI,
        body={"startup_capability": CAPABILITY},
        request_target="/api/bootstrap",
        request_headers={"content-type": "application/json"},
    )
    queued = service.submit_command(
        origin=UI,
        session_id=session.session_id,
        csrf_token=session.csrf_token,
        envelope={
            "schema_version": "sentinel-workbench-broker-command/v1",
            "command": "run-fixture-scan",
            "profile": "fixture-typescript",
            "pair_digest": PAIR_DIGEST,
            "config_digest": CONFIG_DIGEST,
        },
    )
    assert service.claim_next_for_worker() == queued.command_id
    restarted = HostBroker(
        ui_origin=UI,
        startup_capability="different-startup-capability",
        config_digest=CONFIG_DIGEST,
        allowed_profiles={"fixture-typescript"},
        allowed_pair_digests={PAIR_DIGEST},
        session_ttl_seconds=300,
        state_path=state_path,
    )
    assert restarted.status(queued.command_id).status == "failed"
