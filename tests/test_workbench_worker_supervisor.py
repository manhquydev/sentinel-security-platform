from __future__ import annotations

import time

from workbench.host_broker import HostBroker
from workbench.worker_supervisor import HostWorkerSupervisor


UI = "http://127.0.0.1:4173"
CONFIG_DIGEST = "a" * 64
PAIR_DIGEST = "b" * 64
CAPABILITY = "capability-once-opaque-32-bytes"


def test_host_worker_supervisor_drives_a_durable_broker_command_to_a_terminal_refusal_without_scanning(tmp_path):
    broker = HostBroker(
        ui_origin=UI,
        startup_capability=CAPABILITY,
        config_digest=CONFIG_DIGEST,
        allowed_profiles={"fixture-typescript"},
        allowed_pair_digests={PAIR_DIGEST},
        session_ttl_seconds=300,
        state_path=tmp_path / "private" / "broker.sqlite",
    )
    supervisor = HostWorkerSupervisor(
        broker=broker,
        socket_path=tmp_path / "private" / "worker.sock",
        execute=lambda _command: False,
        poll_seconds=0.01,
    )
    supervisor.start()
    try:
        session = broker.bootstrap(
            origin=UI,
            body={"startup_capability": CAPABILITY},
            request_target="/api/bootstrap",
            request_headers={"content-type": "application/json"},
        )
        queued = broker.submit_command(
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
        deadline = time.monotonic() + 2
        while broker.status(queued.command_id).status not in {"succeeded", "failed"} and time.monotonic() < deadline:
            time.sleep(0.01)
        assert broker.status(queued.command_id).status == "failed"
    finally:
        supervisor.stop()


def test_separate_broker_and_worker_process_models_share_the_durable_queue_safely(tmp_path):
    state_path = tmp_path / "private" / "broker.sqlite"
    browser_broker = HostBroker(
        ui_origin=UI,
        startup_capability=CAPABILITY,
        config_digest=CONFIG_DIGEST,
        allowed_profiles={"fixture-typescript"},
        allowed_pair_digests={PAIR_DIGEST},
        session_ttl_seconds=300,
        state_path=state_path,
    )
    worker_broker = HostBroker(
        ui_origin=UI,
        startup_capability=CAPABILITY,
        config_digest=CONFIG_DIGEST,
        allowed_profiles={"fixture-typescript"},
        allowed_pair_digests={PAIR_DIGEST},
        session_ttl_seconds=300,
        state_path=state_path,
        recover_running_commands=False,
    )
    supervisor = HostWorkerSupervisor(
        broker=worker_broker,
        socket_path=tmp_path / "private" / "worker.sock",
        execute=lambda _command: False,
        poll_seconds=0.01,
    )
    supervisor.start()
    try:
        session = browser_broker.bootstrap(
            origin=UI,
            body={"startup_capability": CAPABILITY},
            request_target="/api/bootstrap",
            request_headers={"content-type": "application/json"},
        )
        queued = browser_broker.submit_command(
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
        deadline = time.monotonic() + 2
        while browser_broker.status(queued.command_id).status not in {"succeeded", "failed"} and time.monotonic() < deadline:
            time.sleep(0.01)
        assert browser_broker.status(queued.command_id).status == "failed"
    finally:
        supervisor.stop()
