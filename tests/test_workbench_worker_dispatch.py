from __future__ import annotations

import json
import socket
import threading

from workbench.host_broker import HostBroker
from workbench.private_worker import PrivateWorkerSocket
from workbench.worker_dispatch import BrokerWorkerDispatcher


UI = "http://127.0.0.1:4173"
CONFIG_DIGEST = "a" * 64
PAIR_DIGEST = "b" * 64
CAPABILITY = "capability-once-opaque-32-bytes"


def test_only_a_claimed_broker_command_reaches_the_owner_only_worker_then_transitions_once(tmp_path):
    broker = HostBroker(
        ui_origin=UI,
        startup_capability=CAPABILITY,
        config_digest=CONFIG_DIGEST,
        allowed_profiles={"fixture-typescript"},
        allowed_pair_digests={PAIR_DIGEST},
        session_ttl_seconds=300,
        state_path=tmp_path / "private" / "broker.sqlite",
    )
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
    received: list[str] = []

    def worker_handler(command_id: str) -> dict[str, object]:
        command = broker.command_for_worker(command_id)
        received.append(command.command)
        return {"command_id": command_id, "status": "succeeded"}

    worker = PrivateWorkerSocket(
        tmp_path / "private" / "worker.sock",
        worker_handler,
        authorize=broker.authorize_worker_claim,
    )
    thread = threading.Thread(target=worker.serve_once)
    thread.start()
    try:
        result = BrokerWorkerDispatcher(broker, worker.path).dispatch_next()
    finally:
        thread.join(timeout=2)
        worker.close()

    assert received == ["run-fixture-scan"]
    assert result is not None
    assert result.command_id == queued.command_id
    assert result.status == "succeeded"
    assert broker.status(queued.command_id).status == "succeeded"


def test_direct_socket_client_with_a_known_running_command_id_cannot_invoke_the_worker(tmp_path):
    broker = HostBroker(
        ui_origin=UI,
        startup_capability=CAPABILITY,
        config_digest=CONFIG_DIGEST,
        allowed_profiles={"fixture-typescript"},
        allowed_pair_digests={PAIR_DIGEST},
        session_ttl_seconds=300,
    )
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
    claim = broker.claim_next_for_worker_authorized()
    assert claim is not None and claim.command_id == queued.command_id
    calls: list[str] = []
    worker = PrivateWorkerSocket(
        tmp_path / "private" / "worker.sock",
        lambda command_id: calls.append(command_id) or {"command_id": command_id, "status": "succeeded"},
        authorize=broker.authorize_worker_claim,
    )
    thread = threading.Thread(target=worker.serve_once)
    thread.start()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(str(worker.path))
        client.sendall(json.dumps({"command_id": queued.command_id, "broker_capability": "forged"}).encode("utf-8"))
        assert json.loads(client.recv(1024))["status"] == "rejected"
    finally:
        client.close()
        thread.join(timeout=2)
        worker.close()
    assert calls == []
