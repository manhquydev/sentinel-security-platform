from __future__ import annotations

import json
import socket
import threading

from workbench.private_worker import PrivateWorkerSocket


def test_private_worker_socket_is_owner_only_and_accepts_only_broker_command_id(tmp_path):
    calls: list[str] = []
    worker = PrivateWorkerSocket(
        tmp_path / "private" / "worker.sock",
        lambda command_id: calls.append(command_id) or {"status": "ok", "command_id": command_id},
        authorize=lambda command_id, capability: command_id == "broker-command" and capability == "broker-only-capability",
    )
    assert worker.path.stat().st_mode & 0o077 == 0
    thread = threading.Thread(target=worker.serve_once)
    thread.start()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(str(worker.path))
    client.sendall(json.dumps({"command_id": "broker-command"}).encode())
    assert json.loads(client.recv(1024))["status"] == "rejected"
    client.close()
    thread.join(timeout=2)

    thread = threading.Thread(target=worker.serve_once)
    thread.start()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(str(worker.path))
    client.sendall(json.dumps({"command_id": "broker-command", "broker_capability": "broker-only-capability"}).encode())
    assert json.loads(client.recv(1024))["status"] == "ok"
    client.close()
    thread.join(timeout=2)
    assert calls == ["broker-command"]
    worker.close()
