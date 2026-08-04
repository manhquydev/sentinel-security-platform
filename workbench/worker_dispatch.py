"""Host-side bridge from the durable broker queue to an owner-only worker socket."""
from __future__ import annotations

import json
import os
import socket
import stat
from pathlib import Path

from .host_broker import BrokerStatus, HostBroker


class WorkerDispatchViolation(ValueError):
    """Raised when the host-to-worker private transport cannot be trusted."""


class BrokerWorkerDispatcher:
    """The broker claims work; this bridge sends only its opaque command ID."""

    def __init__(self, broker: HostBroker, worker_socket: Path | str) -> None:
        if not isinstance(broker, HostBroker):
            raise WorkerDispatchViolation("worker bridge requires a host broker")
        self._broker = broker
        self._worker_socket = Path(worker_socket).resolve()

    def dispatch_next(self) -> BrokerStatus | None:
        claim = self._broker.claim_next_for_worker_authorized()
        if claim is None:
            return None
        try:
            response = self._send(claim.command_id, claim.capability)
            if response != {"command_id": claim.command_id, "status": "succeeded"}:
                raise WorkerDispatchViolation("private worker returned an invalid metadata-only response")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, WorkerDispatchViolation):
            return self._broker.finish_worker_command(claim.command_id, succeeded=False)
        return self._broker.finish_worker_command(claim.command_id, succeeded=True)

    def _send(self, command_id: str, capability: str) -> dict[str, object]:
        self._assert_private_socket()
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.settimeout(5)
            client.connect(str(self._worker_socket))
            client.sendall(
                json.dumps(
                    {"command_id": command_id, "broker_capability": capability},
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            raw = client.recv(4096)
        finally:
            client.close()
        if not raw:
            raise WorkerDispatchViolation("private worker returned no response")
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise WorkerDispatchViolation("private worker response must be an object")
        return value

    def _assert_private_socket(self) -> None:
        try:
            parent = self._worker_socket.parent.lstat()
            details = self._worker_socket.lstat()
        except OSError as error:
            raise WorkerDispatchViolation("private worker socket is unavailable") from error
        if (
            stat.S_ISLNK(parent.st_mode)
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_mode & 0o077
            or stat.S_ISLNK(details.st_mode)
            or not stat.S_ISSOCK(details.st_mode)
            or details.st_mode & 0o077
            or details.st_uid != os.geteuid()
        ):
            raise WorkerDispatchViolation("worker endpoint is not an owner-only private Unix socket")
