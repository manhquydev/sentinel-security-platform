"""Host-owned lifecycle for private Workbench workers.

The supervisor is deliberately incapable of receiving browser requests.  It
only drains typed broker queue entries through the authenticated private socket.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Callable

from .broker_protocol import BrokerCommand
from .host_broker import HostBroker
from .private_worker import PrivateWorkerSocket
from .worker_dispatch import BrokerWorkerDispatcher


class WorkerSupervisorViolation(ValueError):
    """Raised when a host worker lifecycle would be incomplete or untrusted."""


class HostWorkerSupervisor:
    def __init__(
        self,
        *,
        broker: HostBroker,
        socket_path: Path | str,
        execute: Callable[[BrokerCommand], bool],
        poll_seconds: float = 0.05,
    ) -> None:
        if not isinstance(broker, HostBroker) or not callable(execute) or poll_seconds <= 0:
            raise WorkerSupervisorViolation("host worker supervisor requires a broker, executor, and positive poll interval")
        self._broker = broker
        self._execute = execute
        self._poll_seconds = poll_seconds
        self._stop = threading.Event()
        self._worker = PrivateWorkerSocket(
            socket_path,
            self._handle,
            authorize=broker.authorize_worker_claim,
        )
        self._dispatcher = BrokerWorkerDispatcher(broker, self._worker.path)
        self._accept_thread: threading.Thread | None = None
        self._dispatch_thread: threading.Thread | None = None

    @property
    def socket_path(self) -> Path:
        return self._worker.path

    def start(self) -> None:
        if self._accept_thread is not None:
            raise WorkerSupervisorViolation("host worker supervisor is already running")
        self._accept_thread = threading.Thread(target=self._accept_loop, name="workbench-private-worker", daemon=True)
        self._dispatch_thread = threading.Thread(target=self._dispatch_loop, name="workbench-broker-dispatch", daemon=True)
        self._accept_thread.start()
        self._dispatch_thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._worker.close()
        if self._dispatch_thread is not None:
            self._dispatch_thread.join(timeout=2)
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2)
        self._accept_thread = None
        self._dispatch_thread = None

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._worker.serve_once()
            except OSError:
                if not self._stop.is_set():
                    raise

    def _dispatch_loop(self) -> None:
        while not self._stop.is_set():
            result = self._dispatcher.dispatch_next()
            if result is None:
                self._stop.wait(self._poll_seconds)

    def _handle(self, command_id: str) -> dict[str, object]:
        command = self._broker.command_for_worker(command_id)
        succeeded = bool(self._execute(command))
        return {
            "command_id": command_id,
            "status": "succeeded" if succeeded else "failed",
        }
