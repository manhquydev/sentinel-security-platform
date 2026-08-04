"""Broker-owned private Unix-socket worker transport."""
from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from typing import Callable


class PrivateWorkerViolation(ValueError):
    """Raised when worker transport would be exposed outside the host broker."""


class PrivateWorkerSocket:
    def __init__(
        self,
        path: Path | str,
        handler: Callable[[str], dict[str, object]],
        *,
        authorize: Callable[[str, str], bool],
    ) -> None:
        self.path = Path(path).resolve()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        if self.path.exists():
            raise PrivateWorkerViolation("worker socket path already exists")
        self._handler = handler
        self._authorize = authorize
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.bind(str(self.path))
        os.chmod(self.path, 0o600)
        self._socket.listen(1)

    def serve_once(self) -> None:
        connection, _ = self._socket.accept()
        with connection:
            raw = connection.recv(4096)
            try:
                value = json.loads(raw.decode("utf-8"))
                if (
                    not isinstance(value, dict)
                    or set(value) != {"command_id", "broker_capability"}
                    or not isinstance(value["command_id"], str)
                    or not isinstance(value["broker_capability"], str)
                    or not self._authorize(value["command_id"], value["broker_capability"])
                ):
                    raise PrivateWorkerViolation("private worker accepts only broker-authorized command IDs")
                response = self._handler(value["command_id"])
                connection.sendall(json.dumps(response, sort_keys=True).encode("utf-8"))
            except Exception as error:
                connection.sendall(json.dumps({"status": "rejected", "reason": type(error).__name__}).encode("utf-8"))

    def close(self) -> None:
        self._socket.close()
        self.path.unlink(missing_ok=True)
