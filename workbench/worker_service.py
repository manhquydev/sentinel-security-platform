"""Lifecycle process for the deliberately source-less fixture transport worker."""
from __future__ import annotations

import os
import signal
import sys
import threading

from .fixture_transport import is_fixture_transport_command
from .host_broker import broker_from_environment
from .worker_supervisor import HostWorkerSupervisor


def _main(argv: list[str]) -> int:
    if argv != ["--serve"]:
        print("usage: python -m workbench.worker_service --serve", file=sys.stderr)
        return 2
    try:
        broker = broker_from_environment(recover_running_commands=False)
        socket_path = os.environ["WORKBENCH_PRIVATE_WORKER_SOCKET"]
        supervisor = HostWorkerSupervisor(
            broker=broker,
            socket_path=socket_path,
            execute=lambda command: False if is_fixture_transport_command(command) else False,
        )
    except (KeyError, ValueError) as error:
        print(f"workbench worker refused configuration: {type(error).__name__}", file=sys.stderr)
        return 2
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    supervisor.start()
    try:
        stopped.wait()
    finally:
        supervisor.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
