#!/usr/bin/env python3
"""Run a charter adapter with bounded, memory-only stdout/stderr pipes."""
from __future__ import annotations

import argparse
import os
import selectors
import signal
import subprocess
import sys


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--stdout-limit", type=int, required=True)
    parser.add_argument("--stderr-limit", type=int, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    if (options.stdout_limit < 1 or options.stderr_limit < 1 or not options.command
            or options.command[0] != "--" or len(options.command) == 1):
        return 64

    process = subprocess.Popen(options.command[1:], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    stdout = bytearray()
    seen = {"stdout": 0, "stderr": 0}
    limits = {"stdout": options.stdout_limit, "stderr": options.stderr_limit}
    overflow = False
    while selector.get_map():
        for key, _ in selector.select():
            chunk = os.read(key.fileobj.fileno(), 8192)
            if not chunk:
                selector.unregister(key.fileobj)
                continue
            stream = key.data
            seen[stream] += len(chunk)
            if seen[stream] > limits[stream]:
                overflow = True
                _terminate(process)
                break
            if stream == "stdout":
                stdout.extend(chunk)
        if overflow:
            break
    selector.close()
    if overflow:
        return 75
    if process.wait() != 0:
        return 1
    # The caller retains this bounded value in memory and strict-decodes it. No
    # stderr, failure output, or overflow data crosses the process boundary.
    sys.stdout.buffer.write(stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
