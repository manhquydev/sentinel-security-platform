#!/usr/bin/env python3
"""Synchronize the executor's dedicated Kong API key into two private env files."""
from __future__ import annotations

import argparse
import os
import secrets
import stat
import tempfile
from pathlib import Path


KEY = "SENTINEL_CHARTER_EXECUTOR_API_KEY"


class ProvisionError(RuntimeError):
    pass


def _private_regular(path: Path) -> None:
    item = os.lstat(path)
    if (
        stat.S_ISLNK(item.st_mode)
        or not stat.S_ISREG(item.st_mode)
        or item.st_uid != os.geteuid()
        or stat.S_IMODE(item.st_mode) != 0o600
    ):
        raise ProvisionError("private environment file is unsafe")


def _lines(path: Path) -> list[str]:
    _private_regular(path)
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ProvisionError("private environment file is unreadable") from exc


def _existing(lines: list[str]) -> str | None:
    matches = [line[len(KEY) + 1:] for line in lines if line.startswith(KEY + "=")]
    if len(matches) > 1:
        raise ProvisionError("API key appears more than once")
    if matches and not matches[0]:
        return None
    return matches[0] if matches else None


def _publish(path: Path, lines: list[str], value: str) -> None:
    replacement = f"{KEY}={value}"
    replaced = False
    output: list[str] = []
    for line in lines:
        if line.startswith(KEY + "="):
            output.append(replacement)
            replaced = True
        else:
            output.append(line)
    if not replaced:
        output.append(replacement)
    descriptor, temporary = tempfile.mkstemp(prefix=".sentinel-api-key.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write("\n".join(output) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise ProvisionError("API key could not be published") from exc


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kong-env", default=root / "infra/.env", type=Path)
    parser.add_argument("--executor-env", default=Path.home() / ".sentinel/executor-secret.env", type=Path)
    args = parser.parse_args(argv)
    try:
        kong_lines = _lines(args.kong_env)
        executor_lines = _lines(args.executor_env)
        kong_key, executor_key = _existing(kong_lines), _existing(executor_lines)
        if kong_key and executor_key and kong_key != executor_key:
            raise ProvisionError("existing API-key values do not match")
        value = kong_key or executor_key or secrets.token_urlsafe(32)
        if not value or "\n" in value or "\r" in value:
            raise ProvisionError("generated API key is invalid")
        changed = kong_key != value or executor_key != value
        if changed:
            _publish(args.kong_env, kong_lines, value)
            _publish(args.executor_env, executor_lines, value)
        print("API key provisioned" if changed else "API key already synchronized")
        return 0
    except (OSError, ProvisionError):
        print("API key provisioning refused", file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
