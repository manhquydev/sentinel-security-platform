"""Typed host-broker messages. Browser processes never access workers directly."""
from __future__ import annotations

from dataclasses import dataclass

from .contracts import ContractViolation, _digest


COMMAND_SCHEMA_VERSION = "sentinel-workbench-broker-command/v1"
_ALLOWED_COMMANDS = {"run-fixture-scan", "run-b3-reading"}


@dataclass(frozen=True)
class BrokerCommand:
    command: str
    profile: str
    pair_digest: str
    config_digest: str
    selection_manifest_digest: str | None = None

    @classmethod
    def from_mapping(cls, envelope: object) -> "BrokerCommand":
        if not isinstance(envelope, dict):
            raise ContractViolation("broker command must use the exact typed envelope")
        command = envelope.get("command")
        expected = {
            "schema_version",
            "command",
            "profile",
            "pair_digest",
            "config_digest",
        }
        if command == "run-b3-reading":
            expected.add("selection_manifest_digest")
        if set(envelope) != expected:
            raise ContractViolation("broker command must use the exact typed envelope")
        if envelope["schema_version"] != COMMAND_SCHEMA_VERSION:
            raise ContractViolation("unsupported broker command schema")
        profile = envelope["profile"]
        if command not in _ALLOWED_COMMANDS or not isinstance(profile, str) or not profile:
            raise ContractViolation("broker command or profile is not allowlisted")
        selection = (
            _digest(envelope["selection_manifest_digest"], "selection_manifest_digest")
            if command == "run-b3-reading"
            else None
        )
        return cls(
            command,
            profile,
            _digest(envelope["pair_digest"], "pair_digest"),
            _digest(envelope["config_digest"], "config_digest"),
            selection,
        )
