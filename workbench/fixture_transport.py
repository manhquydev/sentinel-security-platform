"""Safe metadata-only fixture transport contract used by the local browser demo."""
from __future__ import annotations

import hashlib

from .broker_protocol import BrokerCommand, COMMAND_SCHEMA_VERSION


PROFILE_ID = "fixture-transport-only"
CONFIG_DIGEST = hashlib.sha256(b"fixture-transport-contract-v1").hexdigest()
PAIR_DIGEST = hashlib.sha256(b"fixture-transport-pair-v1").hexdigest()


def command_envelope() -> dict[str, str]:
    return {
        "schema_version": COMMAND_SCHEMA_VERSION,
        "command": "run-fixture-scan",
        "profile": PROFILE_ID,
        "pair_digest": PAIR_DIGEST,
        "config_digest": CONFIG_DIGEST,
    }


def is_fixture_transport_command(command: BrokerCommand) -> bool:
    return (
        command.command == "run-fixture-scan"
        and command.profile == PROFILE_ID
        and command.pair_digest == PAIR_DIGEST
        and command.config_digest == CONFIG_DIGEST
        and command.selection_manifest_digest is None
    )
