"""Host-owned broker authorization model for local Workbench workers."""
from __future__ import annotations

import secrets
import time
import json
import sys
import os
import sqlite3
import hashlib
import functools
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from .broker_protocol import BrokerCommand
from .contracts import ContractViolation, _digest


_ALLOWED_CORS_HEADERS = {
    ("content-type",),
    ("content-type", "x-workbench-csrf"),
}
_ALLOWED_CORS_METHOD = "POST"


@dataclass(frozen=True)
class BrokerSession:
    session_id: str
    csrf_token: str
    cookie_header: str


@dataclass(frozen=True)
class BrokerStatus:
    command_id: str
    status: str

    def to_mapping(self) -> dict[str, str]:
        """Expose the exact public, metadata-only status schema."""
        return {
            "schema_version": "sentinel-workbench-broker-status/v1",
            "command_id": self.command_id,
            "status": self.status,
        }


@dataclass(frozen=True)
class _SessionState:
    csrf_token: str
    expires_at: float


@dataclass(frozen=True)
class BrokerWorkerClaim:
    """Single-use broker-to-worker authority, never exposed to the browser."""

    command_id: str
    capability: str


def _serialized(method):
    @functools.wraps(method)
    def wrapped(self: "HostBroker", *args: object, **kwargs: object):
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapped


class HostBroker:
    """Host-owned command broker with an optional private durable queue."""

    def __init__(
        self,
        *,
        ui_origin: str,
        startup_capability: str,
        config_digest: str,
        allowed_profiles: set[str],
        allowed_pair_digests: set[str],
        session_ttl_seconds: int,
        allowed_commands: set[str] | None = None,
        allowed_selection_manifest_digests: set[str] | None = None,
        state_path: Path | str | None = None,
        clock: Callable[[], float] = time.monotonic,
        recover_running_commands: bool = True,
    ) -> None:
        self._assert_origin(ui_origin)
        if not isinstance(startup_capability, str) or len(startup_capability) < 16:
            raise ContractViolation("startup capability must be a high-entropy opaque value")
        self._ui_origin = ui_origin
        self._startup_capability = startup_capability
        self._capability_consumed = False
        self._config_digest = _digest(config_digest, "config_digest")
        if not allowed_profiles or not all(isinstance(profile, str) and profile for profile in allowed_profiles):
            raise ContractViolation("broker needs one or more allowed profiles")
        self._allowed_profiles = frozenset(allowed_profiles)
        self._allowed_pair_digests = frozenset(
            _digest(pair_digest, "allowed pair_digest") for pair_digest in allowed_pair_digests
        )
        if not self._allowed_pair_digests:
            raise ContractViolation("broker needs one or more allowed pair digests")
        allowed_commands = {"run-fixture-scan"} if allowed_commands is None else allowed_commands
        if not allowed_commands or not allowed_commands.issubset({"run-fixture-scan", "run-b3-reading"}):
            raise ContractViolation("broker command allowlist is invalid")
        self._allowed_commands = frozenset(allowed_commands)
        selection_digests = allowed_selection_manifest_digests or set()
        self._allowed_selection_manifest_digests = frozenset(
            _digest(digest, "allowed selection_manifest_digest") for digest in selection_digests
        )
        if "run-b3-reading" in self._allowed_commands and not self._allowed_selection_manifest_digests:
            raise ContractViolation("B3 broker command needs one or more sealed selection manifests")
        if not isinstance(session_ttl_seconds, int) or session_ttl_seconds <= 0:
            raise ContractViolation("broker session TTL must be positive")
        self._ttl = session_ttl_seconds
        self._clock = clock
        self._lock = threading.RLock()
        self._sessions: dict[str, _SessionState] = {}
        self._statuses: dict[str, BrokerStatus] = {}
        self._idempotency: dict[str, str] = {}
        self._commands: dict[str, BrokerCommand] = {}
        self._command_sessions: dict[str, str] = {}
        self._worker_capability_digests: dict[str, str] = {}
        self._worker_capabilities_consumed: set[str] = set()
        self._state_path = self._initialize_state_path(state_path)
        self._database = self._connect_database(self._state_path) if self._state_path else None
        if self._database is not None:
            self._database.execute(
                """
                CREATE TABLE IF NOT EXISTS broker_command (
                    command_id TEXT PRIMARY KEY,
                    command TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    pair_digest TEXT NOT NULL,
                    config_digest TEXT NOT NULL,
                    selection_manifest_digest TEXT,
                    session_id TEXT,
                    worker_capability_digest TEXT,
                    worker_capability_consumed INTEGER NOT NULL DEFAULT 0,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL CHECK(status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled'))
                )
                """
            )
            columns = {
                row[1] for row in self._database.execute("PRAGMA table_info(broker_command)").fetchall()
            }
            if "session_id" not in columns:
                self._database.execute("ALTER TABLE broker_command ADD COLUMN session_id TEXT")
            if "worker_capability_digest" not in columns:
                self._database.execute("ALTER TABLE broker_command ADD COLUMN worker_capability_digest TEXT")
            if "worker_capability_consumed" not in columns:
                self._database.execute(
                    "ALTER TABLE broker_command ADD COLUMN worker_capability_consumed INTEGER NOT NULL DEFAULT 0"
                )
            self._database.execute(
                """
                CREATE TABLE IF NOT EXISTS broker_startup (
                    capability_digest TEXT PRIMARY KEY,
                    consumed_at INTEGER NOT NULL
                )
                """
            )
            self._database.commit()
            if recover_running_commands:
                self._recover_abandoned_claims()

    @staticmethod
    def _initialize_state_path(state_path: Path | str | None) -> Path | None:
        if state_path is None:
            return None
        path = Path(state_path).resolve()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.parent.is_symlink() or not path.parent.is_dir():
            raise ContractViolation("broker state parent must be a private directory")
        os.chmod(path.parent, 0o700)
        return path

    @staticmethod
    def _connect_database(path: Path) -> sqlite3.Connection:
        connection = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        os.chmod(path, 0o600)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @staticmethod
    def _assert_origin(origin: object) -> None:
        if not isinstance(origin, str) or origin == "null" or "," in origin:
            raise ContractViolation("Origin must be one exact non-null value")
        if not origin.startswith("http://127.0.0.1:"):
            raise ContractViolation("broker UI Origin must be loopback http with an explicit port")

    def _require_origin(self, origin: object) -> None:
        self._assert_origin(origin)
        if origin != self._ui_origin:
            raise ContractViolation("request Origin does not match the configured UI origin")

    @_serialized
    def bootstrap(
        self,
        *,
        origin: str,
        body: Mapping[str, object],
        request_target: str,
        request_headers: Mapping[str, str],
    ) -> BrokerSession:
        self._require_origin(origin)
        if not isinstance(request_target, str) or "?" in request_target or "#" in request_target:
            raise ContractViolation("startup capability must never appear in a URL")
        lowered_headers = {str(key).lower(): str(value) for key, value in request_headers.items()}
        if "x-startup-capability" in lowered_headers or "authorization" in lowered_headers:
            raise ContractViolation("startup capability must be delivered in the bootstrap POST body only")
        referer = lowered_headers.get("referer", "")
        if self._startup_capability in referer:
            raise ContractViolation("startup capability must not leak through a referrer")
        if lowered_headers.get("content-type") != "application/json":
            raise ContractViolation("bootstrap requires exact JSON content type")
        if set(body) != {"startup_capability"} or body.get("startup_capability") != self._startup_capability:
            raise ContractViolation("bootstrap capability is invalid")
        if self._database is None:
            if self._capability_consumed:
                raise ContractViolation("startup capability has already been consumed")
            self._capability_consumed = True
        else:
            capability_digest = hashlib.sha256(self._startup_capability.encode("utf-8")).hexdigest()
            self._database.execute("BEGIN IMMEDIATE")
            try:
                existing = self._database.execute(
                    "SELECT 1 FROM broker_startup WHERE capability_digest = ?",
                    (capability_digest,),
                ).fetchone()
                if existing is not None:
                    self._database.execute("ROLLBACK")
                    raise ContractViolation("startup capability has already been consumed")
                self._database.execute(
                    "INSERT INTO broker_startup(capability_digest, consumed_at) VALUES (?, ?)",
                    (capability_digest, int(time.time())),
                )
                self._database.execute("COMMIT")
            except BaseException:
                if self._database.in_transaction:
                    self._database.execute("ROLLBACK")
                raise
            self._capability_consumed = True
        session_id = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        self._sessions[session_id] = _SessionState(csrf_token, self._clock() + self._ttl)
        return BrokerSession(
            session_id=session_id,
            csrf_token=csrf_token,
            cookie_header=f"workbench_session={session_id}; HttpOnly; SameSite=Strict; Path=/api/; Max-Age={self._ttl}",
        )

    @_serialized
    def cors_headers(self, origin: str, *, method: str, requested_headers: tuple[str, ...]) -> dict[str, str]:
        self._require_origin(origin)
        if method != _ALLOWED_CORS_METHOD:
            raise ContractViolation("broker only allows the fixed credentialed POST method")
        if tuple(header.lower() for header in requested_headers) not in _ALLOWED_CORS_HEADERS:
            raise ContractViolation("broker only allows the fixed CSRF/content-type request headers")
        return {
            "Access-Control-Allow-Origin": self._ui_origin,
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "content-type, x-workbench-csrf",
            "Vary": "Origin",
        }

    def _authorize_session(self, origin: str, session_id: str, csrf_token: str) -> None:
        self._require_origin(origin)
        session = self._sessions.get(session_id)
        if session is None or session.expires_at <= self._clock():
            self._sessions.pop(session_id, None)
            raise ContractViolation("broker session is absent or expired")
        if not secrets.compare_digest(session.csrf_token, csrf_token):
            raise ContractViolation("broker CSRF token is invalid")

    @_serialized
    def submit_command(
        self,
        *,
        origin: str,
        session_id: str,
        csrf_token: str,
        envelope: Mapping[str, object],
    ) -> BrokerStatus:
        self._authorize_session(origin, session_id, csrf_token)
        command = BrokerCommand.from_mapping(dict(envelope))
        if command.command not in self._allowed_commands:
            raise ContractViolation("broker command is not enabled for this phase/profile")
        if command.profile not in self._allowed_profiles:
            raise ContractViolation("broker profile is not allowlisted")
        if command.pair_digest not in self._allowed_pair_digests:
            raise ContractViolation("broker pair is not registered")
        if command.config_digest != self._config_digest:
            raise ContractViolation("broker configuration digest does not match")
        if command.command == "run-b3-reading" and (
            command.selection_manifest_digest is None
            or command.selection_manifest_digest not in self._allowed_selection_manifest_digests
        ):
            raise ContractViolation("broker B3 selection manifest is not registered")
        idempotency_key = hashlib.sha256(
            json.dumps(
                {
                    "command": command.command,
                    "profile": command.profile,
                    "pair_digest": command.pair_digest,
                    "config_digest": command.config_digest,
                    "selection_manifest_digest": command.selection_manifest_digest,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        existing_id = self._idempotency.get(idempotency_key)
        if existing_id is not None:
            self._require_command_owner(existing_id, session_id)
            return self.status(existing_id)
        if self._database is not None:
            existing = self._database.execute(
                "SELECT command_id, session_id FROM broker_command WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if existing is not None:
                self._idempotency[idempotency_key] = existing[0]
                self._command_sessions[existing[0]] = existing[1] or ""
                self._require_command_owner(existing[0], session_id)
                return self.status(existing[0])
        command_id = secrets.token_urlsafe(24)
        status = BrokerStatus(command_id=command_id, status="queued")
        self._statuses[command_id] = status
        self._idempotency[idempotency_key] = command_id
        self._commands[command_id] = command
        self._command_sessions[command_id] = session_id
        if self._database is not None:
            with self._database:
                self._database.execute(
                    """
                    INSERT INTO broker_command(
                        command_id, command, profile, pair_digest, config_digest, selection_manifest_digest, session_id, idempotency_key, status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued')
                    """,
                    (
                        command_id,
                        command.command,
                        command.profile,
                        command.pair_digest,
                        command.config_digest,
                        command.selection_manifest_digest,
                        session_id,
                        idempotency_key,
                    ),
                )
        return status

    @_serialized
    def status(self, command_id: str) -> BrokerStatus:
        status = None
        if self._database is not None:
            row = self._database.execute(
                "SELECT status FROM broker_command WHERE command_id = ?", (command_id,)
            ).fetchone()
            if row is not None:
                status = BrokerStatus(command_id=command_id, status=row[0])
                self._statuses[command_id] = status
        else:
            status = self._statuses.get(command_id)
        if status is None:
            raise ContractViolation("unknown broker command")
        return status

    @_serialized
    def status_for_session(
        self,
        *,
        origin: str,
        session_id: str,
        csrf_token: str,
        command_id: str,
    ) -> BrokerStatus:
        """Return a metadata-only status only to the session that queued it."""
        self._authorize_session(origin, session_id, csrf_token)
        if not isinstance(command_id, str) or not command_id:
            raise ContractViolation("broker status requires a command ID")
        self._require_command_owner(command_id, session_id)
        return self.status(command_id)

    @_serialized
    def command_for_worker(self, command_id: str) -> BrokerCommand:
        """Resolve a typed command only after its private worker claim is running."""
        if self.status(command_id).status != "running":
            raise ContractViolation("only a claimed running command may reach a private worker")
        command = self._commands.get(command_id)
        if command is not None:
            return command
        if self._database is None:
            raise ContractViolation("broker command metadata is unavailable")
        row = self._database.execute(
            """
            SELECT command, profile, pair_digest, config_digest, selection_manifest_digest
            FROM broker_command WHERE command_id = ?
            """,
            (command_id,),
        ).fetchone()
        if row is None:
            raise ContractViolation("unknown broker command")
        command = BrokerCommand(*row)
        self._commands[command_id] = command
        return command

    def _require_command_owner(self, command_id: str, session_id: str) -> None:
        owner = self._command_sessions.get(command_id)
        if owner is None and self._database is not None:
            row = self._database.execute(
                "SELECT session_id FROM broker_command WHERE command_id = ?",
                (command_id,),
            ).fetchone()
            owner = None if row is None else row[0]
            if owner is not None:
                self._command_sessions[command_id] = owner
        if not owner or not secrets.compare_digest(owner, session_id):
            raise ContractViolation("broker command is not owned by this session")

    @_serialized
    def claim_next_for_worker(self) -> str | None:
        """Atomically reserve one queued command for the private worker side."""
        claim = self._claim_next_for_worker()
        return None if claim is None else claim.command_id

    @_serialized
    def claim_next_for_worker_authorized(self) -> BrokerWorkerClaim | None:
        """Claim work and mint the one-use authority required by the private socket."""
        return self._claim_next_for_worker()

    def _claim_next_for_worker(self) -> BrokerWorkerClaim | None:
        capability = secrets.token_urlsafe(32)
        capability_digest = hashlib.sha256(capability.encode("utf-8")).hexdigest()
        if self._database is None:
            for command_id, status in self._statuses.items():
                if status.status == "queued":
                    self._statuses[command_id] = BrokerStatus(command_id, "running")
                    self._worker_capability_digests[command_id] = capability_digest
                    self._worker_capabilities_consumed.discard(command_id)
                    return BrokerWorkerClaim(command_id, capability)
            return None
        self._database.execute("BEGIN IMMEDIATE")
        try:
            row = self._database.execute(
                "SELECT command_id FROM broker_command WHERE status = 'queued' ORDER BY rowid LIMIT 1"
            ).fetchone()
            if row is None:
                self._database.execute("COMMIT")
                return None
            command_id = row[0]
            self._database.execute(
                """
                UPDATE broker_command
                SET status = 'running', worker_capability_digest = ?, worker_capability_consumed = 0
                WHERE command_id = ? AND status = 'queued'
                """,
                (capability_digest, command_id),
            )
            self._database.execute("COMMIT")
        except BaseException:
            self._database.execute("ROLLBACK")
            raise
        self._statuses[command_id] = BrokerStatus(command_id, "running")
        self._worker_capability_digests[command_id] = capability_digest
        self._worker_capabilities_consumed.discard(command_id)
        return BrokerWorkerClaim(command_id, capability)

    @_serialized
    def authorize_worker_claim(self, command_id: str, capability: str) -> bool:
        """Consume an unguessable per-claim token before a worker can see command metadata."""
        if not isinstance(command_id, str) or not isinstance(capability, str) or not capability:
            return False
        digest = hashlib.sha256(capability.encode("utf-8")).hexdigest()
        if self._database is None:
            expected = self._worker_capability_digests.get(command_id)
            if (
                expected is None
                or command_id in self._worker_capabilities_consumed
                or not secrets.compare_digest(expected, digest)
                or self.status(command_id).status != "running"
            ):
                return False
            self._worker_capabilities_consumed.add(command_id)
            return True
        self._database.execute("BEGIN IMMEDIATE")
        try:
            changed = self._database.execute(
                """
                UPDATE broker_command
                SET worker_capability_consumed = 1
                WHERE command_id = ?
                  AND status = 'running'
                  AND worker_capability_consumed = 0
                  AND worker_capability_digest = ?
                """,
                (command_id, digest),
            ).rowcount
            if changed != 1:
                self._database.execute("ROLLBACK")
                return False
            self._database.execute("COMMIT")
        except BaseException:
            if self._database.in_transaction:
                self._database.execute("ROLLBACK")
            raise
        self._worker_capabilities_consumed.add(command_id)
        return True

    @_serialized
    def finish_worker_command(self, command_id: str, *, succeeded: bool) -> BrokerStatus:
        """Record exactly one terminal worker result; queued commands cannot finish."""
        current = self.status(command_id)
        if current.status != "running":
            raise ContractViolation("only a claimed running command may receive a terminal worker status")
        terminal = "succeeded" if succeeded else "failed"
        if self._database is not None:
            with self._database:
                cursor = self._database.execute(
                    "UPDATE broker_command SET status = ? WHERE command_id = ? AND status = 'running'",
                    (terminal, command_id),
                )
                if cursor.rowcount != 1:
                    raise ContractViolation("worker status transition lost its exclusive claim")
        status = BrokerStatus(command_id, terminal)
        self._statuses[command_id] = status
        return status

    def _recover_abandoned_claims(self) -> None:
        """A process restart cannot turn an uncertain worker outcome into a retryable queue item."""
        if self._database is None:
            return
        with self._lock, self._database:
            self._database.execute(
                "UPDATE broker_command SET status = 'failed' WHERE status = 'running'"
            )


def broker_from_environment(*, recover_running_commands: bool) -> HostBroker:
    """Build a host-only broker from explicit startup configuration."""
    required = {
        name: os.environ[name]
        for name in (
            "WORKBENCH_UI_ORIGIN",
            "WORKBENCH_STARTUP_CAPABILITY",
            "WORKBENCH_CONFIG_DIGEST",
            "WORKBENCH_ALLOWED_PROFILES",
            "WORKBENCH_ALLOWED_PAIR_DIGESTS",
            "WORKBENCH_BROKER_STATE_PATH",
        )
    }
    commands = set(filter(None, os.environ.get("WORKBENCH_ALLOWED_COMMANDS", "run-fixture-scan").split(",")))
    selection_digests = set(
        filter(None, os.environ.get("WORKBENCH_ALLOWED_SELECTION_MANIFEST_DIGESTS", "").split(","))
    )
    return HostBroker(
        ui_origin=required["WORKBENCH_UI_ORIGIN"],
        startup_capability=required["WORKBENCH_STARTUP_CAPABILITY"],
        config_digest=required["WORKBENCH_CONFIG_DIGEST"],
        allowed_profiles=set(filter(None, required["WORKBENCH_ALLOWED_PROFILES"].split(","))),
        allowed_pair_digests=set(filter(None, required["WORKBENCH_ALLOWED_PAIR_DIGESTS"].split(","))),
        allowed_commands=commands,
        allowed_selection_manifest_digests=selection_digests,
        session_ttl_seconds=300,
        state_path=required["WORKBENCH_BROKER_STATE_PATH"],
        recover_running_commands=recover_running_commands,
    )


def _main(argv: list[str]) -> int:
    """Expose a guarded local contract check or serve the broker on loopback."""
    if argv == ["--check"]:
        print(
            json.dumps(
                {
                    "schema_version": "sentinel-workbench-host-broker-check/v1",
                    "state": "loopback-http-listener-available",
                    "detail": "The host broker can serve the exact-origin bootstrap, command and status protocol on literal loopback.",
                },
                sort_keys=True,
            )
        )
        return 0
    if argv != ["--serve"]:
        print("usage: python -m workbench.host_broker --check|--serve", file=sys.stderr)
        return 2
    try:
        from .broker_http import serve

        broker = broker_from_environment(recover_running_commands=True)
        port = int(os.environ.get("WORKBENCH_BROKER_PORT", "4174"))
        if not 1 <= port <= 65535:
            raise ValueError("invalid broker port")
        serve(broker, host="127.0.0.1", port=port)
    except (KeyError, ValueError, ContractViolation) as error:
        print(f"workbench broker refused configuration: {type(error).__name__}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
