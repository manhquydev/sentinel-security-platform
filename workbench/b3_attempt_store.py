"""Durable exactly-once reservation state for constrained B3 dispatch."""
from __future__ import annotations

import os
import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path

from .contracts import _digest


class AttemptStoreViolation(ValueError):
    """Raised when an attempt would violate B3 exactly-once state rules."""


@dataclass(frozen=True)
class B3Attempt:
    attempt_id: str
    run_id: str
    arm: str
    replication: int
    selection_manifest_digest: str
    unit_id: str
    profile: str
    status: str


class B3AttemptStore:
    """SQLite-backed reservation store; an unknown transport outcome is terminal."""

    def __init__(self, state_path: Path | str) -> None:
        self._path = Path(state_path).resolve()
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self._path.parent.is_symlink() or not self._path.parent.is_dir():
            raise AttemptStoreViolation("attempt state parent must be a private directory")
        os.chmod(self._path.parent, 0o700)
        self._db = sqlite3.connect(self._path, isolation_level=None)
        os.chmod(self._path, 0o600)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS attempt (
              attempt_id TEXT PRIMARY KEY,
              run_id TEXT NOT NULL,
              arm TEXT NOT NULL,
              replication INTEGER NOT NULL,
              selection_manifest_digest TEXT NOT NULL,
              unit_id TEXT NOT NULL,
              profile TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('reserved','dispatched','succeeded','failed','unknown')),
              terminal_reason TEXT,
              UNIQUE(run_id, arm, replication, selection_manifest_digest, unit_id)
            );
            CREATE TABLE IF NOT EXISTS revoked_profile (
              profile TEXT PRIMARY KEY
            );
            """
        )
        columns = {row[1] for row in self._db.execute("PRAGMA table_info(attempt)").fetchall()}
        if "unit_id" not in columns:
            self._migrate_attempts_to_per_unit_reservations()
        self._recover_stranded_dispatches()

    def reserve(
        self,
        *,
        run_id: str,
        arm: str,
        replication: int,
        selection_manifest_digest: str,
        profile: str,
        unit_id: str,
    ) -> B3Attempt:
        if not isinstance(run_id, str) or not run_id or not isinstance(arm, str) or arm != "B3":
            raise AttemptStoreViolation("attempt requires a labelled B3 run")
        if not isinstance(profile, str) or not profile:
            raise AttemptStoreViolation("attempt requires a labelled profile")
        if not isinstance(unit_id, str) or not unit_id or len(unit_id) > 256 or any(character.isspace() for character in unit_id):
            raise AttemptStoreViolation("attempt requires a bounded unit ID")
        if not isinstance(replication, int) or isinstance(replication, bool) or replication < 1:
            raise AttemptStoreViolation("replication must be a positive integer")
        digest = _digest(selection_manifest_digest, "selection_manifest_digest")
        attempt_id = uuid.uuid4().hex
        self._db.execute("BEGIN IMMEDIATE")
        try:
            existing = self._db.execute(
                """
                SELECT attempt_id, status FROM attempt
                WHERE run_id = ? AND arm = ? AND replication = ? AND selection_manifest_digest = ? AND unit_id = ?
                """,
                (run_id, arm, replication, digest, unit_id),
            ).fetchone()
            if existing is not None:
                self._db.execute("ROLLBACK")
                raise AttemptStoreViolation(f"duplicate B3 attempt already has terminal/reserved state {existing[1]}")
            self._db.execute(
                """
                INSERT INTO attempt(attempt_id,run_id,arm,replication,selection_manifest_digest,unit_id,profile,status)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'reserved')
                """,
                (attempt_id, run_id, arm, replication, digest, unit_id, profile),
            )
            self._db.execute("COMMIT")
        except BaseException:
            if self._db.in_transaction:
                self._db.execute("ROLLBACK")
            raise
        return B3Attempt(attempt_id, run_id, arm, replication, digest, unit_id, profile, "reserved")

    def revoke_profile(self, profile: str) -> None:
        if not isinstance(profile, str) or not profile:
            raise AttemptStoreViolation("profile must be labelled")
        with self._db:
            self._db.execute("INSERT OR IGNORE INTO revoked_profile(profile) VALUES (?)", (profile,))

    def mark_dispatched(self, attempt_id: str, *, profile: str) -> B3Attempt:
        if self._is_revoked(profile):
            raise AttemptStoreViolation("profile is revoked before provider dispatch")
        self._db.execute("BEGIN IMMEDIATE")
        try:
            if self._is_revoked(profile):
                self._db.execute("ROLLBACK")
                raise AttemptStoreViolation("profile is revoked before provider dispatch")
            changed = self._db.execute(
                """
                UPDATE attempt SET status = 'dispatched'
                WHERE attempt_id = ? AND profile = ? AND status = 'reserved'
                """,
                (attempt_id, profile),
            ).rowcount
            if changed != 1:
                self._db.execute("ROLLBACK")
                raise AttemptStoreViolation("only a reserved attempt bound to the same profile may dispatch")
            self._db.execute("COMMIT")
        except BaseException:
            if self._db.in_transaction:
                self._db.execute("ROLLBACK")
            raise
        return self.status(attempt_id)

    def mark_unknown(self, attempt_id: str, *, reason: str) -> B3Attempt:
        if not isinstance(reason, str) or not reason:
            raise AttemptStoreViolation("unknown outcome requires a reason")
        return self._transition(attempt_id, "unknown", reason=reason)

    def mark_terminal(self, attempt_id: str, *, status: str) -> B3Attempt:
        if status not in {"succeeded", "failed"}:
            raise AttemptStoreViolation("terminal status is invalid")
        return self._transition(attempt_id, status)

    def mark_rejected(self, attempt_id: str, *, reason: str) -> B3Attempt:
        if not isinstance(reason, str) or not reason:
            raise AttemptStoreViolation("rejected attempt requires a reason")
        return self._transition_from_reserved(attempt_id, "failed", reason)

    def _transition(self, attempt_id: str, status: str, *, reason: str | None = None) -> B3Attempt:
        with self._db:
            changed = self._db.execute(
                """
                UPDATE attempt SET status = ?, terminal_reason = ?
                WHERE attempt_id = ? AND status = 'dispatched'
                """,
                (status, reason, attempt_id),
            ).rowcount
            if changed != 1:
                raise AttemptStoreViolation("only a dispatched attempt may become terminal")
        return self.status(attempt_id)

    def _transition_from_reserved(self, attempt_id: str, status: str, reason: str) -> B3Attempt:
        with self._db:
            changed = self._db.execute(
                """
                UPDATE attempt SET status = ?, terminal_reason = ?
                WHERE attempt_id = ? AND status = 'reserved'
                """,
                (status, reason, attempt_id),
            ).rowcount
            if changed != 1:
                raise AttemptStoreViolation("only a reserved attempt may be rejected")
        return self.status(attempt_id)

    def retryable(self, attempt_id: str) -> bool:
        attempt = self.status(attempt_id)
        if attempt.status == "unknown":
            raise AttemptStoreViolation("unknown B3 outcome is non-retryable")
        return attempt.status == "reserved"

    def status(self, attempt_id: str) -> B3Attempt:
        row = self._db.execute(
            """
            SELECT attempt_id, run_id, arm, replication, selection_manifest_digest, unit_id, profile, status
            FROM attempt WHERE attempt_id = ?
            """,
            (attempt_id,),
        ).fetchone()
        if row is None:
            raise AttemptStoreViolation("unknown B3 attempt")
        return B3Attempt(*row)

    def _is_revoked(self, profile: str) -> bool:
        return self._db.execute("SELECT 1 FROM revoked_profile WHERE profile = ?", (profile,)).fetchone() is not None

    def _recover_stranded_dispatches(self) -> None:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            self._db.execute(
                """
                UPDATE attempt
                SET status = 'unknown', terminal_reason = 'restart-after-dispatch'
                WHERE status = 'dispatched'
                """
            )
            self._db.execute("COMMIT")
        except BaseException:
            if self._db.in_transaction:
                self._db.execute("ROLLBACK")
            raise

    def _migrate_attempts_to_per_unit_reservations(self) -> None:
        """Preserve legacy terminal state while making future calls unique per request."""
        self._db.execute("BEGIN IMMEDIATE")
        try:
            self._db.execute("ALTER TABLE attempt RENAME TO attempt_legacy")
            self._db.execute(
                """
                CREATE TABLE attempt (
                  attempt_id TEXT PRIMARY KEY,
                  run_id TEXT NOT NULL,
                  arm TEXT NOT NULL,
                  replication INTEGER NOT NULL,
                  selection_manifest_digest TEXT NOT NULL,
                  unit_id TEXT NOT NULL,
                  profile TEXT NOT NULL,
                  status TEXT NOT NULL CHECK(status IN ('reserved','dispatched','succeeded','failed','unknown')),
                  terminal_reason TEXT,
                  UNIQUE(run_id, arm, replication, selection_manifest_digest, unit_id)
                )
                """
            )
            self._db.execute(
                """
                INSERT INTO attempt(
                  attempt_id, run_id, arm, replication, selection_manifest_digest, unit_id, profile, status, terminal_reason
                )
                SELECT
                  attempt_id, run_id, arm, replication, selection_manifest_digest, 'legacy-unspecified', profile, status, terminal_reason
                FROM attempt_legacy
                """
            )
            self._db.execute("DROP TABLE attempt_legacy")
            self._db.execute("COMMIT")
        except BaseException:
            if self._db.in_transaction:
                self._db.execute("ROLLBACK")
            raise
