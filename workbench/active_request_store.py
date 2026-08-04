"""Exactly-once CMC request reservation state."""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path


class ActiveRequestViolation(ValueError):
    """Raised when a CMC nonce/request state cannot dispatch safely."""


class ActiveRequestStore:
    def __init__(self, path: Path | str) -> None:
        self._path = Path(path).resolve()
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self._path.parent, 0o700)
        self._db = sqlite3.connect(self._path, isolation_level=None)
        os.chmod(self._path, 0o600)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS cmc_request (
              request_digest TEXT PRIMARY KEY,
              nonce TEXT NOT NULL UNIQUE,
              status TEXT NOT NULL CHECK(status IN ('reserved','dispatched','succeeded','rejected','revoked','unknown'))
            )
            """
        )
        self._db.execute("UPDATE cmc_request SET status = 'unknown' WHERE status = 'dispatched'")

    def reserve(self, *, request_digest: str, nonce: str) -> None:
        if not request_digest or not nonce:
            raise ActiveRequestViolation("CMC reservation needs request digest and nonce")
        try:
            with self._db:
                self._db.execute(
                    "INSERT INTO cmc_request(request_digest, nonce, status) VALUES (?, ?, 'reserved')",
                    (request_digest, nonce),
                )
        except sqlite3.IntegrityError as error:
            raise ActiveRequestViolation("CMC request/nonce is already consumed or reserved") from error

    def revoke(self, request_digest: str) -> None:
        with self._db:
            changed = self._db.execute(
                "UPDATE cmc_request SET status = 'revoked' WHERE request_digest = ? AND status = 'reserved'",
                (request_digest,),
            ).rowcount
            if changed != 1:
                raise ActiveRequestViolation("only a reserved CMC request can be revoked")

    def mark_dispatched(self, request_digest: str) -> None:
        with self._db:
            changed = self._db.execute(
                "UPDATE cmc_request SET status = 'dispatched' WHERE request_digest = ? AND status = 'reserved'",
                (request_digest,),
            ).rowcount
            if changed != 1:
                raise ActiveRequestViolation("only a reserved non-revoked CMC request may dispatch")
