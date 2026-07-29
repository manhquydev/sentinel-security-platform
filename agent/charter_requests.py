"""Durable executor-only path for the two literal Sentinel charter requests."""
from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Protocol
from urllib.parse import urlsplit

ORIGIN = "https://127.0.0.1:18443"
POLICY = "sentinel-charter-requests/v2-purpose-bound"
POLICY_DIGEST = hashlib.sha256(POLICY.encode()).hexdigest()
TIMEOUT_SECONDS = 5
RESPONSE_CAP = 64 * 1024
EXECUTOR_CONSUMER = "sentinel-charter-executor"
GET_PURPOSE = "Inspect the fixed public product-search response for q=apple; it does not modify target state."
POST_PURPOSE = "Exercise the fixed unauthenticated empty-basket request; it is expected to return 4xx before a target-state change."


class CharterRequestError(RuntimeError):
    pass


@dataclass(frozen=True)
class ResponseObservation:
    """Capped response bytes and local-only raw Content-Type field occurrences."""

    status: int
    body: bytes
    content_types: tuple[str, ...]


def assert_exact_origin(value: str | None = None) -> str:
    if value is not None or os.environ.get("KONG_PROXY") is not None:
        raise CharterRequestError("charter origin is immutable")
    parsed = urlsplit(ORIGIN)
    if (parsed.scheme, parsed.hostname, parsed.port, parsed.username, parsed.password, parsed.path,
            parsed.query, parsed.fragment) != ("https", "127.0.0.1", 18443, None, None, "", "", ""):
        raise CharterRequestError("invalid compiled charter origin")
    return ORIGIN


@dataclass(frozen=True)
class RequestSpec:
    request_id: str
    run_id: str
    method: str
    path: str
    query: str
    body: str
    headers: tuple[tuple[str, str], ...]
    origin: str
    policy_digest: str
    expires_at: float
    purpose: str

    def canonical(self) -> bytes:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()


def _purpose_for(spec: RequestSpec) -> str | None:
    if (spec.method == "GET" and spec.path == "/rest/products/search" and spec.query == "q=apple"
            and spec.body == "" and spec.headers == ()):
        return GET_PURPOSE
    if (spec.method == "POST" and spec.path == "/rest/basket" and spec.query == "" and spec.body == "{}"
            and spec.headers == (("Content-Type", "application/json"),)):
        return POST_PURPOSE
    return None


def validate_spec(spec: RequestSpec) -> None:
    assert_exact_origin()
    purpose = _purpose_for(spec)
    if (not purpose or spec.purpose != purpose or spec.origin != ORIGIN or spec.policy_digest != POLICY_DIGEST
            or not isinstance(spec.request_id, str) or not spec.request_id
            or not isinstance(spec.run_id, str) or not spec.run_id
            or not isinstance(spec.expires_at, (int, float)) or isinstance(spec.expires_at, bool)
            or (isinstance(spec.expires_at, float) and not math.isfinite(spec.expires_at))):
        raise CharterRequestError("request outside immutable charter policy")


def make_spec(*, run_id: str, method: str, path: str, query: str = "", body: str = "",
              headers: dict[str, str] | None = None, ttl: int = 300) -> RequestSpec:
    headers = headers or {}
    provisional = RequestSpec(str(uuid.uuid4()), run_id, method.upper(), path, query, body,
                              tuple(sorted(headers.items())), assert_exact_origin(), POLICY_DIGEST,
                              time.time() + ttl, "")
    purpose = _purpose_for(provisional)
    if not purpose:
        raise CharterRequestError("request outside immutable charter policy")
    spec = RequestSpec(provisional.request_id, provisional.run_id, provisional.method, provisional.path,
                       provisional.query, provisional.body, provisional.headers, provisional.origin,
                       provisional.policy_digest, provisional.expires_at, purpose)
    validate_spec(spec)
    return spec


def load_spec(value: object) -> RequestSpec:
    """Construct and validate a persisted request spec without migrating old artifacts."""
    if not isinstance(value, dict):
        raise CharterRequestError("invalid persisted request spec")
    normalized = dict(value)
    headers = normalized.get("headers")
    if not isinstance(headers, (list, tuple)):
        raise CharterRequestError("invalid persisted request spec")
    try:
        normalized["headers"] = tuple(
            (pair[0], pair[1])
            for pair in headers
            if isinstance(pair, (list, tuple)) and len(pair) == 2
            and isinstance(pair[0], str) and isinstance(pair[1], str)
        )
    except (TypeError, IndexError):
        raise CharterRequestError("invalid persisted request spec") from None
    if len(normalized["headers"]) != len(headers):
        raise CharterRequestError("invalid persisted request spec")
    try:
        spec = RequestSpec(**normalized)
    except (TypeError, ValueError) as exc:
        raise CharterRequestError("invalid persisted request spec") from exc
    validate_spec(spec)
    return spec


class Transport(Protocol):
    def mint(self, origin: str, client_secret: str) -> str: ...
    def request(self, url: str, method: str, headers: dict[str, str], body: str,
                timeout: int, cap: int) -> ResponseObservation: ...


class RequestStore:
    def __init__(self, path: str):
        # Do not toggle journal_mode in every competing process: WAL negotiation itself takes an
        # exclusive database lock. The normal rollback journal + BEGIN IMMEDIATE serializes the
        # tiny reservation transaction safely across independently-started executors.
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
        self.db.execute("PRAGMA busy_timeout=10000")
        for attempt in range(20):
            try:
                self.db.executescript("""
        CREATE TABLE IF NOT EXISTS requests(
          id TEXT PRIMARY KEY, run TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
          state TEXT NOT NULL, ts REAL NOT NULL, spec_digest TEXT NOT NULL, receipt_digest TEXT);
        CREATE TABLE IF NOT EXISTS decisions(nonce TEXT PRIMARY KEY, request_id TEXT NOT NULL,
          decision TEXT NOT NULL, ts REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS revocations(request_id TEXT PRIMARY KEY, nonce TEXT NOT NULL, ts REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS events(id TEXT NOT NULL, state TEXT NOT NULL, ts REAL NOT NULL);
        """)
                # Recovery itself mutates state.  Keep it in the same retry envelope as
                # schema creation; otherwise a concurrent opener can lose the lock here
                # and be misclassified as a quota refusal before it reaches reservation.
                self.db.execute("BEGIN IMMEDIATE")
                now = time.time()
                prepared = self.db.execute("SELECT id FROM requests WHERE state='prepared'").fetchall()
                dispatched = self.db.execute("SELECT id FROM requests WHERE state='dispatched'").fetchall()
                self.db.execute("UPDATE requests SET state='terminal' WHERE state='prepared'")
                self.db.execute("UPDATE requests SET state='unknown' WHERE state='dispatched'")
                self.db.executemany("INSERT INTO events VALUES(?,?,?)",
                                    [(row[0], "terminal", now) for row in prepared]
                                    + [(row[0], "unknown", now) for row in dispatched])
                self.db.execute("COMMIT")
                break
            except sqlite3.OperationalError as exc:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                if "locked" not in str(exc).lower() or attempt == 19:
                    self.db.close(); raise CharterRequestError("executor state store unavailable") from exc
                time.sleep(0.02 * (attempt + 1))

    def _transition(self, request_id: str, state: str, receipt: str | None = None) -> None:
        allowed = {"prepared": {"dispatched", "terminal"}, "dispatched": {"unknown"}}
        row = self.db.execute("SELECT state FROM requests WHERE id=?", (request_id,)).fetchone()
        if not row or state not in allowed.get(row[0], set()):
            raise CharterRequestError("illegal request state transition")
        self.db.execute("UPDATE requests SET state=?, receipt_digest=COALESCE(?,receipt_digest) WHERE id=?",
                        (state, receipt, request_id))
        self.db.execute("INSERT INTO events VALUES(?,?,?)", (request_id, state, time.time()))

    def authorize_prepare(self, spec: RequestSpec, approval, public_key) -> None:
        from .charter_approval import verify
        validate_spec(spec)
        if not verify(approval, spec, public_key):
            raise CharterRequestError("invalid approval envelope")
        now = time.time()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            if self.db.execute("SELECT 1 FROM decisions WHERE nonce=?", (approval.nonce,)).fetchone():
                raise CharterRequestError("approval replay")
            self.db.execute("INSERT INTO decisions VALUES(?,?,?,?)", (approval.nonce, spec.request_id, approval.decision, now))
            if approval.decision == "revoke":
                self.db.execute("INSERT INTO revocations VALUES(?,?,?) ON CONFLICT(request_id) DO NOTHING",
                                (spec.request_id, approval.nonce, now))
                self.db.execute("COMMIT")
                raise CharterRequestError("approval revoked")
            if approval.decision != "approve":
                self.db.execute("COMMIT")
                raise CharterRequestError("approval rejected")
            if self.db.execute("SELECT 1 FROM revocations WHERE request_id=?", (spec.request_id,)).fetchone():
                raise CharterRequestError("approval revoked")
            if spec.expires_at <= now:
                raise CharterRequestError("request expired")
            if self.db.execute("SELECT 1 FROM requests WHERE id=?", (spec.request_id,)).fetchone():
                raise CharterRequestError("request replay")
            if self.db.execute("SELECT count(*) FROM requests WHERE ts>?", (now - 60,)).fetchone()[0] >= 5:
                raise CharterRequestError("request quota exhausted")
            if spec.method == "POST" and self.db.execute(
                    "SELECT 1 FROM requests WHERE run=? AND method='POST'", (spec.run_id,)).fetchone():
                raise CharterRequestError("POST quota exhausted")
            digest = hashlib.sha256(spec.canonical()).hexdigest()
            self.db.execute("INSERT INTO requests VALUES(?,?,?,?,?,?,?,NULL)",
                            (spec.request_id, spec.run_id, spec.method, spec.path, "prepared", now, digest))
            self.db.execute("INSERT INTO events VALUES(?,?,?)", (spec.request_id, "prepared", now))
            self.db.execute("COMMIT")
        except Exception:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def dispatched(self, request_id: str) -> None: self._transition(request_id, "dispatched")
    def dispatch_if_not_revoked(self, request_id: str) -> None:
        """Linearization point: a revoke committed before this transaction wins before OAuth I/O.

        Once this commits, dispatch is durable and a later revoke is truthfully too late to claim
        zero network effect; it remains recorded for audit but cannot cancel an in-flight request.
        """
        self.db.execute("BEGIN IMMEDIATE")
        try:
            if self.db.execute("SELECT 1 FROM revocations WHERE request_id=?", (request_id,)).fetchone():
                # The winning revoke consumes the prepared reservation immediately; no later
                # reopen is needed to repair its state and no OAuth/target call may follow.
                self._transition(request_id, "terminal")
                self.db.execute("COMMIT")
                raise CharterRequestError("approval revoked")
            self._transition(request_id, "dispatched")
            self.db.execute("COMMIT")
        except Exception:
            if self.db.in_transaction: self.db.execute("ROLLBACK")
            raise
    def unknown(self, request_id: str) -> None: self._transition(request_id, "unknown")

    def _before_terminalization_commit(self) -> None:
        """Narrow local failure seam for transaction tests."""

    def _after_terminalization_commit(self) -> None:
        """Narrow local failure seam for transaction tests."""

    def _terminalize_from(self, request_id: str, receipt: str, expected_state: str) -> None:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT state FROM requests WHERE id=?", (request_id,)).fetchone()
            if not row or row[0] != expected_state:
                raise CharterRequestError("illegal request state transition")
            self.db.execute("UPDATE requests SET state='terminal', receipt_digest=? WHERE id=?",
                            (receipt, request_id))
            self.db.execute("INSERT INTO events VALUES(?,?,?)", (request_id, "terminal", time.time()))
            self._before_terminalization_commit()
            self.db.execute("COMMIT")
        except Exception:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise
        self._after_terminalization_commit()

    def terminalize_response(self, request_id: str, receipt: str) -> None:
        """Atomically record one bounded response received for a dispatched request."""
        self._terminalize_from(request_id, receipt, "dispatched")

    def _terminalize_audit(self, request_id: str, receipt: str) -> None:
        """Atomically settle an indeterminate request from validated audit evidence."""
        self._terminalize_from(request_id, receipt, "unknown")

    def refuse_observed(self, request_id: str) -> None:
        if self.state(request_id) == "observed":
            raise CharterRequestError("request recovery required")

    def state(self, request_id: str) -> str | None:
        row = self.db.execute("SELECT state FROM requests WHERE id=?", (request_id,)).fetchone(); return row[0] if row else None

    def reconcile_audit(self, request_id: str, audit_records: list[dict]) -> dict:
        row = self.db.execute("SELECT state,method,path FROM requests WHERE id=?", (request_id,)).fetchone()
        if not row or row[0] != "unknown": raise CharterRequestError("request is not reconcilable")
        expected_query = "q=apple" if (row[1], row[2]) == ("GET", "/rest/products/search") else ""
        if (row[1], row[2]) not in (("GET", "/rest/products/search"), ("POST", "/rest/basket")):
            raise CharterRequestError("request is not reconcilable")
        if not all(isinstance(record, dict) for record in audit_records):
            raise CharterRequestError("invalid audit evidence")
        matches = [r for r in audit_records if r.get("request_id") == request_id
                   and r.get("consumer") == EXECUTOR_CONSUMER and r.get("method") == row[1]
                   and r.get("path") == row[2] and r.get("query") == expected_query
                   and _status_matches_policy(row[1], r.get("status"))
                   and isinstance(r.get("source_digest"), str)
                   and len(r["source_digest"]) == 64
                   and all(character in "0123456789abcdef" for character in r["source_digest"])]
        if len(matches) != 1: raise CharterRequestError("audit receipt absent or ambiguous")
        receipt = matches[0]["source_digest"]
        self._terminalize_audit(request_id, receipt)
        return {"request_id": request_id, "status": matches[0]["status"], "receipt_digest": receipt}

    def reconcile_audit_file(self, request_id: str, path: str) -> dict:
        return self.reconcile_audit(request_id, parse_kong_file_log(open(path, "rb").read()))
    def close(self): self.db.close()


def parse_kong_file_log(raw: bytes) -> list[dict]:
    """Fail-closed parser for Kong file-log JSON lines; no synthetic flattened receipt input."""
    records: list[dict] = []
    for line in raw.splitlines():
        if not line.strip(): continue
        try:
            value = json.loads(line, object_pairs_hook=_object_without_duplicate_keys,
                               parse_constant=_reject_json_constant)
            request, response, consumer = value["request"], value["response"], value["consumer"]
            if not all(isinstance(value, dict) for value in (request, response, consumer)):
                continue
            headers = request.get("headers")
            if not isinstance(headers, dict):
                continue
            request_id = headers.get("x-sentinel-request-id") or headers.get("X-Sentinel-Request-ID")
            uri = request["uri"]
            parsed = urlsplit(uri)
            path, query = parsed.path, parsed.query
            if not all(isinstance(x, str) for x in (request_id, consumer["username"], request["method"], path)):
                continue
            if parsed.scheme or parsed.netloc or parsed.fragment or type(response["status"]) is not int: continue
            records.append({"request_id": request_id, "consumer": consumer["username"],
                            "method": request["method"], "path": path, "query": query, "status": response["status"],
                            "source_digest": hashlib.sha256(line).hexdigest()})
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue
    return records


def _object_without_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _status_matches_policy(method: str, status: object) -> bool:
    return type(status) is int and ((method == "GET" and 200 <= status < 300)
                                    or (method == "POST" and 400 <= status < 500))


def _response_receipt(request_id: str, status: object, response: bytes) -> str:
    """Digest a bounded response without allowing malformed status metadata to reopen it."""
    try:
        safe_status = json.loads(json.dumps(status, sort_keys=True, separators=(",", ":"), allow_nan=False))
    except (TypeError, ValueError, OverflowError, RecursionError):
        safe_status = {"invalid_status_type": f"{type(status).__module__}.{type(status).__qualname__}"}
    return hashlib.sha256(json.dumps({"request_id": request_id, "status": safe_status,
                                      "body_sha256": hashlib.sha256(response[:RESPONSE_CAP]).hexdigest()},
                                     sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def execute(spec: RequestSpec, approval, *, public_key, store: RequestStore, transport: Transport,
            executor_secret: str) -> dict:
    assert_exact_origin(); validate_spec(spec)
    from .charter_approval import CharterApproval
    if isinstance(approval, dict): approval = CharterApproval(**approval)
    # Historical observed rows represent the old non-atomic gap.  They may only be
    # resolved by an authorized recovery process, never by re-running the request.
    store.refuse_observed(spec.request_id)
    store.authorize_prepare(spec, approval, public_key)
    # This is the revocation/dispatch linearization point. A durable revoke before it prevents
    # OAuth mint and target dispatch; after it, the executor records the revoke but cannot lie
    # about cancelling a possibly in-flight request.
    store.dispatch_if_not_revoked(spec.request_id)
    try:
        token = transport.mint(ORIGIN, executor_secret)
    except Exception as exc:
        store._transition(spec.request_id, "terminal")
        raise CharterRequestError("OAuth mint failed") from exc
    try:
        observation = transport.request(ORIGIN + spec.path + (("?" + spec.query) if spec.query else ""), spec.method,
                                        dict(spec.headers) | {"Authorization": "Bearer " + token,
                                                              "X-Sentinel-Request-ID": spec.request_id},
                                        spec.body, TIMEOUT_SECONDS, RESPONSE_CAP)
    except Exception as exc:
        store.unknown(spec.request_id)
        raise CharterRequestError("request outcome unknown") from exc
    if not isinstance(observation, ResponseObservation):
        store.unknown(spec.request_id)
        raise CharterRequestError("invalid transport response")
    status, response = observation.status, observation.body
    if type(response) is not bytes or len(response) > RESPONSE_CAP:
        store.unknown(spec.request_id)
        raise CharterRequestError("response exceeds charter cap")
    receipt = _response_receipt(spec.request_id, status, response)
    store.terminalize_response(spec.request_id, receipt)
    if type(status) is not int:
        raise CharterRequestError("invalid transport status")
    if not _status_matches_policy(spec.method, status):
        raise CharterRequestError("response outside charter policy")
    if spec.method == "POST":
        return {"request_id": spec.request_id, "status": status, "bytes": len(response),
                "receipt_digest": receipt, "post_expected_4xx": True}

    from .charter_response_guard import guard_response_preview
    guarded = guard_response_preview(response, observation.content_types)
    common = {"schema_version": "sentinel-charter-receipt/v2", "request_id": spec.request_id,
              "status": status, "bytes": len(response), "receipt_digest": receipt}
    if guarded.status == "accepted":
        assert guarded.preview is not None and guarded.preview_truncated is not None
        return common | {"preview": guarded.preview, "preview_truncated": guarded.preview_truncated}
    return common | {"quarantine": guarded.quarantine}
