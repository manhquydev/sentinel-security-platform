"""The Week-8 PR1 HITL approval-token machinery (RD1/RD3/RD4, docs/plans/active/2026-07-24-...).

This module is the graph-side (`agent/supervisor.py`) half of the approval gate: it can VERIFY a
signed token with an Ed25519 PUBLIC key, hash/identify a proposal, and append to the audit ledger
— and that is ALL it can do. It never imports `serialization.load_pem_private_key` for a private
key, never calls `.sign()`, and has no code path that accepts a private-key argument. Minting a
token (loading the PRIVATE key + signing) lives entirely in `agent/approve.py`, the separate
human-run CLI — this is the load-bearing split that makes self-approval structurally impossible
(RD1, red-team finding #3/F4): a compromised agent runtime that imports this module (as
`agent/supervisor.py` does) gains a verifier, not a signer.

Honest residual (documented, not solved here): on a single shared-user host, a fully-compromised
agent runtime could still scrape the private key file if an operator's shell history, environment,
or a co-located process exposed its path — this module's boundary stops the AGENT's own code from
reading it, not a host-level compromise. The durable production answer is a separate approval
user/service (deferred); Ed25519 verify-only is the right architecture on this host today.

Token = {proposal_id, proposal_hash, issued_at, ttl_seconds, nonce, signature}. `proposal_id` is
derived from the FACTS a proposal carries (`endpoint`/`vuln_class` — code-derived, never LLM
output, matching `agent/schema.py`'s own "facts by code" discipline for those two fields).
`proposal_hash` is a sha256 over the exact content a human reviewed before approving (facts +
narrative). Verification re-derives both from the CURRENT proposal and rejects a mismatch — a
token cannot be replayed against a different or tampered proposal (HA3).
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import trace

DEFAULT_TTL_SECONDS = 300
# How far into the future an `issued_at` may sit before it is rejected outright — guards against
# a token minted with a bogus future timestamp being treated as "not yet expired" indefinitely,
# while tolerating ordinary clock skew between the approver's machine and the agent host.
_CLOCK_SKEW_TOLERANCE_SECONDS = 5.0

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "out", "approval.sqlite")
DEFAULT_PUBKEY_PATH = os.path.join(os.path.dirname(__file__), "keys", "approver.pub")

# The proposal fields a signed token binds to. endpoint/vuln_class are code-derived facts
# (schema.py); technique/justification/expected_impact are the LLM narrative a human actually
# reads (and `agent/approve.py` displays) before deciding — all five together are "the exact
# reviewed proposal" the plan requires, so a runtime holding a genuine token cannot swap any
# human-visible field post-approval and still verify (security-audit M1).
_HASH_FIELDS = ("endpoint", "vuln_class", "technique", "justification", "expected_impact")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS consumed_nonces (
    nonce TEXT PRIMARY KEY,
    consumed_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    proposal_id TEXT NOT NULL,
    approver TEXT,
    decision TEXT,
    action TEXT NOT NULL,
    detail TEXT
);
"""


def proposal_id(proposal: dict[str, Any]) -> str:
    """Stable identifier for an ExploitProposal, derived ONLY from the code-derived fact fields
    (`endpoint`/`vuln_class` — never `technique`/`justification`, which are LLM narrative) so it
    cannot be spoofed by rephrasing the narrative."""
    return f"{proposal.get('endpoint', '')}::{proposal.get('vuln_class', '')}"


def proposal_content_hash(proposal: dict[str, Any]) -> str:
    """sha256 over the exact content a human reviews before approving. A unit-separator join
    (`\\x1f`, not bare concatenation) avoids a field-boundary collision — e.g. endpoint="ab"
    vuln_class="c" must hash differently from endpoint="a" vuln_class="bc"."""
    basis = "\x1f".join(str(proposal.get(f, "")) for f in _HASH_FIELDS)
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def canonical_payload(payload: dict[str, Any]) -> bytes:
    """Deterministic byte encoding of a token's signed fields — used IDENTICALLY by the signer
    (`agent/approve.py::sign_token`) and the verifier (`verify_approval` below) so a signature
    always covers exactly, and only, these five fields in a fixed order/encoding."""
    ordered = {k: payload[k] for k in
               ("proposal_id", "proposal_hash", "issued_at", "ttl_seconds", "nonce")}
    return json.dumps(ordered, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class ApprovalToken:
    proposal_id: str
    proposal_hash: str
    issued_at: float
    ttl_seconds: int
    nonce: str
    signature: str  # hex-encoded Ed25519 signature over canonical_payload(the other 5 fields)

    def to_dict(self) -> dict[str, Any]:
        return {"proposal_id": self.proposal_id, "proposal_hash": self.proposal_hash,
                "issued_at": self.issued_at, "ttl_seconds": self.ttl_seconds,
                "nonce": self.nonce, "signature": self.signature}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ApprovalToken":
        return cls(proposal_id=str(d["proposal_id"]), proposal_hash=str(d["proposal_hash"]),
                    issued_at=float(d["issued_at"]), ttl_seconds=int(d["ttl_seconds"]),
                    nonce=str(d["nonce"]), signature=str(d["signature"]))


def load_public_key(path: str = DEFAULT_PUBKEY_PATH) -> Ed25519PublicKey:
    """The only key-loading function this module exposes — deliberately PUBLIC-key-only. There is
    no `load_private_key` here; that lives in `agent/approve.py` alone (see module docstring)."""
    with open(path, "rb") as f:
        key = serialization.load_pem_public_key(f.read())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"{path} is not an Ed25519 public key")
    return key


class ApprovalLedger:
    """Append-only audit trail + single-use nonce consumption, backed by one SQLite file
    (`agent/out/approval.sqlite` by default — gitignored, like the LangGraph checkpoint). Both the
    human-run `agent/approve.py` CLI (records the human's Approve/Reject decision) and the graph's
    `state_change_node` (records the simulated action, and atomically consumes the token's nonce)
    write to the SAME ledger, so proposal -> approver -> decision -> action lands in one ordered
    trail. `audit_log` rows are only ever INSERTed here — never UPDATEd or DELETEd (RD4).

    Honest residual (security-audit M2, documented not solved — same candor as the private-key
    residual above): append-only is enforced BY CONVENTION (this class only ever INSERTs), not
    structurally. A fully-compromised runtime sharing this process/user could open the sqlite file
    directly and UPDATE/DELETE/DROP rows to erase a refusal — this defeats repudiation-resistance,
    though it still cannot make an unapproved action RUN. The durable production answer is a
    separate-user-owned / WORM append-only sink (e.g. an external log service the agent user can
    only append to), deferred with the rest of the real-execution cycle."""

    def __init__(self, path: str = DEFAULT_DB_PATH):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def consume_nonce(self, nonce: str) -> bool:
        """Atomically mark `nonce` used. Returns True the FIRST time a given nonce is consumed,
        False on every subsequent call (replay) — the sqlite PRIMARY KEY constraint (not an
        in-process lock) is what makes this atomic, so it holds even across separate processes
        sharing the same db file."""
        try:
            self._conn.execute(
                "INSERT INTO consumed_nonces (nonce, consumed_at) VALUES (?, ?)",
                (nonce, time.time()))
            self._conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def record(self, *, proposal_id: str, action: str, decision: str | None = None,
               approver: str | None = None, detail: str | None = None) -> None:
        """Append one audit row. `detail` is free text (e.g. a human rejection note, or this
        module's own "why refused" explanation) and is scrubbed through `trace.redact_persisted`
        before it is persisted — the same rule every other operator/LLM-adjacent narrative field
        in this repo follows (D5)."""
        self._conn.execute(
            "INSERT INTO audit_log (ts, proposal_id, approver, decision, action, detail) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (time.time(), proposal_id, approver, decision, action, trace.redact_persisted(detail)))
        self._conn.commit()

    def entries(self) -> list[dict[str, Any]]:
        """Full audit trail in insertion order — for tests/operators, never read by
        `state_change_node` itself (it only ever consumes a nonce / appends a row)."""
        cur = self._conn.execute(
            "SELECT id, ts, proposal_id, approver, decision, action, detail "
            "FROM audit_log ORDER BY id")
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def close(self) -> None:
        self._conn.close()


def verify_approval(token: dict[str, Any] | ApprovalToken, proposal: dict[str, Any],
                     pubkey: Ed25519PublicKey, ledger: ApprovalLedger) -> bool:
    """Fail-closed on ANY problem: malformed shape, bad signature, expired/not-yet-valid, a
    proposal-id/hash mismatch, or an already-consumed nonce all return False — this function never
    raises past its own boundary and never partially applies. Nonce consumption is the LAST check
    and only runs once every other check has already passed, so a token that fails verification
    for any other reason can be retried without burning the proposal's one real approval.

    Verifies with the PUBLIC key ONLY (RD1) — nothing in this call graph can mint a signature."""
    try:
        tok = token if isinstance(token, ApprovalToken) else ApprovalToken.from_dict(token)
    except (KeyError, TypeError, ValueError):
        return False

    try:
        signature = bytes.fromhex(tok.signature)
        pubkey.verify(signature, canonical_payload(tok.to_dict()))
    except (InvalidSignature, ValueError):
        return False

    now = time.time()
    if tok.issued_at > now + _CLOCK_SKEW_TOLERANCE_SECONDS:
        return False
    if now > tok.issued_at + tok.ttl_seconds:
        return False

    if tok.proposal_id != proposal_id(proposal) or tok.proposal_hash != proposal_content_hash(proposal):
        return False

    return ledger.consume_nonce(tok.nonce)
