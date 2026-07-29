"""Ed25519 envelopes only authenticate an operator decision; the executor owns consumption."""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DOMAIN = "sentinel-charter-approval/v1"


@dataclass(frozen=True)
class CharterApproval:
    decision_id: str
    decision: str
    request_id: str
    run_id: str
    spec_digest: str
    policy_digest: str
    issued_at: float
    expires_at: float
    nonce: str
    signature: str

    def payload(self) -> bytes:
        return json.dumps({"domain": DOMAIN, **asdict(self), "signature": ""},
                          sort_keys=True, separators=(",", ":")).encode()


def digest(spec) -> str:
    return hashlib.sha256(spec.canonical()).hexdigest()


def sign(spec, private: Ed25519PrivateKey, decision: str = "approve", ttl: int = 300) -> CharterApproval:
    if decision not in {"approve", "reject", "revoke"}:
        raise ValueError("invalid charter decision")
    now = time.time()
    unsigned = CharterApproval(uuid.uuid4().hex, decision, spec.request_id, spec.run_id, digest(spec),
                               spec.policy_digest, now, now + ttl, uuid.uuid4().hex, "")
    return CharterApproval(**{**asdict(unsigned), "signature": private.sign(unsigned.payload()).hex()})


def verify(approval: CharterApproval, spec, public: Ed25519PublicKey) -> bool:
    try:
        public.verify(bytes.fromhex(approval.signature), approval.payload())
        return (approval.decision in {"approve", "reject", "revoke"}
                and approval.request_id == spec.request_id and approval.run_id == spec.run_id
                and approval.spec_digest == digest(spec) and approval.policy_digest == spec.policy_digest
                and approval.expires_at > time.time() and approval.issued_at <= approval.expires_at)
    except Exception:
        return False
