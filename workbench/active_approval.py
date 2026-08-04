"""Purpose-bound Ed25519 approval validation for the optional CMC smoke request."""
from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class ActiveApprovalViolation(ValueError):
    """Raised when a CMC approval is expired, malformed, or mismatched."""


_FIELDS = {
    "profile_id",
    "snapshot_id",
    "catalog_id",
    "request_digest",
    "operator_id",
    "nonce",
    "expires_at",
}


def approval_payload(document: Mapping[str, object]) -> bytes:
    if set(document) != _FIELDS or not all(isinstance(document[field], str) and document[field] for field in _FIELDS):
        raise ActiveApprovalViolation("CMC approval payload has an invalid shape")
    return json.dumps(dict(document), sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_approval(
    document: Mapping[str, object],
    *,
    signature_b64: str,
    public_key_b64: str,
    expected_request_digest: str,
    now: datetime,
) -> dict[str, str]:
    payload = approval_payload(document)
    if document["request_digest"] != expected_request_digest:
        raise ActiveApprovalViolation("CMC approval is bound to a different request")
    try:
        expiry = datetime.fromisoformat(str(document["expires_at"]))
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64, validate=True))
        signature = base64.b64decode(signature_b64, validate=True)
        key.verify(signature, payload)
    except (ValueError, InvalidSignature) as error:
        raise ActiveApprovalViolation("CMC approval signature is invalid") from error
    if expiry.tzinfo is None or expiry.astimezone(UTC) <= now.astimezone(UTC):
        raise ActiveApprovalViolation("CMC approval has expired")
    return {field: str(document[field]) for field in _FIELDS}
