from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from workbench.active_approval import ActiveApprovalViolation, approval_payload, verify_approval
from workbench.active_request_store import ActiveRequestStore, ActiveRequestViolation


def document():
    return {
        "profile_id": "cmc-local",
        "snapshot_id": "a" * 64,
        "catalog_id": "cmc-edu-v1",
        "request_digest": "b" * 64,
        "operator_id": "operator",
        "nonce": "nonce-1",
        "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
    }


def test_ed25519_approval_binds_request_and_exactly_once_reservation(tmp_path):
    private = Ed25519PrivateKey.generate()
    value = document()
    signature = base64.b64encode(private.sign(approval_payload(value))).decode()
    public = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    assert verify_approval(
        value,
        signature_b64=signature,
        public_key_b64=public,
        expected_request_digest="b" * 64,
        now=datetime.now(UTC),
    )["nonce"] == "nonce-1"
    store = ActiveRequestStore(tmp_path / "private" / "requests.sqlite")
    store.reserve(request_digest="b" * 64, nonce="nonce-1")
    with pytest.raises(ActiveRequestViolation):
        store.reserve(request_digest="b" * 64, nonce="nonce-1")
    store.revoke("b" * 64)
    with pytest.raises(ActiveRequestViolation):
        store.mark_dispatched("b" * 64)


def test_approval_rejects_request_mismatch_or_expiry():
    private = Ed25519PrivateKey.generate()
    value = document()
    value["expires_at"] = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    signature = base64.b64encode(private.sign(approval_payload(value))).decode()
    public = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    with pytest.raises(ActiveApprovalViolation):
        verify_approval(
            value,
            signature_b64=signature,
            public_key_b64=public,
            expected_request_digest="c" * 64,
            now=datetime.now(UTC),
        )
