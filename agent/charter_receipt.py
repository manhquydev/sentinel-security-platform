"""Exact metadata contracts for the isolated charter executor receipt boundary."""
from __future__ import annotations

import json
import re
from typing import Any, Protocol

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_RESULT_FIELDS = {"request_id", "status", "bytes", "receipt_digest", "post_expected_4xx"}
_V1_FIELDS = {"schema_version", "request_id", "status", "bytes", "receipt_digest"}
_V2_ACCEPTED_FIELDS = _V1_FIELDS | {"preview", "preview_truncated"}
_V2_QUARANTINE_FIELDS = _V1_FIELDS | {"quarantine"}
AUDIT_SOURCE = "docker-logs-sentinel-kong"
_AUDIT_V1_FIELDS = {
    "schema_version", "request_id", "status", "started_at", "manifest_created_at_ms",
    "recovery_started_at_ms", "source", "source_digest",
}
_QUARANTINE_CODES = frozenset((
    "media-missing", "media-duplicate", "media-malformed", "media-unsupported", "decode-invalid-utf8",
    "objective-change", "secret-disclosure", "out-of-scope-tool",
    "pii-card", "pii-phone", "pii-email", "pii-jwt", "pii-uuid",
))


class ReceiptContractError(ValueError):
    """Untrusted executor metadata does not satisfy the sealed receipt contract."""


class _RequestSpec(Protocol):
    request_id: str
    method: str


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReceiptContractError("duplicate JSON object key")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ReceiptContractError(f"invalid JSON constant: {value}")


def decode_object(raw: bytes) -> dict[str, Any]:
    """Decode one strict UTF-8 JSON object, rejecting duplicate keys at every level."""
    if type(raw) is not bytes:
        raise ReceiptContractError("metadata must be UTF-8 bytes")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object_without_duplicate_keys,
                           parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ReceiptContractError) as exc:
        raise ReceiptContractError("invalid JSON metadata") from exc
    if not isinstance(value, dict):
        raise ReceiptContractError("metadata must be a JSON object")
    return value


decode_json_object = decode_object


def _validated_context(spec: _RequestSpec) -> tuple[str, str]:
    request_id, method = getattr(spec, "request_id", None), getattr(spec, "method", None)
    if not isinstance(request_id, str) or not request_id or method not in {"GET", "POST"}:
        raise ReceiptContractError("invalid immutable request context")
    return request_id, method


def _validate_common(value: object, fields: set[str], spec: _RequestSpec, *, method: str | None = None) -> tuple[str, int, int, str, str]:
    request_id, immutable_method = _validated_context(spec)
    if method is not None and immutable_method != method:
        raise ReceiptContractError("metadata violates immutable method policy")
    if not isinstance(value, dict) or set(value) != fields:
        raise ReceiptContractError("metadata has wrong fields")
    actual_id, status, byte_count, digest = (value.get("request_id"), value.get("status"),
                                               value.get("bytes"), value.get("receipt_digest"))
    if (type(actual_id) is not str or actual_id != request_id or type(status) is not int
            or type(byte_count) is not int or not 0 <= byte_count <= 65536
            or type(digest) is not str or not _DIGEST.fullmatch(digest)):
        raise ReceiptContractError("metadata has invalid identity, status, bytes, or digest")
    if (immutable_method == "GET" and not 200 <= status < 300) or (immutable_method == "POST" and not 400 <= status < 500):
        raise ReceiptContractError("metadata status violates immutable request policy")
    return actual_id, status, byte_count, digest, immutable_method


def _validated_preview(value: object) -> str:
    if type(value) is not str:
        raise ReceiptContractError("receipt preview must be text")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise ReceiptContractError("receipt preview must be valid UTF-8") from exc
    if len(encoded) > 512 or len(value) > 256:
        raise ReceiptContractError("receipt preview exceeds approved limit")
    return value


def _validated_quarantine(value: object) -> dict[str, int]:
    if not isinstance(value, dict) or not value:
        raise ReceiptContractError("receipt quarantine is empty or invalid")
    if any(type(key) is not str or key not in _QUARANTINE_CODES or type(count) is not int or not 1 <= count <= 65536
           for key, count in value.items()):
        raise ReceiptContractError("receipt quarantine has invalid reason count")
    return dict(value)


def _validate_v2(value: object, spec: _RequestSpec) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != "sentinel-charter-receipt/v2":
        raise ReceiptContractError("receipt has an unknown schema version")
    fields = set(value)
    if fields == _V2_ACCEPTED_FIELDS:
        request_id, status, byte_count, digest, _ = _validate_common(value, _V2_ACCEPTED_FIELDS, spec, method="GET")
        preview = _validated_preview(value["preview"])
        if type(value["preview_truncated"]) is not bool:
            raise ReceiptContractError("receipt preview truncation marker is invalid")
        return {"schema_version": "sentinel-charter-receipt/v2", "request_id": request_id, "status": status,
                "bytes": byte_count, "receipt_digest": digest, "preview": preview,
                "preview_truncated": value["preview_truncated"]}
    if fields == _V2_QUARANTINE_FIELDS:
        request_id, status, byte_count, digest, _ = _validate_common(value, _V2_QUARANTINE_FIELDS, spec, method="GET")
        return {"schema_version": "sentinel-charter-receipt/v2", "request_id": request_id, "status": status,
                "bytes": byte_count, "receipt_digest": digest, "quarantine": _validated_quarantine(value["quarantine"])}
    raise ReceiptContractError("receipt v2 has wrong fields")


def validate_adapter_result(value: object, spec: _RequestSpec) -> dict[str, Any]:
    """Accept a strict GET v2 receipt candidate or the legacy POST result only."""
    if isinstance(value, dict) and value.get("schema_version") == "sentinel-charter-receipt/v2":
        return _validate_v2(value, spec)
    request_id, status, byte_count, digest, method = _validate_common(value, _RESULT_FIELDS, spec, method="POST")
    assert isinstance(value, dict)
    if type(value["post_expected_4xx"]) is not bool or value["post_expected_4xx"] is not True:
        raise ReceiptContractError("executor result has invalid POST policy flag")
    return {"request_id": request_id, "status": status, "bytes": byte_count,
            "receipt_digest": digest, "post_expected_4xx": method == "POST"}


def validate_receipt(value: object, spec: _RequestSpec) -> dict[str, Any]:
    """Validate an exact v1 legacy receipt or one exact GET v2 receipt."""
    if isinstance(value, dict) and value.get("schema_version") == "sentinel-charter-receipt/v2":
        return _validate_v2(value, spec)
    request_id, status, byte_count, digest, _ = _validate_common(value, _V1_FIELDS, spec)
    assert isinstance(value, dict)
    if type(value["schema_version"]) is not str or value["schema_version"] != "sentinel-charter-receipt/v1":
        raise ReceiptContractError("receipt has an unknown schema version")
    return {"schema_version": "sentinel-charter-receipt/v1", "request_id": request_id,
            "status": status, "bytes": byte_count, "receipt_digest": digest}


def validate_audit(value: object, spec: _RequestSpec) -> dict[str, Any]:
    """Validate the distinct, response-free Kong transit/status recovery artifact."""
    request_id, method = _validated_context(spec)
    if not isinstance(value, dict) or set(value) != _AUDIT_V1_FIELDS:
        raise ReceiptContractError("audit has wrong fields")
    if value.get("schema_version") != "sentinel-charter-audit/v1":
        raise ReceiptContractError("audit has an unknown schema version")
    status, started_at, manifest_created_at_ms, recovery_started_at_ms, source, digest = (
        value.get("status"), value.get("started_at"), value.get("manifest_created_at_ms"),
        value.get("recovery_started_at_ms"), value.get("source"), value.get("source_digest"),
    )
    if (value.get("request_id") != request_id or type(status) is not int
            or (method == "GET" and not 200 <= status < 300)
            or (method == "POST" and not 400 <= status < 500)
            or type(started_at) is not int or started_at < 0
            or type(manifest_created_at_ms) is not int or manifest_created_at_ms < 0
            or type(recovery_started_at_ms) is not int or recovery_started_at_ms < manifest_created_at_ms
            or not manifest_created_at_ms <= started_at <= recovery_started_at_ms
            or source != AUDIT_SOURCE
            or type(digest) is not str or not _DIGEST.fullmatch(digest)):
        raise ReceiptContractError("audit has invalid gateway transit metadata")
    return {
        "schema_version": "sentinel-charter-audit/v1",
        "request_id": request_id,
        "status": status,
        "started_at": started_at,
        "manifest_created_at_ms": manifest_created_at_ms,
        "recovery_started_at_ms": recovery_started_at_ms,
        "source": AUDIT_SOURCE,
        "source_digest": digest,
    }
