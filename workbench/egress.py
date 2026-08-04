"""Fail-closed B3-only source egress and response quarantine boundary."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Any, Mapping

from agent import pii
from infra.litellm.guardrails import egress_redaction
from .analysis_population import AnalysisPopulationViolation, SelectionManifest


class EgressViolation(ValueError):
    """Raised when a B3 source dispatch or response cannot remain no-trace."""


_CONTEXT_CAP = 8192
_ROUTE_KEYS = {
    "route_id",
    "stream",
    "message_body_logging",
    "callbacks",
    "shared_trace_network",
}
_UNIT_ID_MAXIMUM = 256


@dataclass(frozen=True)
class PreparedB3Request:
    prompt: str
    record: dict[str, object]


@dataclass(frozen=True)
class QuarantinedResponse:
    proposal_ids: tuple[str, ...]
    record: dict[str, object]


@dataclass(frozen=True)
class B3Route:
    """A host-owned no-trace route descriptor with no serializable credential."""

    route_id: str
    _authority_token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._authority_token is not _ROUTE_AUTHORITY:
            raise EgressViolation("B3 route must be issued by the host deployment authority")
        _validate_route(self.to_mapping())

    def to_mapping(self) -> dict[str, object]:
        return {
            "route_id": self.route_id,
            "stream": False,
            "message_body_logging": False,
            "callbacks": [],
            "shared_trace_network": False,
        }

    @classmethod
    def from_host_config(
        cls,
        *,
        route_id: str,
        key_path: Path | str,
        config_digest: str,
        expected_config_digest: str,
    ) -> "B3Route":
        if route_id != "workbench-b3-no-trace" or config_digest != expected_config_digest:
            raise EgressViolation("B3 route identity/configuration is not the frozen dedicated deployment")
        _read_scoped_key(key_path)
        return cls(route_id, _ROUTE_AUTHORITY)


_ROUTE_AUTHORITY = object()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_route(route: Mapping[str, object]) -> None:
    if set(route) != _ROUTE_KEYS:
        raise EgressViolation("B3 route must use the exact no-trace configuration shape")
    if not isinstance(route["route_id"], str) or not route["route_id"]:
        raise EgressViolation("B3 route must be labelled")
    if route["stream"] is not False or route["message_body_logging"] is not False:
        raise EgressViolation("B3 route must disable streaming and message-body logging")
    if route["callbacks"] != [] or route["shared_trace_network"] is not False:
        raise EgressViolation("B3 route must have no callbacks or shared trace network")


def _read_scoped_key(key_path: Path | str) -> str:
    """Read a restricted key only for a host-private transport factory."""
    path = Path(key_path).resolve()
    try:
        details = path.lstat()
        key = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise EgressViolation("B3 scoped key file is unreadable") from error
    if (
        details.st_mode & 0o077
        or details.st_mode & 0o111
        or not details.st_mode & 0o400
        or not key
        or any(word in key.lower() for word in ("master", "admin", "unscoped", "fallback"))
    ):
        raise EgressViolation("B3 key is not a private restricted virtual key")
    return key


def prepare_b3_request(
    *,
    selection: SelectionManifest,
    unit_id: str,
    route: B3Route,
) -> PreparedB3Request:
    """Create an egress-safe request; metadata records deliberately omit source."""
    if (
        not isinstance(selection, SelectionManifest)
        or not selection.is_authorized()
        or not isinstance(unit_id, str)
        or not unit_id
    ):
        raise EgressViolation("B3 dispatch requires a host-owned sealed selection and unit ID")
    if not isinstance(route, B3Route) or route._authority_token is not _ROUTE_AUTHORITY:
        raise EgressViolation("B3 dispatch requires a host-owned no-trace route")
    try:
        canonical_unit, dependency_context = selection.slice_for(unit_id)
    except AnalysisPopulationViolation as error:
        raise EgressViolation("B3 request unit is outside the sealed selection frame") from error
    if len(dependency_context.encode("utf-8")) > _CONTEXT_CAP:
        raise EgressViolation("B3 sealed dependency context exceeds its frozen byte cap")
    try:
        secret_redacted, secret_findings = egress_redaction.redact(canonical_unit + "\n" + dependency_context)
        pii_redacted, pii_findings = pii.redact(secret_redacted)
    except Exception as error:
        raise EgressViolation("B3 source redaction failed closed") from error
    if any(not isinstance(finding, Mapping) or finding.get("redacted") is not True for finding in secret_findings):
        raise EgressViolation("B3 source contains unredacted credential-like material")
    if not isinstance(pii_redacted, str):
        raise EgressViolation("B3 redaction yielded an invalid source body")
    prompt = (
        "Analyze exactly this redacted canonical unit and optional sealed dependency context. "
        "Return structured proposal IDs only.\n<unit>\n"
        + pii_redacted
        + "\n</unit>"
    )
    record = {
        "schema_version": "sentinel-workbench-egress-record/v1",
        "route_id": route.route_id,
        "request_digest": _digest(prompt),
        "selection_manifest_digest": selection.digest,
        "unit_id": unit_id,
        "canonical_unit_bytes": len(canonical_unit.encode("utf-8")),
        "dependency_context_bytes": len(dependency_context.encode("utf-8")),
        "redaction_summary": {
            "secret_findings": len(secret_findings),
            "pii_findings": len(pii_findings),
        },
        "stream": False,
    }
    return PreparedB3Request(prompt, record)


def quarantine_response(
    value: object,
    *,
    admitted_unit_ids: set[str] | frozenset[str],
) -> QuarantinedResponse:
    """Accept a narrow sanitized response schema and persist only its digest/metadata."""
    if not isinstance(value, Mapping) or set(value) != {"proposal_ids"}:
        raise EgressViolation("B3 provider response has an unexpected or raw field")
    proposals = value["proposal_ids"]
    if (
        not isinstance(proposals, list)
        or not all(isinstance(item, str) and item for item in proposals)
        or len(set(proposals)) != len(proposals)
        or any(len(item) > _UNIT_ID_MAXIMUM or any(character.isspace() for character in item) for item in proposals)
    ):
        raise EgressViolation("B3 provider response has an invalid sanitized shape")
    if not admitted_unit_ids or not set(proposals).issubset(admitted_unit_ids):
        raise EgressViolation("B3 provider response refers to a unit outside the admitted frame")
    serialized = json.dumps({"proposal_ids": proposals}, sort_keys=True, separators=(",", ":"))
    return QuarantinedResponse(
        tuple(proposals),
        {
            "schema_version": "sentinel-workbench-response-quarantine/v1",
            "response_digest": _digest(serialized),
            "proposal_count": len(proposals),
        },
    )
