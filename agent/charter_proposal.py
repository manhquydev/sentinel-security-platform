"""Typed bridge from grounded charter findings to the fixed Phase-3 policy."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .charter_contracts import ReportFinding
from .charter_requests import RequestSpec, make_spec, safe_request_case

_WEEK3_SCHEMA = "week3-analysis/v1"
_CHARTER_REPORT_SCHEMA = "1.0"


@dataclass(frozen=True)
class RequestProposal:
    available: bool
    finding_ids: tuple[str, ...]
    method: str = ""
    path: str = ""
    query: str = ""
    body: str = ""
    case_id: str = ""
    reason: str = ""

    def to_spec(self, run_id: str) -> RequestSpec:
        if not self.available:
            raise ValueError("proposal unavailable")
        case = safe_request_case(self.case_id)
        return make_spec(
            run_id=run_id,
            method=case.method,
            path=case.path,
            query=case.query,
            body=case.body,
            headers=dict(case.headers),
            case_id=case.case_id,
        )


def propose(findings: Iterable[object], *, request_kind: str = "get") -> RequestProposal:
    rows = list(findings)
    ids: list[str] = []
    for row in rows:
        # A ReportFinding is only constructed after the normalized scanner fact IDs,
        # allowed LLM enrichment shape, and retrieval provenance have all validated.
        # The old, nonexistent `grounded` attribute rejected every real report here.
        if not isinstance(row, ReportFinding):
            return RequestProposal(False, (), reason="unsupported evidence")
        ids.append(row.finding_id)
    if not ids:
        return RequestProposal(False, (), reason="no grounded findings")
    aliases = {"get": "get-baseline", "post": "post-empty-object"}
    case_id = aliases.get(request_kind, request_kind)
    try:
        case = safe_request_case(case_id)
    except Exception:
        return RequestProposal(False, tuple(ids), reason="unsupported fixed policy")
    return RequestProposal(
        available=True,
        finding_ids=tuple(ids),
        case_id=case.case_id,
        method=case.method,
        path=case.path,
        query=case.query,
        body=case.body,
    )


def _project_week3_report_finding(payload: dict) -> ReportFinding:
    """Validate a Week-3 analysis row, then keep only grounded report fields."""
    # Local import keeps the proposal bridge free of week3 module import cost for the
    # common charter-report path, and avoids any accidental package cycles.
    from .week3_analysis import Week3ReportFinding

    week3 = Week3ReportFinding.model_validate(payload)
    return ReportFinding(
        finding_id=week3.finding_id,
        name=week3.name,
        severity=week3.severity,
        location=week3.location,
        scanner_evidence=list(week3.scanner_evidence),
        explanation=week3.explanation,
        remediation=week3.remediation,
        confidence=week3.confidence,
        source_ids=list(week3.source_ids),
        knowledge_provenance=list(week3.knowledge_provenance),
    )


def _load_grounded_report_rows(path: str | Path) -> list[ReportFinding]:
    """Load a grounded report JSONL through the strict type for its schema.

    Supported schemas:
    - charter report ``1.0`` (``ReportFinding``)
    - week3 analysis ``week3-analysis/v1`` (validated then projected)

    Any parse or validation error fails the entire file; partial loads never escape.
    """
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError("invalid grounded report") from exc

    rows: list[ReportFinding] = []
    try:
        for line in lines:
            if not line.strip():
                continue
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise ValueError("report row must be an object")
            schema = payload.get("schema_version")
            if schema == _WEEK3_SCHEMA:
                rows.append(_project_week3_report_finding(payload))
            elif schema == _CHARTER_REPORT_SCHEMA or schema is None:
                # Charter rows use schema_version="1.0". A missing key is accepted by
                # ReportFinding's default; explicit null or any other literal fails
                # validation. model_validate still enforces extra=forbid and field types.
                rows.append(ReportFinding.model_validate(payload))
            else:
                raise ValueError(f"unsupported report schema_version {schema!r}")
    except Exception as exc:
        raise ValueError("invalid grounded report") from exc
    return rows


def propose_report_jsonl(path: str | Path, *, request_kind: str = "get") -> RequestProposal:
    """Load a persisted grounded report through its strict type before proposing.

    Accepts charter ``ReportFinding`` JSONL and Week-3 analysis JSONL. A JSON
    object merely shaped like a report is not enough: the loader forbids extra
    fields for the declared schema and the proposal path receives only validated
    ``ReportFinding`` instances. Request path/query/body always come from the
    fixed SAFE_REQUEST catalog, never from finding locations.
    """
    rows = _load_grounded_report_rows(path)
    return propose(rows, request_kind=request_kind)
