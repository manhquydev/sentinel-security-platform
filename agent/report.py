"""Grounded charter report construction from typed normalized findings only."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable

from .charter_contracts import AnalysisFailure, NormalizedFinding, ReportFinding, write_jsonl_atomic
from .pii import scrub


@dataclass(frozen=True)
class KnowledgeItem:
    content: str
    provenance: str


@dataclass(frozen=True)
class ReportResult:
    records: list[ReportFinding]
    failure: AnalysisFailure | None = None


def _failure(code: str, message: str) -> ReportResult:
    return ReportResult([], AnalysisFailure(code=code, message=message))


def _enrichments(payload: str, findings: dict[str, NormalizedFinding]) -> dict[str, dict] | None:
    try:
        values = json.loads(payload)
    except (TypeError, json.JSONDecodeError):
        return None
    # The live transport requests a JSON-schema object wrapper.  Keep accepting the
    # historical bare array for deterministic callers/tests, but never accept any
    # other outer fields or model-authored facts.
    if isinstance(values, dict):
        if set(values) != {"enrichments"}:
            return None
        values = values["enrichments"]
    if not isinstance(values, list):
        return None
    result: dict[str, dict] = {}
    for value in values:
        if not isinstance(value, dict) or set(value) != {
                "finding_id", "explanation_mode", "remediation_mode", "confidence"}:
            return None
        finding_id = value.get("finding_id")
        if finding_id not in findings or finding_id in result:
            return None
        if value.get("confidence") not in {"low", "medium", "high"}:
            return None
        if (value.get("explanation_mode") != "scanner-observation"
                or value.get("remediation_mode") != "review-documented-fix"):
            return None
        result[finding_id] = value
    return result if set(result) == set(findings) else None


def build_grounded_report(
    findings: Iterable[NormalizedFinding], knowledge: Iterable[KnowledgeItem] | None,
    model_output: str, output_path: str | None = None,
) -> ReportResult:
    """Validate model prose against fixed fact IDs and atomically publish only on full success."""
    typed = list(findings)
    if not typed:
        return _failure("empty-input", "no typed findings are available for analysis")
    context = list(knowledge or [])
    if (not context or not all(isinstance(item, KnowledgeItem) for item in context)
            or any(not item.content.strip() or not item.provenance.strip() for item in context)):
        return _failure("knowledge-unavailable", "retrieval returned no content with provenance")
    additions = _enrichments(model_output, {finding.finding_id: finding for finding in typed})
    if additions is None:
        return _failure("model-output-invalid", "model output did not match the allowed explanatory schema")
    provenance = sorted({scrub(item.provenance) or "[redacted]" for item in context})
    records: list[ReportFinding] = []
    for finding in sorted(typed, key=lambda item: item.finding_id):
        addition = additions[finding.finding_id]
        # The model selects only reviewable modes and confidence. These fixed code projections
        # contain no facts except the already-typed scanner title/location/evidence, so an
        # arbitrary model phrase cannot establish a new vulnerability, endpoint, CWE, or proof.
        explanation = (
            f"The scanner reported '{finding.title}' at the listed location. "
            "This report preserves that scanner observation and does not infer an additional issue.")
        remediation = (
            f"Review the scanner evidence and retrieved documentation for '{finding.title}', "
            "apply the documented fix, then verify it in the sandbox.")
        records.append(ReportFinding(
            finding_id=finding.finding_id, name=finding.title, severity=finding.severity,
            location=finding.location, scanner_evidence=finding.evidence,
            explanation=scrub(explanation) or "[redacted]",
            remediation=scrub(remediation) or "[redacted]",
            confidence=addition["confidence"], source_ids=finding.source_ids,
            knowledge_provenance=provenance,
        ))
    if output_path:
        write_jsonl_atomic(output_path, records)
    return ReportResult(records)
