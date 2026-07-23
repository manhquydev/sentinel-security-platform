"""findings.jsonl record shape, locked in docs/benchmark-pre-plan-decisions.md §QD2."""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass

logger = logging.getLogger(__name__)

SEVERITY_LEVELS = ("critical", "high", "medium", "low", "info")

_SARIF_LEVEL_TO_SEVERITY = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}


@dataclass
class Finding:
    finding_id: str
    run_id: str
    timestamp: str
    tool: str
    tool_version: str
    variant: str
    model: str
    rule_id: str
    title: str
    cwe: int | None
    severity: str
    file: str
    start_line: int
    end_line: int
    message: str
    stage_status: str
    confidence: float | None
    target: str
    sarif_ref: str
    owasp: str | None = None
    code_snippet: str | None = None
    target_test_case: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def compute_finding_id(tool: str, rule_id: str, file: str, start_line: int, end_line: int, cwe: int | None) -> str:
    """sha1 over a JSON-encoded tuple (not a delimited string) so a literal '|' in
    any field (most plausibly `file`, a URI) can never make two different tuples
    hash identically. cwe+end_line included so two findings on the same
    start_line with a different CWE or span never collide."""
    key = json.dumps([tool, rule_id, file, start_line, end_line, cwe])
    return hashlib.sha1(key.encode("utf-8")).hexdigest()


def normalize_severity(raw: str | None) -> str:
    """Map a tool-reported severity/SARIF level to the fixed severity vocabulary.
    Logs when a non-empty value doesn't match either known vocabulary, since that
    silently collapses to the lowest severity bucket otherwise."""
    if not raw:
        return "info"
    lowered = raw.strip().lower()
    if lowered in SEVERITY_LEVELS:
        return lowered
    if lowered in _SARIF_LEVEL_TO_SEVERITY:
        return _SARIF_LEVEL_TO_SEVERITY[lowered]
    logger.warning("unrecognized severity value %r; defaulting to 'info'", raw)
    return "info"


def parse_cwe(raw: str | int | None) -> int | None:
    """Accept 'CWE-89', 'CWE:89', '89', or an int; return int or None if unparseable."""
    if raw is None:
        return None
    if isinstance(raw, int):
        return raw
    digits = "".join(ch for ch in str(raw) if ch.isdigit())
    return int(digits) if digits else None
