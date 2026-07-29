"""Nuclei-sanitized JSONL -> complete, typed Sentinel charter findings."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from .charter_contracts import AnalysisFailure, ContractResult, NormalizedFinding
from .pii import scrub

_SEVERITIES = {
    "critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info",
}
_ORIGIN = "http://127.0.0.1:13000"
_REDACTION_TOKEN = re.compile(r"\[redacted:[^\]]+\]")


def _failure(code: str, message: str, line: int | None = None) -> ContractResult:
    return ContractResult([], AnalysisFailure(code=code, message=message, line=line))


def _safe_location(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("matched-at must be a string")
    if "?" in value or "#" in value or "%" in value:
        raise ValueError("matched-at contains a non-canonical delimiter or escape")
    parsed = urlsplit(value)
    if (parsed.scheme, parsed.hostname, parsed.port, parsed.username, parsed.password,
            parsed.query, parsed.fragment) != ("http", "127.0.0.1", 13000, None, None, "", ""):
        raise ValueError("matched-at is not the sanitized charter origin")
    if not parsed.path.startswith("/"):
        raise ValueError("matched-at path is invalid")
    return _ORIGIN + parsed.path


def _cwe(value: object) -> int | None:
    if value in (None, "", []):
        return None
    values = value if isinstance(value, list) else [value]
    found: set[int] = set()
    for item in values:
        digits = "".join(ch for ch in str(item) if ch.isdigit())
        if digits:
            found.add(int(digits))
    if len(found) > 1:
        raise ValueError("multiple CWE values are unsupported")
    return next(iter(found), None)


def _record(row: object, line: int) -> NormalizedFinding:
    if not isinstance(row, dict):
        raise ValueError("record must be an object")
    if row.get("type") != "http":
        raise ValueError("only sanitized HTTP Nuclei records are supported")
    template_id = row.get("template-id")
    info = row.get("info")
    if not isinstance(template_id, str) or not template_id or not isinstance(info, dict):
        raise ValueError("template-id and info are required")
    name = info.get("name")
    severity_raw = info.get("severity")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("info.name is required")
    if not isinstance(severity_raw, str) or severity_raw.lower() not in _SEVERITIES:
        raise ValueError("info.severity is unknown")
    location = _safe_location(row.get("matched-at"))
    classification = info.get("classification") or {}
    if not isinstance(classification, dict):
        raise ValueError("info.classification must be an object")
    clean_name = scrub(name) or ""
    if not _REDACTION_TOKEN.sub("", clean_name).strip():
        raise ValueError("finding title contained no non-sensitive content after sanitization")
    matcher = row.get("matcher-name")
    evidence = [f"template-id={scrub(template_id)}"]
    if isinstance(matcher, str) and matcher:
        evidence.append(f"matcher-name={scrub(matcher)}")
    # The source id is a digest over the already-sanitized row, so it is deterministic without
    # copying raw scanner authority or response content into the report.
    canonical = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    source_id = f"nuclei:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}:line:{line}"
    finding_key = json.dumps({"title": scrub(name), "severity": _SEVERITIES[severity_raw.lower()],
                              "location": location, "cwe": _cwe(classification.get("cwe-id"))},
                             sort_keys=True, separators=(",", ":"))
    return NormalizedFinding(
        finding_id="finding:" + hashlib.sha256(finding_key.encode("utf-8")).hexdigest(),
        source_ids=[source_id], tool="nuclei", scanner="DAST", title=clean_name,
        severity=_SEVERITIES[severity_raw.lower()], cwe=_cwe(classification.get("cwe-id")),
        location=location, evidence=list(dict.fromkeys(evidence)),
    )


def normalize_sanitized_jsonl(path: str | Path) -> ContractResult:
    """Validate all input before returning records; failure never yields a partial result."""
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return _failure("malformed-input", "sanitized input could not be read")
    if not lines or not any(line.strip() for line in lines):
        return _failure("empty-input", "sanitized input contained no findings")
    parsed: list[NormalizedFinding] = []
    for number, raw in enumerate(lines, start=1):
        if not raw.strip():
            return _failure("malformed-input", "blank JSONL lines are not permitted", number)
        try:
            parsed.append(_record(json.loads(raw), number))
        except json.JSONDecodeError:
            return _failure("malformed-input", "invalid JSONL", number)
        except (TypeError, ValueError) as exc:
            return _failure("invalid-record", str(exc), number)

    grouped: dict[str, NormalizedFinding] = {}
    for record in parsed:
        old = grouped.get(record.finding_id)
        if old is None:
            grouped[record.finding_id] = record
            continue
        grouped[record.finding_id] = old.model_copy(update={
            "source_ids": sorted(set(old.source_ids + record.source_ids)),
            "evidence": sorted(set(old.evidence + record.evidence)),
        })
    return ContractResult(sorted(grouped.values(), key=lambda item: item.finding_id))
