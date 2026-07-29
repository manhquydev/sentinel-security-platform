"""Typed adapter for the CI's redacted Trivy JSON artifact.

This adapter deliberately accepts only the exact ``trivy-sanitized-json`` v1
handoff produced by the repository workflow.  It projects static scanner facts
into the common normalized-record schema; it does not invoke an LLM, import a
finding, or treat a filesystem finding as a Nuclei/HTTP observation.
"""
from __future__ import annotations

import hashlib
import json
import re
import argparse
import sys
from pathlib import Path
from typing import Any

from .charter_contracts import AnalysisFailure, ContractResult, NormalizedFinding, write_jsonl_atomic
from .pii import scrub


_SHA256 = re.compile(r"[0-9a-f]{64}")
_REDACTION = re.compile(r"\[redacted:(?:pii:[a-z]+|secret)\]")
_BARE_PHONE = re.compile(r"(?<!\d)(?:\+?\d[ .()\-]?){8,15}(?!\d)")
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)\b(?P<label>token|secret|api[_-]?key|password|authorization)\b\s*[:=]\s*\S+"
)
_SEVERITIES = {
    "critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "unknown": "Info",
}
_ROOT_FIELDS = {"SchemaVersion", "ArtifactName", "ArtifactType", "Results"}
_RESULT_FIELDS = {"Target", "Class", "Type", "Vulnerabilities", "Secrets", "Misconfigurations"}
_ISSUE_FIELDS = {
    "Vulnerabilities": {"VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "Title"},
    "Secrets": {"RuleID", "Category", "Severity", "Title", "StartLine", "EndLine"},
    "Misconfigurations": {"ID", "AVDID", "Title", "Description", "Severity", "Resolution", "Message"},
}


def _failure(code: str, message: str, line: int | None = None) -> ContractResult:
    return ContractResult([], AnalysisFailure(code=code, message=message, line=line))


def _safe_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    clean = scrub(value) or ""
    # Scanner titles/identifiers are target-derived. Unlike a port or a line
    # number (which are emitted structurally below), an unlabeled phone-shaped
    # value here has no safe operational meaning. Remove it conservatively.
    clean = _BARE_PHONE.sub("[redacted:pii:phone]", clean)
    clean = _CREDENTIAL_ASSIGNMENT.sub(lambda match: f"{match.group('label')}=[redacted:secret]", clean)
    # Redaction placeholders are safe to persist, but a field comprised only of
    # removed personal data is not useful scanner evidence.
    if not _REDACTION.sub("", clean).strip():
        raise ValueError(f"{label} contained no safe content")
    return clean


def _safe_location(value: object) -> str:
    target = _safe_text(value, "Target")
    if "\x00" in target or target.startswith("/") or "\\" in target:
        raise ValueError("Target must be a relative filesystem path")
    parts = target.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("Target path is not canonical")
    return f"file:{target}"


def _severity(value: object) -> str:
    if not isinstance(value, str) or value.lower() not in _SEVERITIES:
        raise ValueError("Severity is unknown")
    return _SEVERITIES[value.lower()]


def _integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _metadata(path: str | Path, artifact: bytes) -> AnalysisFailure | None:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return AnalysisFailure(code="metadata-mismatch", message="Trivy metadata could not be read")
    digest = hashlib.sha256(artifact).hexdigest()
    if (not isinstance(value, dict) or value != {
            "type": "trivy-sanitized-json", "version": "1", "sha256": digest,
    } or not _SHA256.fullmatch(value["sha256"])):
        return AnalysisFailure(code="metadata-mismatch", message="Trivy metadata type, version, or digest mismatched")
    return None


def _validate_root(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != _ROOT_FIELDS:
        raise ValueError("Trivy sanitized root schema mismatched")
    if value["SchemaVersion"] != 2:
        raise ValueError("Trivy SchemaVersion must be 2")
    _safe_text(value["ArtifactName"], "ArtifactName")
    if value["ArtifactType"] != "filesystem":
        raise ValueError("Trivy ArtifactType must be filesystem")
    results = value["Results"]
    if not isinstance(results, list) or not results:
        raise EOFError("Trivy sanitized report contained no results")
    if any(not isinstance(result, dict) for result in results):
        raise ValueError("Trivy Result must be an object")
    return results


def _issue_evidence(kind: str, issue: dict[str, Any]) -> list[str]:
    if kind == "Vulnerabilities":
        values = [("vulnerability-id", issue["VulnerabilityID"]), ("package", issue["PkgName"])]
        for key, output in (("InstalledVersion", "installed-version"), ("FixedVersion", "fixed-version")):
            if key in issue:
                values.append((output, issue[key]))
    elif kind == "Secrets":
        values = [("rule-id", issue["RuleID"])]
        if "Category" in issue:
            values.append(("category", issue["Category"]))
        if "StartLine" in issue or "EndLine" in issue:
            start = _integer(issue.get("StartLine"), "StartLine")
            end = _integer(issue.get("EndLine"), "EndLine")
            if end < start:
                raise ValueError("EndLine is before StartLine")
            values.append(("line-range", f"{start}-{end}"))
    else:
        values = [("id", issue["ID"])]
        if "AVDID" in issue:
            values.append(("avd-id", issue["AVDID"]))
    kind_name = {"Vulnerabilities": "vulnerability", "Secrets": "secret", "Misconfigurations": "misconfiguration"}[kind]
    evidence = [f"trivy-kind={kind_name}"]
    evidence.extend(f"{label}={_safe_text(raw, label)}" for label, raw in values)
    return list(dict.fromkeys(evidence))


def _record(result: dict[str, Any], kind: str, issue: object, result_index: int, issue_index: int) -> NormalizedFinding:
    if not isinstance(issue, dict) or not set(issue).issubset(_ISSUE_FIELDS[kind]):
        raise ValueError(f"Trivy {kind} schema mismatched")
    required = {
        "Vulnerabilities": {"VulnerabilityID", "PkgName", "Severity", "Title"},
        "Secrets": {"RuleID", "Severity", "Title"},
        "Misconfigurations": {"ID", "Severity", "Title"},
    }[kind]
    if not required.issubset(issue):
        raise ValueError(f"Trivy {kind} required field missing")
    title = _safe_text(issue["Title"], "Title")
    severity = _severity(issue["Severity"])
    location = _safe_location(result["Target"])
    evidence = _issue_evidence(kind, issue)
    canonical = json.dumps(
        {"tool": "trivy", "kind": kind, "title": title, "severity": severity,
         "location": location, "evidence": evidence}, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return NormalizedFinding(
        finding_id=f"finding:{digest}",
        source_ids=[f"trivy:{kind.lower()}:{result_index}:{issue_index}"],
        tool="trivy", scanner="SCA" if kind == "Vulnerabilities" else "SAST",
        title=title, severity=severity, location=location, evidence=evidence,
    )


def normalize_trivy_sanitized_json(artifact_path: str | Path, metadata_path: str | Path) -> ContractResult:
    """Return complete normalized Trivy records or one typed failure and no records."""
    try:
        artifact = Path(artifact_path).read_bytes()
    except OSError:
        return _failure("malformed-input", "Trivy sanitized artifact could not be read")
    metadata_failure = _metadata(metadata_path, artifact)
    if metadata_failure is not None:
        return ContractResult([], metadata_failure)
    try:
        root = json.loads(artifact.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _failure("malformed-input", "Trivy sanitized artifact was not JSON")
    try:
        results = _validate_root(root)
    except EOFError as exc:
        return _failure("empty-input", str(exc))
    except ValueError as exc:
        return _failure("invalid-record", str(exc))

    records: list[NormalizedFinding] = []
    try:
        for result_index, result in enumerate(results):
            if set(result) - _RESULT_FIELDS or not {"Target", "Class", "Vulnerabilities", "Secrets", "Misconfigurations"}.issubset(result):
                raise ValueError("Trivy Result schema mismatched")
            if not isinstance(result["Class"], str) or result["Class"] not in {"secret", "config", "lang-pkgs", "os-pkgs"}:
                raise ValueError("Trivy Result Class is unsupported")
            for kind in ("Vulnerabilities", "Secrets", "Misconfigurations"):
                entries = result[kind]
                if not isinstance(entries, list):
                    raise ValueError(f"Trivy {kind} must be a list")
                for issue_index, issue in enumerate(entries):
                    records.append(_record(result, kind, issue, result_index, issue_index))
    except ValueError as exc:
        return _failure("invalid-record", str(exc))
    if not records:
        return _failure("empty-input", "Trivy sanitized artifact contained no findings")

    grouped: dict[str, NormalizedFinding] = {}
    for record in records:
        prior = grouped.get(record.finding_id)
        grouped[record.finding_id] = record if prior is None else prior.model_copy(update={
            "source_ids": sorted(set(prior.source_ids + record.source_ids)),
            "evidence": sorted(set(prior.evidence + record.evidence)),
        })
    return ContractResult(sorted(grouped.values(), key=lambda record: record.finding_id))


def normalize_trivy_sanitized_to_jsonl(
    artifact_path: str | Path, metadata_path: str | Path, destination: str | Path, *, exclusive_output: bool = False,
) -> ContractResult:
    """Atomically publish only a fully validated, non-empty Trivy projection."""
    result = normalize_trivy_sanitized_json(artifact_path, metadata_path)
    if result.failure is not None:
        return result
    try:
        write_jsonl_atomic(destination, result.records, exclusive=exclusive_output)
    except OSError:
        return _failure("artifact-publication-failed", "Trivy normalized artifact could not be published")
    return result


def main(argv: list[str] | None = None) -> int:
    """Publish the strict CI projection and print only safe status metadata."""
    parser = argparse.ArgumentParser(description="Normalize a Sentinel Trivy CI artifact")
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--metadata", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--exclusive-output", action="store_true")
    args = parser.parse_args(argv)
    result = normalize_trivy_sanitized_to_jsonl(
        args.artifact, args.metadata, args.output, exclusive_output=args.exclusive_output,
    )
    if result.failure is not None:
        print(json.dumps({"status": "failed", "failure": result.failure.code}, sort_keys=True))
        return 1
    print(json.dumps({"status": "ok", "records": len(result.records)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
