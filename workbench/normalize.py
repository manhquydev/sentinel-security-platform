"""Strict integration boundary for CodeQL, Semgrep, and Trivy raw reports."""
from __future__ import annotations

import hashlib
import json
import posixpath
from dataclasses import dataclass
from typing import Any, Mapping


class NormalizationViolation(ValueError):
    """Raised when one source record cannot be faithfully normalized."""


@dataclass(frozen=True)
class NormalizedFinding:
    engine: str
    rule_id: str
    locator: str
    title: str
    severity: str
    union_key: str


def _relative_path(value: object, *, source_mount: str | None = None) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise NormalizationViolation("finding locator path must be a canonical source-relative path")
    if source_mount is not None:
        if not source_mount.startswith("/") or source_mount.endswith("/") or "://" in source_mount:
            raise NormalizationViolation("declared scanner source mount is invalid")
        prefixes = (f"{source_mount}/", f"file://{source_mount}/")
        matched = next((prefix for prefix in prefixes if value.startswith(prefix)), None)
        if matched is not None:
            value = value[len(matched) :]
    if value.startswith("/") or "://" in value or value.startswith("file:"):
        raise NormalizationViolation("finding locator path must be source-relative")
    normalized = posixpath.normpath(value)
    if normalized in (".", "..") or normalized.startswith("../") or normalized != value:
        raise NormalizationViolation("finding locator path must not traverse or normalize")
    return normalized


def _line(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise NormalizationViolation("finding locator requires a positive source line")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise NormalizationViolation(f"{label} must be a labelled string")
    return value


def _finding(
    engine: str,
    rule_id: object,
    path: object,
    line: object,
    title: object,
    severity: object,
    *,
    source_mount: str | None = None,
) -> NormalizedFinding:
    safe_path = _relative_path(path, source_mount=source_mount)
    safe_line = _line(line)
    safe_rule_id = _text(rule_id, "rule id")
    safe_title = _text(title, "finding title")
    safe_severity = _text(severity, "finding severity").lower()
    locator = f"{safe_path}:{safe_line}"
    union_key = hashlib.sha256(
        json.dumps(
            {
                "engine": engine,
                "rule_id": safe_rule_id,
                "locator": locator,
                "title": safe_title,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return NormalizedFinding(engine, safe_rule_id, locator, safe_title, safe_severity, union_key)


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise NormalizationViolation(f"{label} must be an object")
    return value


def normalize_codeql(report: object, *, source_mount: str | None = None) -> tuple[NormalizedFinding, ...]:
    document = _mapping(report, "CodeQL SARIF")
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise NormalizationViolation("CodeQL SARIF requires one or more runs")
    normalized: list[NormalizedFinding] = []
    raw_count = 0
    for run in runs:
        run_data = _mapping(run, "CodeQL run")
        invocations = run_data.get("invocations")
        if not isinstance(invocations, list) or not invocations or any(
            _mapping(item, "CodeQL invocation").get("executionSuccessful") is not True for item in invocations
        ):
            raise NormalizationViolation("CodeQL database/query invocation is incomplete")
        results = run_data.get("results")
        if not isinstance(results, list):
            raise NormalizationViolation("CodeQL SARIF results are absent")
        for result in results:
            raw_count += 1
            item = _mapping(result, "CodeQL result")
            locations = item.get("locations")
            if not isinstance(locations, list) or len(locations) != 1:
                raise NormalizationViolation("CodeQL result requires exactly one source location")
            physical = _mapping(_mapping(locations[0], "CodeQL location").get("physicalLocation"), "CodeQL physical location")
            artifact = _mapping(physical.get("artifactLocation"), "CodeQL artifact location")
            region = _mapping(physical.get("region"), "CodeQL source region")
            message = _mapping(item.get("message"), "CodeQL message")
            normalized.append(
                _finding(
                    "codeql",
                    item.get("ruleId"),
                    artifact.get("uri"),
                    region.get("startLine"),
                    message.get("text"),
                    item.get("level", "warning"),
                    source_mount=source_mount,
                )
            )
    if raw_count != len(normalized):
        raise NormalizationViolation("CodeQL raw and normalized record counts do not reconcile")
    return tuple(normalized)


def normalize_semgrep(report: object, *, source_mount: str | None = None) -> tuple[NormalizedFinding, ...]:
    document = _mapping(report, "Semgrep JSON")
    errors = document.get("errors")
    paths = _mapping(document.get("paths"), "Semgrep paths")
    scanned = paths.get("scanned")
    skipped = paths.get("skipped", [])
    results = document.get("results")
    if not isinstance(skipped, list) or skipped:
        raise NormalizationViolation("Semgrep skipped source files; a B0 result would be incomplete")
    if not isinstance(errors, list) or errors or not isinstance(scanned, list) or not scanned or not isinstance(results, list):
        raise NormalizationViolation("Semgrep result is absent, incomplete, or has parse errors")
    normalized: list[NormalizedFinding] = []
    for result in results:
        item = _mapping(result, "Semgrep result")
        extra = _mapping(item.get("extra"), "Semgrep result extra")
        start = _mapping(item.get("start"), "Semgrep result start")
        normalized.append(
            _finding(
                "semgrep",
                item.get("check_id"),
                item.get("path"),
                start.get("line"),
                extra.get("message", item.get("check_id")),
                extra.get("severity", "warning"),
                source_mount=source_mount,
            )
        )
    if len(results) != len(normalized):
        raise NormalizationViolation("Semgrep raw and normalized record counts do not reconcile")
    return tuple(normalized)


def normalize_trivy(report: object, *, source_mount: str | None = None) -> tuple[NormalizedFinding, ...]:
    document = _mapping(report, "Trivy JSON")
    results = document.get("Results")
    if not isinstance(results, list):
        raise NormalizationViolation("Trivy results are absent")
    normalized: list[NormalizedFinding] = []
    raw_count = 0
    categories = ("Vulnerabilities", "Misconfigurations", "Secrets")
    for result in results:
        item = _mapping(result, "Trivy result")
        target = item.get("Target")
        _relative_path(target, source_mount=source_mount)
        for category in categories:
            findings = item.get(category, [])
            if not isinstance(findings, list):
                raise NormalizationViolation("Trivy finding category must be a list")
            for finding in findings:
                raw_count += 1
                finding_data = _mapping(finding, "Trivy finding")
                metadata = finding_data.get("CauseMetadata", {})
                metadata_data = _mapping(metadata, "Trivy cause metadata")
                rule_id = finding_data.get("VulnerabilityID") or finding_data.get("ID") or finding_data.get("RuleID")
                normalized.append(
                    _finding(
                        "trivy",
                        rule_id,
                        target,
                        metadata_data.get("StartLine", 1),
                        finding_data.get("Title") or finding_data.get("Message") or rule_id,
                        finding_data.get("Severity", "unknown"),
                        source_mount=source_mount,
                    )
                )
    if raw_count != len(normalized):
        raise NormalizationViolation("Trivy raw and normalized record counts do not reconcile")
    return tuple(normalized)
