"""SARIF -> findings.jsonl converter. Handles the two CWE-location shapes seen in
real tool output: Metis puts `cwe`/`severity`/`confidence` on the result's own
`properties`; SAIST puts CWE/severity as `CWE:n` / `SEVERITY:x` tags on the rule
definition (looked up via ruleId), since its results carry no such properties.

Known unimplemented SARIF shape: message-by-template (`message.id` + `arguments`,
looked up in `rule.messageStrings`) is not read, only `message.text`/plain-string
messages. No real tool output seen so far uses the template form; if one does,
`message` becomes "" silently rather than erroring."""
from __future__ import annotations

import json
import logging
import re

from .schema import Finding, compute_finding_id, normalize_severity, parse_cwe

logger = logging.getLogger(__name__)

_BENCHMARK_TEST_CASE_RE = re.compile(r"(BenchmarkTest\d+)")
_TAG_CWE_RE = re.compile(r"CWE[:\-](\d+)", re.IGNORECASE)
_TAG_SEVERITY_RE = re.compile(r"SEVERITY[:\-](\w+)", re.IGNORECASE)


class _SkipResult(Exception):
    """Raised internally to skip one malformed/incomplete SARIF result without
    aborting the whole conversion. Carries a human-readable reason for logging."""


def _rule_tags(rule: dict) -> list[str]:
    return rule.get("properties", {}).get("tags", []) or []


def _cwe_severity_from_rule_tags(tags: list[str]) -> tuple[int | None, str | None]:
    cwe = None
    severity = None
    for tag in tags:
        m = _TAG_CWE_RE.match(tag)
        if m:
            cwe = int(m.group(1))
        m = _TAG_SEVERITY_RE.match(tag)
        if m:
            severity = m.group(1)
    return cwe, severity


def _extract_target_test_case(file_path: str, target: str) -> str | None:
    if target != "owasp-benchmark":
        return None
    m = _BENCHMARK_TEST_CASE_RE.search(file_path)
    return m.group(1) if m else None


def _extract_message_text(raw_message: object) -> str:
    if isinstance(raw_message, str):
        return raw_message
    if isinstance(raw_message, dict):
        return raw_message.get("text", "")
    return ""


def _convert_one_result(
    result: dict,
    *,
    tool: str,
    tool_version: str,
    rules_by_id: dict,
    run_id: str,
    timestamp: str,
    variant: str,
    model: str,
    target: str,
    sarif_ref: str,
    stage_status: str,
) -> Finding:
    rule_id = result.get("ruleId", "unknown")
    rule = rules_by_id.get(rule_id) or {}
    tags = _rule_tags(rule)
    tag_cwe, tag_severity = _cwe_severity_from_rule_tags(tags)

    props = result.get("properties") or {}
    cwe = parse_cwe(props.get("cwe")) if "cwe" in props else tag_cwe
    severity = normalize_severity(props.get("severity") or tag_severity or result.get("level"))

    raw_confidence = props.get("confidence")
    confidence: float | None
    if raw_confidence is None:
        confidence = None
    else:
        try:
            confidence = float(raw_confidence)
        except (TypeError, ValueError):
            logger.warning("rule=%s: non-numeric confidence %r, treating as null", rule_id, raw_confidence)
            confidence = None

    locations = result.get("locations") or []
    if not locations:
        raise _SkipResult(f"rule={rule_id}: no locations")
    phys = locations[0].get("physicalLocation") or {}
    file_path = phys.get("artifactLocation", {}).get("uri", "unknown")
    region = phys.get("region") or {}
    start_line = region.get("startLine", 0)
    end_line = region.get("endLine", start_line)

    message = _extract_message_text(result.get("message"))
    short_description = rule.get("shortDescription") or {}
    title = short_description.get("text") or message

    return Finding(
        finding_id=compute_finding_id(tool, rule_id, file_path, start_line, end_line, cwe),
        run_id=run_id,
        timestamp=timestamp,
        tool=tool,
        tool_version=tool_version,
        variant=variant,
        model=model,
        rule_id=rule_id,
        title=title,
        cwe=cwe,
        severity=severity,
        file=file_path,
        start_line=start_line,
        end_line=end_line,
        message=message,
        stage_status=stage_status,
        confidence=confidence,
        target=target,
        sarif_ref=sarif_ref,
        target_test_case=_extract_target_test_case(file_path, target),
    )


def convert_sarif_to_findings(
    sarif: dict,
    *,
    sarif_ref: str,
    run_id: str,
    timestamp: str,
    variant: str,
    model: str,
    target: str,
    stage_status: str = "validated",
    skip_log: list[dict] | None = None,
) -> list[Finding]:
    """stage_status defaults to 'validated': neither SAIST (0 real results so far)
    nor Metis (single-pass review, no exposed candidate/rejected split in SARIF)
    give us a documented source for per-finding stage. See docs/benchmark-pre-plan-decisions.md
    and plan.md Phase 2 caveat. Pass an explicit value if a source becomes available.

    A malformed or unexpected-shape result is logged and skipped rather than
    aborting the whole conversion (important for a ~2700-test-case FULL OWASP
    Benchmark run: one bad result must not zero out the run against the
    completeness gate). Pass `skip_log` to collect the skip reasons for that run's
    manifest instead of only relying on the log stream."""
    findings: list[Finding] = []

    for run in sarif.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        tool = driver.get("name", "unknown")
        tool_version = driver.get("version", "unknown")
        rules_by_id = {r["id"]: r for r in driver.get("rules", []) if "id" in r}

        for result in run.get("results", []):
            try:
                finding = _convert_one_result(
                    result,
                    tool=tool,
                    tool_version=tool_version,
                    rules_by_id=rules_by_id,
                    run_id=run_id,
                    timestamp=timestamp,
                    variant=variant,
                    model=model,
                    target=target,
                    sarif_ref=sarif_ref,
                    stage_status=stage_status,
                )
            except _SkipResult as e:
                entry = {"rule_id": result.get("ruleId"), "reason": str(e)}
                logger.warning("skipping SARIF result: %s", entry)
                if skip_log is not None:
                    skip_log.append(entry)
                continue
            except Exception as e:  # malformed/unexpected shape - isolate, don't abort the run
                entry = {"rule_id": result.get("ruleId"), "reason": f"{type(e).__name__}: {e}"}
                logger.warning("skipping malformed SARIF result: %s", entry)
                if skip_log is not None:
                    skip_log.append(entry)
                continue
            findings.append(finding)

    seen_ids: set[str] = set()
    for f in findings:
        if f.finding_id in seen_ids:
            logger.warning(
                "duplicate finding_id %s (rule=%s file=%s:%s) - tool reported the same "
                "location+rule+cwe more than once in this run",
                f.finding_id,
                f.rule_id,
                f.file,
                f.start_line,
            )
        seen_ids.add(f.finding_id)

    return findings


def findings_to_jsonl(findings: list[Finding]) -> str:
    return "\n".join(json.dumps(f.to_dict()) for f in findings)
