#!/usr/bin/env python3
"""Deterministic, current-run-only evaluator for the Sentinel charter profile."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
METRIC_FIELDS = {
    "duration_ms", "request_count", "warning_count", "approve_count", "reject_count",
    "llm_error_count", "application_error_count",
}
_SENSITIVE_KEY = re.compile(r"(?:token|secret|password|credential|authorization|body)", re.I)
_SENSITIVE_VALUE = re.compile(
    r"(?:\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|"
    r"\b(?:\+?\d[ .()\-]?){8,15}\b|\b(?:\d[ -]?){13,19}\b)"
)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_CREDENTIAL_VALUE = re.compile(r"(?i)\b(?:token|secret|api[_-]?key|password|authorization)\b\s*[:=]\s*\S+")
_CANONICAL_REQUEST_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


class EvaluationError(ValueError):
    pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_canonical_request_id(field: str | None, value: str) -> bool:
    return field == "request_id" and _CANONICAL_REQUEST_ID.fullmatch(value) is not None


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvaluationError(f"invalid JSON artifact: {path.name}") from exc


def _require_private_regular(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise EvaluationError(f"required artifact is absent: {path.name}") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode) or stat.S_IMODE(mode) != 0o600:
        raise EvaluationError(f"artifact is not a private regular file: {path.name}")


def _inside(run_dir: Path, candidate: str | Path, *, must_exist: bool = True) -> Path:
    path = Path(candidate)
    if not path.is_absolute():
        path = run_dir / path
    if must_exist and path.is_symlink():
        raise EvaluationError("artifact must not be a symlink")
    resolved = path.resolve(strict=must_exist)
    try:
        resolved.relative_to(run_dir.resolve(strict=True))
    except ValueError as exc:
        raise EvaluationError("artifact is not inside the current run directory") from exc
    return resolved


def _assert_sanitized(value: Any, field: str | None = None) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if _SENSITIVE_KEY.search(str(key)):
                raise EvaluationError("artifact has a sensitive field name")
            _assert_sanitized(item, str(key))
    elif isinstance(value, list):
        for item in value:
            _assert_sanitized(item)
    elif isinstance(value, str):
        # The charter's literal loopback origin is an approved location, not a
        # telephone number. Keep scanning the path suffix for real PII.
        candidate = value.replace("http://127.0.0.1:13000", "http://loopback")
        if _JWT.search(candidate) or _CREDENTIAL_VALUE.search(candidate):
            raise EvaluationError("artifact contains a credential-looking value")
        if (_SENSITIVE_VALUE.search(candidate) and field != "version"
                and not _is_canonical_request_id(field, value)):
            raise EvaluationError("artifact contains a sensitive-looking value")


def _manifest_contract() -> Any:
    spec = importlib.util.spec_from_file_location("sentinel_manifest_contract", ROOT / "scripts" / "sentinel-manifest.py")
    if spec is None or spec.loader is None:
        raise EvaluationError("current manifest contract could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_manifest(run_dir: Path) -> tuple[dict[str, Any], Path]:
    path = _inside(run_dir, "manifest.json")
    _require_private_regular(path)
    value = _load_json(path)
    try:
        _manifest_contract().valid(value)
    except (SystemExit, ValueError, TypeError) as exc:
        raise EvaluationError("manifest failed the current charter contract") from exc
    metrics = value.get("metrics")
    if (not isinstance(metrics, dict) or set(metrics) != {"version", *METRIC_FIELDS}
            or metrics.get("version") != "RunMetrics/v1"
            or any(type(metrics[name]) is not int or metrics[name] < 0 for name in METRIC_FIELDS)):
        raise EvaluationError("manifest RunMetrics/v1 is missing, extra, or malformed")
    if value["result"]["status"] == "recovered":
        audit_path = _inside(run_dir, "audit-recovery.json")
        _require_private_regular(audit_path)
        try:
            from agent.charter_receipt import ReceiptContractError, decode_object, validate_audit
            from agent.charter_requests import load_spec
            spec = load_spec(_load_json(_inside(run_dir, "request-spec.json")))
            validate_audit(decode_object(audit_path.read_bytes()), spec)
        except (OSError, ReceiptContractError, ValueError) as exc:
            raise EvaluationError("audit-only recovery artifact is invalid") from exc
        raise EvaluationError("audit-only recovery cannot satisfy receipt, response-guard, or evaluation evidence")
    if value["result"]["status"] not in {"passed", "rejected"} or value["required_skips"]:
        raise EvaluationError("manifest is not a completed no-skip current run")
    return value, path


def _load_jsonl(path: Path, kind: str) -> list[dict[str, Any]]:
    from agent.charter_contracts import NormalizedFinding, ReportFinding
    _require_private_regular(path)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise EvaluationError(f"{kind} artifact could not be read") from exc
    if not lines or not all(line.strip() for line in lines):
        raise EvaluationError(f"{kind} artifact is empty or malformed")
    records: list[dict[str, Any]] = []
    for line in lines:
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EvaluationError(f"{kind} artifact is not JSONL") from exc
        try:
            record = (NormalizedFinding if kind == "normalized" else ReportFinding).model_validate(record).model_dump(exclude_none=True)
        except Exception as exc:
            raise EvaluationError(f"{kind} record does not meet the current typed contract") from exc
        _assert_sanitized(record)
        records.append(record)
    if len({record["finding_id"] for record in records}) != len(records):
        raise EvaluationError(f"{kind} artifact has duplicate finding ids")
    return records


def _load_artifact_bindings(run_dir: Path, manifest: dict[str, Any], manifest_path: Path,
                            normalized_path: Path, report_path: Path, request_path: Path,
                            receipt_path: Path | None, request_spec_path: Path | None) -> Path:
    path = _inside(run_dir, "artifact-bindings.json")
    _require_private_regular(path)
    value = _load_json(path)
    expected = {
        "schema_version": "charter-artifact-bindings/v2", "run_id": manifest["run_id"],
        "manifest_output_sha256": manifest["identity"]["output_sha256"],
        "manifest_sha256": _sha256(manifest_path), "normalized_sha256": _sha256(normalized_path),
        "report_sha256": _sha256(report_path), "request_sha256": _sha256(request_path),
        "receipt_sha256": _sha256(receipt_path) if receipt_path is not None else None,
        "request_spec_sha256": _sha256(request_spec_path) if request_spec_path is not None else None,
    }
    if value != expected:
        raise EvaluationError("artifact bindings are missing, stale, or not from this current run")
    _assert_sanitized(value)
    return path


def _load_request_spec(run_dir: Path) -> tuple[Any | None, Path | None]:
    path = run_dir / "request-spec.json"
    if not path.exists() and not path.is_symlink():
        return None, None
    path = _inside(run_dir, "request-spec.json")
    _require_private_regular(path)
    try:
        from agent.charter_requests import load_spec
        return load_spec(_load_json(path)), path
    except Exception as exc:
        raise EvaluationError("immutable request spec is invalid") from exc


def _load_request(run_dir: Path, request_name: str, manifest: dict[str, Any], request_spec: Any | None) -> tuple[dict[str, Any], Path, Path | None]:
    path = _inside(run_dir, request_name)
    _require_private_regular(path)
    value = _load_json(path)
    if (not isinstance(value, dict) or set(value) != {"schema_version", "action_sent", "request_count", "receipt_sha256"}
            or value["schema_version"] != "charter-request-outcome/v1"
            or type(value["action_sent"]) is not bool or type(value["request_count"]) is not int
            or value["request_count"] < 0 or value["action_sent"] != manifest["result"]["action_sent"]
            or value["request_count"] != manifest["metrics"]["request_count"]):
        raise EvaluationError("request outcome does not match the current manifest")
    receipt_path: Path | None = None
    receipt_hash = value["receipt_sha256"]
    if not value["action_sent"]:
        if receipt_hash is not None or value["request_count"] != 0:
            raise EvaluationError("zero-action request outcome cannot claim a receipt")
        if any((run_dir / name).exists() or (run_dir / name).is_symlink()
               for name in ("receipt.json", "request-descriptor.json", "executor-state.sqlite")):
            raise EvaluationError("zero-action run has stray action evidence")
    else:
        if request_spec is None:
            raise EvaluationError("sent request outcome requires immutable request spec")
        if not isinstance(receipt_hash, str) or not _SHA256.fullmatch(receipt_hash):
            raise EvaluationError("sent request outcome requires a receipt hash")
        receipt_path = _inside(run_dir, "receipt.json")
        _require_private_regular(receipt_path)
        descriptor_path = _inside(run_dir, "request-descriptor.json")
        _require_private_regular(descriptor_path)
        if _load_json(descriptor_path) != {"schema_version": "sentinel-request-descriptor/v1", "receipt": "receipt.json"}:
            raise EvaluationError("sent request outcome has an invalid receipt descriptor")
        try:
            from agent.charter_receipt import ReceiptContractError, decode_object, validate_receipt
            receipt = decode_object(receipt_path.read_bytes())
            validate_receipt(receipt, request_spec)
        except (OSError, ReceiptContractError) as exc:
            raise EvaluationError("receipt does not meet the immutable request contract") from exc
        _assert_sanitized(receipt)
        if _sha256(receipt_path) != receipt_hash:
            raise EvaluationError("request receipt hash does not bind the current receipt")
    _assert_sanitized(value)
    return value, path, receipt_path


def _review_inputs(cases_path: Path, gold_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    cases_doc, gold = _load_json(cases_path), _load_json(gold_path)
    if (not isinstance(cases_doc, dict) or cases_doc.get("schema_version") != "charter-eval-cases/v1"
            or not isinstance(gold, dict) or gold.get("schema_version") != "charter-eval-gold/v1"):
        raise EvaluationError("review inputs have an unknown version")
    reviewer = cases_doc.get("reviewer")
    if (not isinstance(reviewer, dict) or set(reviewer) != {"id", "version"}
            or not all(isinstance(value, str) and value for value in reviewer.values())
            or gold.get("reviewer") != reviewer):
        raise EvaluationError("cases and gold are not owned by the same reviewer version")
    cases = cases_doc.get("cases")
    expected = gold.get("expected")
    if not isinstance(cases, list) or not 5 <= len(cases) <= 10 or not isinstance(expected, dict):
        raise EvaluationError("review set must contain exactly 5-10 cases and expected outcomes")
    identifiers: list[str] = []
    for case in cases:
        if (not isinstance(case, dict) or set(case) != {"case_id", "version", "artifact", "truth"}
                or not isinstance(case["case_id"], str) or not case["case_id"]
                or not isinstance(case["version"], str) or not case["version"]
                or case["artifact"] not in {"normalized", "report", "manifest", "request"}
                or case["truth"] not in {"positive", "negative"}):
            raise EvaluationError("review case is malformed")
        identifiers.append(case["case_id"])
    if len(set(identifiers)) != len(identifiers) or set(identifiers) != set(expected):
        raise EvaluationError("gold expectations do not exactly bind the cases")
    if any(not isinstance(expected[identifier], dict) or not expected[identifier] for identifier in identifiers):
        raise EvaluationError("review gold has a malformed expected outcome")
    if not any(case["truth"] == "positive" for case in cases) or not any(case["truth"] == "negative" for case in cases):
        raise EvaluationError("review set is vacuous without positive and negative cases")
    for field in ("limitations", "improvement_proposals"):
        if (not isinstance(gold.get(field), list) or not gold[field]
                or any(not isinstance(item, str) or not item.strip() for item in gold[field])):
            raise EvaluationError(f"review gold lacks {field}")
    _assert_sanitized(cases_doc)
    _assert_sanitized(gold)
    return cases, gold


def _matches(value: Any, expected: Any) -> bool:
    if isinstance(expected, dict):
        return isinstance(value, dict) and all(key in value and _matches(value[key], wanted) for key, wanted in expected.items())
    return value == expected


def _case_match(case: dict[str, Any], expected: dict[str, Any], manifest: dict[str, Any], request: dict[str, Any], normalized: list[dict[str, Any]], report: list[dict[str, Any]]) -> bool:
    artifact = case["artifact"]
    if artifact == "manifest":
        return _matches(manifest, expected)
    if artifact == "request":
        return _matches(request, expected)
    records = normalized if artifact == "normalized" else report
    return any(_matches(record, expected) for record in records)


def _result_payload(manifest: dict[str, Any], manifest_path: Path, artifact_bindings_path: Path, request: dict[str, Any], request_path: Path, receipt_path: Path | None, request_spec_path: Path | None, normalized_path: Path, report_path: Path,
                    cases_path: Path, gold_path: Path, cases: list[dict[str, Any]], gold: dict[str, Any]) -> dict[str, Any]:
    normalized = _load_jsonl(normalized_path, "normalized")
    report = _load_jsonl(report_path, "report")
    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    analyses = []
    for case in cases:
        matched = _case_match(case, gold["expected"][case["case_id"]], manifest, request, normalized, report)
        if case["truth"] == "positive":
            bucket = "TP" if matched else "FN"
        else:
            bucket = "FP" if matched else "TN"
        counts[bucket.lower()] += 1
        analyses.append({
            "case_id": case["case_id"], "artifact": case["artifact"], "truth": case["truth"],
            "outcome": bucket, "correct": bucket in {"TP", "TN"},
            "analysis": "reviewer expectation matched the current artifact" if matched else "reviewer expectation did not match the current artifact",
        })
    return {
        "schema_version": "charter-eval-result/v1",
        "run_id": manifest["run_id"],
        "reviewer": gold["reviewer"],
        "bindings": {
            "manifest_sha256": _sha256(manifest_path),
            "normalized_sha256": _sha256(normalized_path),
            "report_sha256": _sha256(report_path),
            "request_sha256": _sha256(request_path),
            "receipt_sha256": _sha256(receipt_path) if receipt_path is not None else None,
            "request_spec_sha256": _sha256(request_spec_path) if request_spec_path is not None else None,
            "artifact_bindings_sha256": _sha256(artifact_bindings_path),
            "cases_sha256": _sha256(cases_path),
            "gold_sha256": _sha256(gold_path),
            "manifest_output_sha256": manifest["identity"]["output_sha256"],
        },
        "run_metrics": manifest["metrics"],
        "result": manifest["result"],
        "confusion": counts,
        "case_analysis": analyses,
        "limitations": gold["limitations"],
        "improvement_proposals": gold["improvement_proposals"],
    }


def _write_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    os.fchmod(fd, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    run_dir = Path(args.run_dir).resolve(strict=True)
    manifest, manifest_path = _load_manifest(run_dir)
    normalized_path = _inside(run_dir, args.normalized)
    report_path = _inside(run_dir, args.report)
    request_spec, request_spec_path = _load_request_spec(run_dir)
    request, request_path, receipt_path = _load_request(run_dir, args.request, manifest, request_spec)
    artifact_bindings_path = _load_artifact_bindings(run_dir, manifest, manifest_path, normalized_path, report_path, request_path, receipt_path, request_spec_path)
    cases_path, gold_path = Path(args.cases), Path(args.gold)
    cases, gold = _review_inputs(cases_path, gold_path)
    value = _result_payload(manifest, manifest_path, artifact_bindings_path, request, request_path, receipt_path, request_spec_path, normalized_path, report_path, cases_path, gold_path, cases, gold)
    _assert_sanitized(value)
    destination = _inside(run_dir, args.output, must_exist=False)
    _write_atomic(destination, value)
    return value


def verify(args: argparse.Namespace) -> dict[str, Any]:
    run_dir = Path(args.run_dir).resolve(strict=True)
    manifest, manifest_path = _load_manifest(run_dir)
    normalized_path = _inside(run_dir, args.normalized)
    report_path = _inside(run_dir, args.report)
    request_spec, request_spec_path = _load_request_spec(run_dir)
    request, request_path, receipt_path = _load_request(run_dir, args.request, manifest, request_spec)
    artifact_bindings_path = _load_artifact_bindings(run_dir, manifest, manifest_path, normalized_path, report_path, request_path, receipt_path, request_spec_path)
    result_path = _inside(run_dir, args.result)
    value = _load_json(result_path)
    if not isinstance(value, dict) or value.get("schema_version") != "charter-eval-result/v1":
        raise EvaluationError("result report has an unknown version")
    cases_path, gold_path = Path(args.cases), Path(args.gold)
    cases, gold = _review_inputs(cases_path, gold_path)
    expected = _result_payload(manifest, manifest_path, artifact_bindings_path, request, request_path, receipt_path, request_spec_path, normalized_path, report_path, cases_path, gold_path, cases, gold)
    if value != expected:
        raise EvaluationError("result report is stale, malformed, or not bound to this current run")
    _require_private_regular(result_path)
    _assert_sanitized(value)
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("evaluate", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--run-dir", required=True)
        command.add_argument("--normalized", default="normalized.jsonl")
        command.add_argument("--report", default="report.jsonl")
        command.add_argument("--request", default="request.json")
        command.add_argument("--cases", default=str(HERE / "cases.json"))
        command.add_argument("--gold", default=str(HERE / "gold.json"))
    commands.choices["evaluate"].add_argument("--output", default="charter-evaluation.json")
    commands.choices["verify"].add_argument("--result", default="charter-evaluation.json")
    args = parser.parse_args()
    try:
        value = evaluate(args) if args.command == "evaluate" else verify(args)
    except (EvaluationError, OSError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
