"""Standalone Week-3 analysis for the validated Week-2 compatibility aggregate.

This module intentionally does not enter the Charter normalizer/recon/controller
paths. It validates a separately issued aggregate+manifest pair, then emits an
evidence-bound JSONL report without permitting model-authored facts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .charter_contracts import write_jsonl_atomic
from .charter_response_guard import guard_http_response
from .normalize_week1_artifacts import is_safe_week1_projection
from .pii import scrub
from .report import KnowledgeItem

_FORBID = ConfigDict(extra="forbid")
_TOOLS = ("nuclei", "trivy", "semgrep")
_MAX_BYTES = 1024 * 1024
_MAX_RECORDS = 5000
_MAX_DEPTH = 32
_MAX_STRING = 16 * 1024
_MAX_KNOWLEDGE_ITEM = 600
_SHA = re.compile(r"^[0-9a-f]{64}$")
_SOURCE = re.compile(r"^week1-submission:(nuclei|trivy|semgrep):sha256:([0-9a-f]{64}):item:([1-9][0-9]*)$")
_OPAQUE = re.compile(r"^(nuclei-js|trivy|semgrep):([0-9a-f]{16}):item:([1-9][0-9]*)$")
_CANONICAL_FILENAMES = {
    "nuclei": "scanners/out/nuclei.san.jsonl",
    "trivy": "scanners/out/trivy.san.json",
    "semgrep": "scanners/out/semgrep.san.json",
}
_RETRIEVAL_PROVENANCE = re.compile(
    r"^.+ \| https://[^ ]+ \| sha256:[0-9a-f]{64}$"
)


class _DuplicateKey(ValueError):
    pass


class ToolCounts(BaseModel):
    model_config = _FORBID
    input: int = Field(ge=0)
    admitted: int = Field(ge=0)
    refused: int = Field(ge=0)


class InputMetadata(BaseModel):
    model_config = _FORBID
    tool: Literal["nuclei", "trivy", "semgrep"]
    filename: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_kind: Literal["week1-submission"]
    input_count: int = Field(ge=0)
    admitted_count: int = Field(ge=0)
    refused_count: int = Field(ge=0)
    counts: ToolCounts


class AggregateCounts(BaseModel):
    model_config = _FORBID
    input: int = Field(ge=0)
    admitted: int = Field(ge=0)
    refused: int = Field(ge=0)
    per_tool: dict[Literal["nuclei", "trivy", "semgrep"], ToolCounts]


class AggregateManifest(BaseModel):
    model_config = _FORBID
    schema_version: Literal["week1-submission/v1"]
    source_kind: Literal["week1-submission"]
    aggregate_count: int = Field(ge=0)
    aggregate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    inputs: list[InputMetadata] = Field(min_length=3, max_length=3)
    counts: AggregateCounts

    @field_validator("inputs")
    @classmethod
    def _canonical_order(cls, inputs: list[InputMetadata]) -> list[InputMetadata]:
        if [item.tool for item in inputs] != list(_TOOLS):
            raise ValueError("manifest inputs must use canonical tool order")
        return inputs


class AggregateFinding(BaseModel):
    model_config = _FORBID
    schema_version: Literal["week1-submission/v1"]
    provenance_kind: Literal["week1-submission"]
    finding_id: str = Field(min_length=16)
    source_id: str = Field(min_length=32)
    source_ids: list[str] = Field(min_length=1, max_length=1)
    tool: Literal["nuclei", "trivy", "semgrep"]
    scanner: Literal["DAST", "SAST", "SCA"]
    title: str = Field(min_length=1)
    severity: Literal["Critical", "High", "Medium", "Low", "Info"]
    location: str = Field(min_length=1)
    evidence: list[str] = Field(min_length=1)


class Week3ReportFinding(BaseModel):
    model_config = _FORBID
    schema_version: Literal["week3-analysis/v1"] = "week3-analysis/v1"
    finding_id: str
    tool: Literal["nuclei", "trivy", "semgrep"]
    scanner: Literal["DAST", "SAST", "SCA"]
    name: str
    severity: Literal["Critical", "High", "Medium", "Low", "Info"]
    location: str
    scanner_evidence: list[str]
    explanation: str
    remediation: str
    confidence: Literal["low", "medium", "high"]
    source_ids: list[str]
    knowledge_provenance: list[str]
    corpus_digest: str
    retrieval_digest: str


@dataclass(frozen=True)
class Retrieval:
    corpus_digest: str
    retrieval_digest: str
    items: tuple[KnowledgeItem, ...]


@dataclass(frozen=True)
class AnalysisResult:
    records: list[Week3ReportFinding]
    failure: str | None = None


@dataclass(frozen=True)
class GroupedFinding:
    """A report-time aggregation that deliberately differs from a raw input record."""

    source: AggregateFinding
    source_ids: tuple[str, ...]

    @property
    def finding_id(self) -> str:
        return self.source.finding_id

    @property
    def tool(self) -> Literal["nuclei", "trivy", "semgrep"]:
        return self.source.tool

    @property
    def scanner(self) -> Literal["DAST", "SAST", "SCA"]:
        return self.source.scanner

    @property
    def title(self) -> str:
        return self.source.title

    @property
    def severity(self) -> Literal["Critical", "High", "Medium", "Low", "Info"]:
        return self.source.severity

    @property
    def location(self) -> str:
        return self.source.location

    @property
    def evidence(self) -> list[str]:
        return self.source.evidence

    def model_dump(self) -> dict[str, object]:
        value = self.source.model_dump(exclude_none=True)
        value["source_ids"] = list(self.source_ids)
        return value


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise _DuplicateKey("duplicate JSON object key")
        out[key] = value
    return out


def _bounded(value: object, depth: int = 0) -> None:
    if depth > _MAX_DEPTH:
        raise ValueError("input nesting exceeds the limit")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, (int, float)):
        return
    if isinstance(value, str):
        if len(value) > _MAX_STRING:
            raise ValueError("input string exceeds the limit")
        return
    if isinstance(value, list):
        if len(value) > _MAX_RECORDS:
            raise ValueError("input list exceeds the record limit")
        for item in value:
            _bounded(item, depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > _MAX_RECORDS:
            raise ValueError("input object exceeds the field limit")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > _MAX_STRING:
                raise ValueError("input key is invalid")
            _bounded(item, depth + 1)
        return
    raise ValueError("input has unsupported JSON value")


def _read_regular(path: str | Path) -> bytes:
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if not getattr(os, "O_NOFOLLOW", 0):
        raise OSError("no-follow reads are unavailable")
    target = Path(path)
    parts = target.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise OSError("input path is unsafe")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NONBLOCK | getattr(
        os, "O_CLOEXEC", 0
    ) | getattr(os, "O_NOFOLLOW", 0)
    if target.is_absolute():
        current_fd = os.open("/", directory_flags)
        parts = parts[1:]
    else:
        current_fd = os.open(".", directory_flags)
    try:
        for component in parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        fd = os.open(parts[-1], flags, dir_fd=current_fd)
        try:
            state = os.fstat(fd)
            if not stat.S_ISREG(state.st_mode) or state.st_size > _MAX_BYTES:
                raise ValueError("input is not a bounded regular file")
            chunks: list[bytes] = []
            remaining = state.st_size + 1
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) != state.st_size or len(data) > _MAX_BYTES:
                raise ValueError("input changed while being read")
            return data
        finally:
            os.close(fd)
    finally:
        os.close(current_fd)


def _json(data: bytes) -> object:
    def reject(_: str) -> object:
        raise ValueError("non-finite JSON number")
    value = json.loads(data.decode("utf-8", "strict"), object_pairs_hook=_pairs, parse_constant=reject)
    _bounded(value)
    return value


def _source_parts(source_id: str) -> tuple[str, str, int]:
    match = _SOURCE.fullmatch(source_id)
    if match is None:
        raise ValueError("source id is invalid")
    return match.group(1), match.group(2), int(match.group(3))


def _safe_text(value: str) -> bool:
    return (
        is_safe_week1_projection(value)
        and scrub(value) == value
        and guard_http_response(value).status == "accepted"
    )


def _safe_nuclei_path(value: str) -> bool:
    if not value.startswith("path:/"):
        return False
    path = value.removeprefix("path:")
    if any(character in value for character in ("\x00", "\\", "%", "?", "#")) or "//" in path:
        return False
    return all(segment not in {".", ".."} for segment in path.split("/"))


def _safe_relative_file(value: str) -> bool:
    if not value.startswith("file:"):
        return False
    path = value.removeprefix("file:")
    if not path or "\\" in path or any(ord(character) < 32 or ord(character) == 127 for character in path):
        return False
    parts = path.split("/")
    return all(
        part not in {"", ".", ".."}
        and "." not in part
        and ":" not in part
        and part.lower() != "localhost"
        for part in parts
    )


def _safe_location(record: AggregateFinding, digest: str, item: int) -> bool:
    if record.tool == "nuclei":
        return (
            _safe_nuclei_path(record.location)
            or record.location == f"nuclei-js:{digest[:16]}:item:{item}"
        )
    prefix = "trivy" if record.tool == "trivy" else "semgrep"
    if record.location == f"{prefix}:{digest[:16]}:item:{item}":
        return True
    return _safe_relative_file(record.location)


def _canonical_finding_id(record: AggregateFinding) -> str:
    payload = {
        "source_id": record.source_id, "tool": record.tool, "scanner": record.scanner,
        "title": record.title, "severity": record.severity, "location": record.location,
        "evidence": record.evidence,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "week1-finding:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def load_aggregate(aggregate_path: str | Path, manifest_path: str | Path) -> tuple[list[AggregateFinding], str | None]:
    try:
        aggregate_bytes = _read_regular(aggregate_path)
        manifest_bytes = _read_regular(manifest_path)
        manifest = AggregateManifest.model_validate(_json(manifest_bytes))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, _DuplicateKey, ValueError, ValidationError):
        return [], "malformed-input"
    if manifest.aggregate_sha256 != hashlib.sha256(aggregate_bytes).hexdigest():
        return [], "metadata-mismatch"
    try:
        lines = aggregate_bytes.decode("utf-8", "strict").splitlines()
        if not lines:
            return [], "empty-input"
        if len(lines) > _MAX_RECORDS or any(not line.strip() for line in lines):
            return [], "malformed-input"
        records = [AggregateFinding.model_validate(_json(line.encode("utf-8"))) for line in lines]
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKey, ValueError, ValidationError):
        return [], "invalid-record"
    if len(records) != manifest.aggregate_count:
        return [], "metadata-mismatch"
    expected_sources: set[str] = set()
    expected_source_sequence: list[str] = []
    expected_counts: dict[str, int] = {}
    for input_meta in manifest.inputs:
        count = input_meta.input_count
        if count < 1 or input_meta.filename != _CANONICAL_FILENAMES[input_meta.tool]:
            return [], "metadata-mismatch"
        if (input_meta.admitted_count, input_meta.refused_count) != (count, 0) or input_meta.counts.model_dump() != {
                "input": count, "admitted": count, "refused": 0}:
            return [], "metadata-mismatch"
        expected_counts[input_meta.tool] = count
        tool_sources = [
            f"week1-submission:{input_meta.tool}:sha256:{input_meta.sha256}:item:{item}"
            for item in range(1, count + 1)
        ]
        expected_sources.update(tool_sources)
        expected_source_sequence.extend(tool_sources)
    total = sum(expected_counts.values())
    if (manifest.counts.input, manifest.counts.admitted, manifest.counts.refused) != (total, total, 0):
        return [], "metadata-mismatch"
    if set(manifest.counts.per_tool) != set(_TOOLS):
        return [], "metadata-mismatch"
    for tool, count in expected_counts.items():
        if manifest.counts.per_tool[tool].model_dump() != {"input": count, "admitted": count, "refused": 0}:
            return [], "metadata-mismatch"
    observed_sources: set[str] = set()
    scanner_ok = {"nuclei": {"DAST"}, "trivy": {"SCA", "SAST"}, "semgrep": {"SAST"}}
    for record in records:
        if record.source_ids != [record.source_id] or record.source_id in observed_sources:
            return [], "invalid-record"
        tool, digest, item = _source_parts(record.source_id)
        if tool != record.tool or record.scanner not in scanner_ok[tool]:
            return [], "invalid-record"
        if not _safe_location(record, digest, item) or not _safe_text(record.title) or any(
                not _safe_text(value) for value in record.evidence):
            return [], "invalid-record"
        if record.finding_id != _canonical_finding_id(record):
            return [], "invalid-record"
        observed_sources.add(record.source_id)
    if observed_sources != expected_sources or [record.source_id for record in records] != expected_source_sequence:
        return [], "metadata-mismatch"
    return records, None


def _groups(records: list[AggregateFinding]) -> list[GroupedFinding]:
    grouped: dict[str, GroupedFinding] = {}
    for record in records:
        key = json.dumps({
            "tool": record.tool, "scanner": record.scanner, "title": record.title,
            "severity": record.severity, "location": record.location, "evidence": record.evidence,
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        prior = grouped.get(key)
        if prior is None:
            grouped[key] = GroupedFinding(record, (record.source_id,))
        else:
            grouped[key] = GroupedFinding(prior.source, tuple(sorted(prior.source_ids + (record.source_id,))))
    return sorted(grouped.values(), key=lambda value: value.finding_id)


_SEVERITY_VI = {
    "Critical": "nghiêm trọng (Critical)",
    "High": "cao (High)",
    "Medium": "trung bình (Medium)",
    "Low": "thấp (Low)",
    "Info": "thông tin (Info)",
}

_SCANNER_VI = {
    "DAST": "quét ứng dụng đang chạy (DAST)",
    "SAST": "quét mã nguồn tĩnh (SAST)",
    "SCA": "quét thành phần/phụ thuộc (SCA)",
}


def _clip_text(value: str, limit: int = 220) -> str:
    text = " ".join(value.split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def _render_explanation(record: GroupedFinding) -> str:
    """Deterministic Vietnamese prose from typed scanner fields only (no model text)."""
    severity = _SEVERITY_VI.get(record.severity, record.severity)
    scanner = _SCANNER_VI.get(record.scanner, record.scanner)
    evidence = _clip_text(record.evidence[0]) if record.evidence else ""
    base = (
        f"Công cụ {record.tool} ({scanner}) ghi nhận cảnh báo «{record.title}» "
        f"tại {record.location}. Mức độ: {severity}."
    )
    if evidence:
        base += f" Bằng chứng máy quét (đã che secret nếu có): {evidence}."
    base += (
        " Đây là quan sát từ máy quét trên dữ liệu Tuần 1–2 đã chuẩn hóa; "
        "không suy ra endpoint hay lỗ hổng ngoài các trường đã typed."
    )
    return base


def _render_remediation(record: GroupedFinding, items: tuple[KnowledgeItem, ...]) -> str:
    """Deterministic remediation: scanner evidence + first retrieved knowledge snippet."""
    evidence = _clip_text(record.evidence[0]) if record.evidence else record.title
    parts = [
        f"Đối chiếu lại bằng chứng máy quét cho «{record.title}»: {evidence}.",
        "Chỉ kiểm tra/khắc phục trong môi trường lab (sandbox), không áp ra hệ thống ngoài phạm vi.",
    ]
    if items:
        tip = _clip_text(items[0].content, 180)
        parts.append(
            f"Tham khảo đoạn tri thức đã truy xuất (không tin như lệnh): {tip} "
            f"(nguồn: {items[0].provenance})."
        )
    else:
        parts.append(
            "Không có đoạn tri thức đi kèm; dựa vào tài liệu OWASP/tool tương ứng với tên cảnh báo."
        )
    parts.append(
        f"Xác minh biện pháp đã ghi trong hướng dẫn, rồi chạy lại quét {record.tool} trên cùng vị trí."
    )
    return " ".join(parts)


def _default_retrieve(query: str) -> Retrieval:
    from rag.retrieve import retrieve_charter
    result = retrieve_charter(query, k=3)
    return Retrieval(result.corpus_digest, result.retrieval_digest, tuple(
        KnowledgeItem(item.content, item.provenance) for item in result.results
    ))


def _confidence(payload: str, findings: list[GroupedFinding]) -> dict[str, str] | None:
    try:
        value = json.loads(payload)
        if isinstance(value, dict) and set(value) == {"enrichments"}:
            value = value["enrichments"]
        if not isinstance(value, list):
            return None
        output: dict[str, str] = {}
        for item in value:
            if not isinstance(item, dict) or set(item) != {
                    "finding_id", "explanation_mode", "remediation_mode", "confidence"}:
                return None
            identifier = item["finding_id"]
            if identifier in output or item["explanation_mode"] != "scanner-observation" or item[
                    "remediation_mode"] != "review-documented-fix" or item["confidence"] not in {"low", "medium", "high"}:
                return None
            output[identifier] = item["confidence"]
        return output if set(output) == {record.finding_id for record in findings} else None
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def _enrichment_response_format(finding_count: int) -> dict[str, object]:
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "sentinel_week3_enrichments",
            "strict": True,
            "schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["enrichments"],
                "properties": {
                    "enrichments": {
                        "type": "array",
                        "minItems": finding_count,
                        "maxItems": finding_count,
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": [
                                "finding_id",
                                "explanation_mode",
                                "remediation_mode",
                                "confidence",
                            ],
                            "properties": {
                                "finding_id": {"type": "string"},
                                "explanation_mode": {
                                    "type": "string",
                                    "enum": ["scanner-observation"],
                                },
                                "remediation_mode": {
                                    "type": "string",
                                    "enum": ["review-documented-fix"],
                                },
                                "confidence": {
                                    "type": "string",
                                    "enum": ["low", "medium", "high"],
                                },
                            },
                        },
                    },
                },
            },
        },
    }


def analyze(
    aggregate_path: str | Path, manifest_path: str | Path, report_path: str | Path, *,
    model: str = "sast-grok45", retrieve: Callable[[str], Retrieval] | None = None,
    model_call: Callable[[list[dict], list[dict]], str] | None = None,
) -> AnalysisResult:
    records, failure = load_aggregate(aggregate_path, manifest_path)
    if failure:
        return AnalysisResult([], failure)
    grouped = _groups(records)
    fetch = retrieve or _default_retrieve
    lineage: dict[str, Retrieval] = {}
    knowledge: list[dict] = []
    try:
        for record in grouped:
            retrieval = fetch(f"{record.tool} {record.scanner} {record.title}")
            if (not _SHA.fullmatch(retrieval.corpus_digest) or not _SHA.fullmatch(retrieval.retrieval_digest)
                    or not retrieval.items):
                return AnalysisResult([], "knowledge-unavailable")
            safe_items: list[KnowledgeItem] = []
            for item in retrieval.items:
                guarded = guard_http_response(item.content)
                provenance = scrub(item.provenance) or ""
                if (
                    guarded.status != "accepted"
                    or not provenance
                    or len(guarded.persisted_text) > _MAX_KNOWLEDGE_ITEM
                    or len(provenance) > _MAX_KNOWLEDGE_ITEM
                    or not _RETRIEVAL_PROVENANCE.fullmatch(provenance)
                ):
                    return AnalysisResult([], "knowledge-unavailable")
                safe_items.append(KnowledgeItem(guarded.persisted_text, provenance))
            if not all(item.content and item.provenance for item in safe_items):
                return AnalysisResult([], "knowledge-unavailable")
            lineage[record.finding_id] = Retrieval(retrieval.corpus_digest, retrieval.retrieval_digest, tuple(safe_items))
            knowledge.append({"finding_id": record.finding_id, "items": [
                {"provenance": item.provenance, "content": "BEGIN_UNTRUSTED_REFERENCE\n" + item.content +
                 "\nEND_UNTRUSTED_REFERENCE"} for item in safe_items]})
    except Exception:
        return AnalysisResult([], "knowledge-unavailable")
    facts = [record.model_dump() for record in grouped]
    if model_call is None:
        try:
            from . import llm
            prompt = (Path(__file__).parent / "prompts" / "charter-system-prompt.md").read_text(encoding="utf-8")
            model_output = llm.checked_chat([
                llm.Msg("system", prompt, llm.operator()),
                llm.Msg("user", json.dumps({"findings": facts, "knowledge": knowledge}, ensure_ascii=False),
                        llm.target_derived(source="week1-submission-aggregate", target="sentinel-week3")),
            ], model=model, max_tokens=1200, response_format=_enrichment_response_format(len(facts)))
        except Exception:
            return AnalysisResult([], "live-preflight-failed")
    else:
        try:
            model_output = model_call(facts, knowledge)
        except Exception:
            return AnalysisResult([], "model-output-invalid")
    confidences = _confidence(model_output, grouped)
    if confidences is None:
        return AnalysisResult([], "model-output-invalid")
    report: list[Week3ReportFinding] = []
    for record in grouped:
        source = lineage[record.finding_id]
        report.append(Week3ReportFinding(
            finding_id=record.finding_id, tool=record.tool, scanner=record.scanner, name=record.title,
            severity=record.severity, location=record.location, scanner_evidence=record.evidence,
            explanation=_render_explanation(record),
            remediation=_render_remediation(record, source.items),
            confidence=confidences[record.finding_id], source_ids=record.source_ids,
            knowledge_provenance=sorted({item.provenance for item in source.items}),
            corpus_digest=source.corpus_digest, retrieval_digest=source.retrieval_digest,
        ))
    try:
        write_jsonl_atomic(report_path, report, exclusive=True)
    except Exception:
        return AnalysisResult([], "artifact-publication-failed")
    return AnalysisResult(report)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze a validated Week-2 Sentinel aggregate.")
    parser.add_argument("--week3-aggregate", required=True)
    parser.add_argument("--week3-manifest", required=True)
    parser.add_argument("--week3-report-out", required=True)
    parser.add_argument("--week3-model", default="sast-grok45")
    args = parser.parse_args(argv)
    result = analyze(args.week3_aggregate, args.week3_manifest, args.week3_report_out, model=args.week3_model)
    print(json.dumps({"status": "ok" if result.failure is None else "failed", "failure": result.failure}, sort_keys=True))
    return 0 if result.failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
