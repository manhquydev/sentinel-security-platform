"""Strict, versioned contracts for the Sentinel charter analysis artifacts.

Scanner boundaries produce typed, sanitized records (currently Nuclei JSONL and
the CI Trivy JSON handoff). Nothing downstream accepts a partially-normalized
stream: callers first obtain a complete in-memory result and only then publish it
with :func:`write_jsonl_atomic`.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

NORMALIZED_SCHEMA_VERSION = "1.0"
REPORT_SCHEMA_VERSION = "1.0"
Severity = Literal["Critical", "High", "Medium", "Low", "Info"]
_FORBID = ConfigDict(extra="forbid")


class NormalizedFinding(BaseModel):
    """A deterministic projection of one or more sanitized scanner alerts."""

    model_config = _FORBID
    schema_version: Literal["1.0"] = NORMALIZED_SCHEMA_VERSION
    finding_id: str = Field(min_length=12)
    source_ids: list[str] = Field(min_length=1)
    # Common scanner record: tool/scanner provenance remains explicit so a CI
    # Trivy artifact can never be misrepresented as an HTTP/Nuclei observation.
    tool: Literal["nuclei", "trivy"]
    scanner: Literal["DAST", "SAST", "SCA"]
    title: str = Field(min_length=1)
    severity: Severity
    cwe: int | None = Field(default=None, ge=1)
    location: str = Field(min_length=1)
    evidence: list[str] = Field(min_length=1)

    @field_validator("source_ids", "evidence")
    @classmethod
    def _unique_nonempty(cls, values: list[str]) -> list[str]:
        if any(not value or not isinstance(value, str) for value in values):
            raise ValueError("values must be non-empty strings")
        if len(values) != len(set(values)):
            raise ValueError("values must be unique")
        return values


class ReportFinding(BaseModel):
    """The stable, per-finding JSONL report presented to the charter user."""

    model_config = _FORBID
    schema_version: Literal["1.0"] = REPORT_SCHEMA_VERSION
    finding_id: str
    name: str = Field(min_length=1)
    severity: Severity
    location: str = Field(min_length=1)
    scanner_evidence: list[str] = Field(min_length=1)
    explanation: str = Field(min_length=1)
    remediation: str = Field(min_length=1)
    confidence: Literal["low", "medium", "high"]
    source_ids: list[str] = Field(min_length=1)
    knowledge_provenance: list[str] = Field(min_length=1)


class AnalysisFailure(BaseModel):
    """Typed failure returned to the caller; it is intentionally not a published artifact."""

    model_config = _FORBID
    schema_version: Literal["1.0"] = "1.0"
    code: Literal[
        "empty-input", "malformed-input", "invalid-record", "metadata-mismatch", "knowledge-unavailable",
        "model-output-invalid", "live-preflight-failed", "artifact-publication-failed",
    ]
    message: str = Field(min_length=1)
    line: int | None = Field(default=None, ge=1)


@dataclass(frozen=True)
class ContractResult:
    records: list[NormalizedFinding]
    failure: AnalysisFailure | None = None

    @property
    def ok(self) -> bool:
        return self.failure is None


def write_jsonl_atomic(
    path: str | os.PathLike[str], records: list[BaseModel], *, exclusive: bool = False,
) -> None:
    """Publish a fully validated JSONL artifact atomically with private file permissions.

    The caller must not pass an empty list: absence is the contract for an empty/invalid run,
    preventing a misleading empty success artifact from escaping a failed analysis.
    """
    if not records:
        raise ValueError("refusing to publish an empty JSONL artifact")
    destination = Path(path)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            for record in records:
                handle.write(record.model_dump_json(exclude_none=True, by_alias=True))
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if exclusive:
            # link(2) is an exclusive publication primitive: it never replaces a
            # pre-existing regular file or a symlink supplied by another actor.
            os.link(temporary, destination)
        else:
            os.replace(temporary, destination)
        os.chmod(destination, 0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    else:
        # exclusive publication retains the staging hard-link until we remove
        # it; the destination remains the sole published artifact.
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


class ArtifactPublicationError(RuntimeError):
    """A paired charter artifact could not be published without exposing a partial result."""


def _stage_jsonl(destination: Path, records: list[BaseModel]) -> Path:
    if not records:
        raise ValueError("refusing to publish an empty JSONL artifact")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.stage.", dir=destination.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            for record in records:
                handle.write(record.model_dump_json(exclude_none=True, by_alias=True))
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        return Path(temporary)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _unlink_if_staged(destination: Path, staged: Path) -> None:
    """Remove only a file this transaction created; never delete a caller artifact."""
    try:
        if destination.exists() and os.path.samestat(destination.stat(), staged.stat()):
            destination.unlink()
    except FileNotFoundError:
        pass


def write_jsonl_pair_atomic(
    normalized_path: str | os.PathLike[str], normalized_records: list[BaseModel],
    report_path: str | os.PathLike[str], report_records: list[BaseModel],
) -> None:
    """Commit a new normalized/report pair or publish neither file.

    A multi-directory rename cannot be atomic.  Instead both files are fully staged in their
    destination directories, then hard-linked into *previously absent* destination names.  Link
    creation never overwrites a caller-owned artifact.  If the second link fails, the first is
    removed only after inode comparison proves it is this transaction's file.
    """
    normalized_destination = Path(normalized_path)
    report_destination = Path(report_path)
    if normalized_destination == report_destination:
        raise ArtifactPublicationError("normalized and report destinations must differ")
    normalized_stage: Path | None = None
    report_stage: Path | None = None
    normalized_published = False
    report_published = False
    try:
        normalized_stage = _stage_jsonl(normalized_destination, normalized_records)
        report_stage = _stage_jsonl(report_destination, report_records)
        # link(2) is an exclusive create at the destination: unlike replace(), it cannot clobber
        # a prior caller artifact between validation and commit.
        os.link(normalized_stage, normalized_destination)
        normalized_published = True
        os.link(report_stage, report_destination)
        report_published = True
    except Exception as exc:
        if normalized_published and normalized_stage is not None:
            _unlink_if_staged(normalized_destination, normalized_stage)
        if report_published and report_stage is not None:
            _unlink_if_staged(report_destination, report_stage)
        raise ArtifactPublicationError("paired charter artifact publication failed") from exc
    finally:
        for staged in (normalized_stage, report_stage):
            if staged is not None:
                try:
                    staged.unlink()
                except FileNotFoundError:
                    pass
