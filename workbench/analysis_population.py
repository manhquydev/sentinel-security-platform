"""Frozen all-arm analysis masks and sealed B3 input frames."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Sequence

from .comparison_pair import ComparisonPair
from .contracts import ExperimentSpec
from .intake import IntakeViolation, RepositoryIntake
from agent import pii
from infra.litellm.guardrails import egress_redaction


class AnalysisPopulationViolation(ValueError):
    """Raised when a population could make B3's information budget mutable."""


def _digest(value: object) -> str:
    if isinstance(value, Mapping):
        value = dict(value)
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class SelectionManifest:
    """Public source-free manifest plus host-only slices held in process memory."""

    document: Mapping[str, object]
    _slices: Mapping[str, tuple[str, str]]
    _authority_token: object

    @property
    def digest(self) -> str:
        return _digest(self.document)

    @property
    def unit_ids(self) -> frozenset[str]:
        return frozenset(self._slices)

    def slice_for(self, unit_id: str) -> tuple[str, str]:
        try:
            return self._slices[unit_id]
        except KeyError as error:
            raise AnalysisPopulationViolation("B3 unit is not in the frozen sealed selection frame") from error

    def is_authorized(self) -> bool:
        return self._authority_token is _SELECTION_AUTHORITY


_SELECTION_AUTHORITY = object()


def _read_lines(intake: RepositoryIntake, snapshot_id: str, path: str, start_line: int, end_line: int) -> str:
    try:
        data = intake.read_sealed_file(snapshot_id, path)
    except IntakeViolation as error:
        raise AnalysisPopulationViolation("selection references a file outside the sealed candidate snapshot") from error
    try:
        lines = data.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError as error:
        raise AnalysisPopulationViolation("sealed selection source is not UTF-8") from error
    if not isinstance(start_line, int) or isinstance(start_line, bool) or not isinstance(end_line, int) or isinstance(end_line, bool):
        raise AnalysisPopulationViolation("selection line bounds must be integers")
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        raise AnalysisPopulationViolation("selection line bounds are outside the sealed file")
    value = "".join(lines[start_line - 1 : end_line])
    if not value:
        raise AnalysisPopulationViolation("selection canonical unit cannot be empty")
    return value


def build_selection_manifest(
    spec: ExperimentSpec,
    intake: RepositoryIntake,
    pair: ComparisonPair,
    units: Sequence[Mapping[str, object]],
) -> SelectionManifest:
    """Bind source-free B3 request metadata to slices read only from sealed bytes."""
    if not isinstance(units, Sequence) or len(units) < spec.data["review_packets_per_arm"]:
        raise AnalysisPopulationViolation("analysis population must retain at least twelve admissible units")
    try:
        candidate = intake.resolve_snapshot(pair.candidate_snapshot_id)
    except IntakeViolation as error:
        raise AnalysisPopulationViolation("selection requires the pair's intact sealed candidate snapshot") from error
    if candidate.repository_identity != pair.repository_identity:
        raise AnalysisPopulationViolation("selection pair identity does not bind its candidate snapshot")
    if not pair.is_authorized():
        raise AnalysisPopulationViolation("selection requires a host-issued verified comparison pair")

    normalized: list[dict[str, object]] = []
    slices: dict[str, tuple[str, str]] = {}
    seen: set[str] = set()
    for unit in units:
        required = {"unit_id", "path", "start_line", "end_line", "dependency_paths"}
        if not isinstance(unit, Mapping) or set(unit) != required:
            raise AnalysisPopulationViolation("selection unit must use the exact sealed descriptor fields")
        unit_id = unit["unit_id"]
        path = unit["path"]
        dependencies = unit["dependency_paths"]
        if (
            not isinstance(unit_id, str)
            or not unit_id
            or unit_id in seen
            or not isinstance(path, str)
            or not path
            or not isinstance(dependencies, list)
            or not dependencies
            or not all(isinstance(item, str) and item for item in dependencies)
            or len(set(dependencies)) != len(dependencies)
        ):
            raise AnalysisPopulationViolation("selection units need unique labelled sealed descriptors")
        canonical = _read_lines(intake, candidate.snapshot_id, path, unit["start_line"], unit["end_line"])
        try:
            context = b"".join(
                intake.read_sealed_file(candidate.snapshot_id, dependency) for dependency in dependencies
            ).decode("utf-8")
        except (IntakeViolation, UnicodeDecodeError) as error:
            raise AnalysisPopulationViolation("selection dependency context must be read from sealed UTF-8 files") from error
        try:
            canonical_secret, canonical_secret_findings = egress_redaction.redact(canonical)
            context_secret, context_secret_findings = egress_redaction.redact(context)
            canonical, canonical_pii_findings = pii.redact(canonical_secret)
            context, context_pii_findings = pii.redact(context_secret)
        except Exception as error:
            raise AnalysisPopulationViolation("selection redaction admission failed closed") from error
        secret_findings = [*canonical_secret_findings, *context_secret_findings]
        pii_findings = [*canonical_pii_findings, *context_pii_findings]
        if any(finding.get("redacted") is not True for finding in secret_findings):
            raise AnalysisPopulationViolation("selection contains unredacted credential-like material")
        if not isinstance(canonical, str) or not isinstance(context, str):
            raise AnalysisPopulationViolation("selection redaction returned an invalid body")
        if len(context.encode("utf-8")) > spec.data["b3_context_cap_bytes"]:
            raise AnalysisPopulationViolation("selection dependency context violates the frozen byte cap")
        seen.add(unit_id)
        slices[unit_id] = (canonical, context)
        normalized.append(
            {
                "unit_id": unit_id,
                "canonical_unit_digest": _digest(canonical),
                "canonical_unit_bytes": len(canonical.encode("utf-8")),
                "dependency_context_digest": _digest(context),
                "dependency_context_bytes": len(context.encode("utf-8")),
            }
        )
    normalized.sort(key=lambda item: str(item["unit_id"]))
    sorted_slices = {str(item["unit_id"]): slices[str(item["unit_id"])] for item in normalized}
    unit_ids = list(sorted_slices)
    mask_digest = _digest(unit_ids)
    b3_frame_digest = _digest(normalized)
    arms = {
        "B0": {"analysis_mask_digest": mask_digest, "information_inputs": ["candidate-snapshot"]},
        "B1": {"analysis_mask_digest": mask_digest, "information_inputs": ["sealed-pair-diff", "conservative-closure"]},
        "B2": {"analysis_mask_digest": mask_digest, "information_inputs": ["candidate-snapshot", "stable-order"]},
        "B3": {
            "analysis_mask_digest": mask_digest,
            "information_inputs": ["canonical-unit", "sealed-dependency-context"],
            "readings": spec.data["b3_readings"],
            "request_granularity": "one-unit-per-request",
            "follow_up": False,
            "batching": False,
            "context_cap_bytes": spec.data["b3_context_cap_bytes"],
        },
    }
    document = {
        "schema_version": "sentinel-workbench-selection-manifest/v1",
        "experiment_spec_digest": spec.digest,
        "pair_digest": pair.pair_digest,
        "candidate_snapshot_id": candidate.snapshot_id,
        "redaction_admitted": True,
        "analysis_mask_digest": mask_digest,
        "candidate_truth_denominator_digest": mask_digest,
        "unit_ids": unit_ids,
        "b3_input_frame": normalized,
        "b3_input_frame_digest": b3_frame_digest,
        "b3_requests": len(normalized) * spec.data["b3_readings"],
        "resource_vector": {
            "review_seconds_per_packet": spec.data["review_seconds_per_packet"],
            "b3_readings": spec.data["b3_readings"],
            "b3_requests": len(normalized) * spec.data["b3_readings"],
            "context_cap_bytes": spec.data["b3_context_cap_bytes"],
            "batching": False,
            "follow_up": False,
            "stream": False,
            "temperature": spec.data["b3_temperature"],
            "top_p": spec.data["b3_top_p"],
            "output_cap_tokens": spec.data["b3_output_cap_tokens"],
        },
        "arms": arms,
    }
    return SelectionManifest(MappingProxyType(document), MappingProxyType(sorted_slices), _SELECTION_AUTHORITY)
