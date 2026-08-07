"""Fail-closed comparative corpus admission gates.

Candidates from inventory never become an admitted comparative corpus until
every gate passes *and* independent repository clusters ≥ 20. This module
records gate evidence digests; it never invents truth, licence, or calibration.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

MINIMUM_INDEPENDENT_CLUSTERS = 20

REMAINING_GATES = (
    "frozen-truth-manifest",
    "license-and-authorship-screen",
    "model-cutoff-contamination-screen",
    "independent-outcome-blind-control-audit",
    "separate-non-confirmatory-calibration",
    "at-least-20-independent-repository-clusters",
)


class CorpusGateViolation(ValueError):
    """Raised when gate evidence is malformed (not when a gate simply fails)."""


def _digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _require_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CorpusGateViolation(f"{label} must be an object")
    return value


@dataclass(frozen=True)
class GateResult:
    gate_id: str
    passed: bool
    reason_code: str
    evidence_digest: str | None = None


def _gate_truth(evidence: Mapping[str, Any] | None) -> GateResult:
    gate = "frozen-truth-manifest"
    if not evidence:
        return GateResult(gate, False, "missing-truth-manifest-evidence")
    path = evidence.get("truth_manifest_path")
    if not isinstance(path, str) or not path:
        return GateResult(gate, False, "missing-truth-manifest-path")
    manifest = Path(path)
    if not manifest.is_file() or manifest.is_symlink():
        return GateResult(gate, False, "truth-manifest-unavailable")
    try:
        document = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return GateResult(gate, False, "truth-manifest-unreadable")
    if not isinstance(document, Mapping):
        return GateResult(gate, False, "truth-manifest-invalid")
    # Minimal shape: non-empty findings or anchors; full TruthManifest validation is separate.
    if not document.get("findings") and not document.get("anchors"):
        return GateResult(gate, False, "truth-manifest-empty")
    return GateResult(gate, True, "truth-manifest-present", _digest_file(manifest))


def _gate_license(evidence: Mapping[str, Any] | None) -> GateResult:
    gate = "license-and-authorship-screen"
    if not evidence:
        return GateResult(gate, False, "missing-license-authorship-evidence")
    license_value = evidence.get("license")
    authorship = evidence.get("authorship")
    if not isinstance(license_value, str) or not license_value.strip():
        return GateResult(gate, False, "license-not-screened")
    if authorship != "independent":
        return GateResult(gate, False, "authorship-not-independent")
    return GateResult(
        gate,
        True,
        "license-and-authorship-screened",
        _canonical_digest({"license": license_value, "authorship": authorship}),
    )


def _gate_contamination(evidence: Mapping[str, Any] | None) -> GateResult:
    gate = "model-cutoff-contamination-screen"
    if not evidence:
        return GateResult(gate, False, "missing-contamination-evidence")
    status = evidence.get("model_cutoff_contamination")
    if status != "screened":
        return GateResult(gate, False, "contamination-not-screened")
    record = evidence.get("screen_record_path")
    if isinstance(record, str) and record:
        path = Path(record)
        if path.is_file() and not path.is_symlink():
            return GateResult(gate, True, "contamination-screened", _digest_file(path))
    # Explicit screened status without durable record is not enough for corpus-only.
    return GateResult(gate, False, "contamination-screen-record-missing")


def _gate_control_audit(evidence: Mapping[str, Any] | None) -> GateResult:
    gate = "independent-outcome-blind-control-audit"
    if not evidence:
        return GateResult(gate, False, "missing-control-audit-evidence")
    if evidence.get("outcome_blind") is not True:
        return GateResult(gate, False, "control-audit-not-outcome-blind")
    controls = evidence.get("unplanted_control_ids")
    if not isinstance(controls, list) or not controls:
        return GateResult(gate, False, "control-audit-missing-controls")
    return GateResult(
        gate,
        True,
        "control-audit-recorded",
        _canonical_digest({"outcome_blind": True, "unplanted_control_ids": controls}),
    )


def _gate_calibration(evidence: Mapping[str, Any] | None) -> GateResult:
    gate = "separate-non-confirmatory-calibration"
    if not evidence:
        return GateResult(gate, False, "missing-calibration-evidence")
    if evidence.get("calibration_is_confirmatory") is not False:
        return GateResult(gate, False, "calibration-must-be-non-confirmatory")
    digest = evidence.get("calibration_corpus_digest")
    if not isinstance(digest, str) or len(digest) != 64:
        return GateResult(gate, False, "calibration-digest-missing")
    return GateResult(gate, True, "calibration-non-confirmatory", digest)


def _gate_cluster_count(cluster_count: int) -> GateResult:
    gate = "at-least-20-independent-repository-clusters"
    if cluster_count < MINIMUM_INDEPENDENT_CLUSTERS:
        return GateResult(
            gate,
            False,
            f"clusters-below-minimum:{cluster_count}<{MINIMUM_INDEPENDENT_CLUSTERS}",
        )
    return GateResult(
        gate,
        True,
        "clusters-meet-minimum",
        _canonical_digest({"paired_repository_count": cluster_count}),
    )


def evaluate_inventory_admission(
    inventory: Mapping[str, Any],
    *,
    gate_evidence: Mapping[str, Any] | None = None,
) -> dict[str, object]:
    """Evaluate comparative admission for an inventory document.

    Always returns admission_decision not-admitted unless *all* gates pass and
    cluster count ≥ 20. Even then this function only reports readiness to write a
    catalog row; it never mutates the committed catalog.
    """
    document = _require_mapping(inventory, "inventory")
    if document.get("schema_version") != "sentinel-workbench-candidate-corpus-inventory/v1":
        raise CorpusGateViolation("unsupported inventory schema")
    entries = document.get("entries")
    if not isinstance(entries, list):
        raise CorpusGateViolation("inventory entries must be a list")

    candidates = [
        entry
        for entry in entries
        if isinstance(entry, Mapping)
        and isinstance(entry.get("source_evidence"), Mapping)
        and entry["source_evidence"].get("state") == "candidate-needs-adjudication"
        and isinstance(entry.get("repository_cluster"), str)
    ]
    clusters = sorted({entry["repository_cluster"] for entry in candidates})
    cluster_count = len(clusters)
    evidence = gate_evidence or {}

    results = [
        _gate_truth(evidence.get("truth") if isinstance(evidence.get("truth"), Mapping) else None),
        _gate_license(
            evidence.get("license_authorship")
            if isinstance(evidence.get("license_authorship"), Mapping)
            else None
        ),
        _gate_contamination(
            evidence.get("contamination")
            if isinstance(evidence.get("contamination"), Mapping)
            else None
        ),
        _gate_control_audit(
            evidence.get("control_audit") if isinstance(evidence.get("control_audit"), Mapping) else None
        ),
        _gate_calibration(
            evidence.get("calibration") if isinstance(evidence.get("calibration"), Mapping) else None
        ),
        _gate_cluster_count(cluster_count),
    ]
    open_gates = [item.gate_id for item in results if not item.passed]
    all_passed = not open_gates
    # Honesty rail: never admit with fewer than 20 clusters even if other evidence is supplied.
    if cluster_count < MINIMUM_INDEPENDENT_CLUSTERS:
        all_passed = False
        if "at-least-20-independent-repository-clusters" not in open_gates:
            open_gates.append("at-least-20-independent-repository-clusters")

    return {
        "schema_version": "sentinel-workbench-corpus-admission-ledger/v1",
        "admission_decision": "admitted-ready-for-catalog" if all_passed else "not-admitted",
        "comparative_status": (
            "eligible-corpus-catalogued" if all_passed else "blocked-no-eligible-typescript-corpus"
        ),
        "candidate_count": len(candidates),
        "independent_repository_cluster_count": cluster_count,
        "minimum_independent_repository_clusters": MINIMUM_INDEPENDENT_CLUSTERS,
        "repository_clusters": clusters,
        "gates": [
            {
                "gate_id": item.gate_id,
                "passed": item.passed,
                "reason_code": item.reason_code,
                "evidence_digest": item.evidence_digest,
            }
            for item in results
        ],
        "remaining_gates": open_gates,
        "notes": (
            "Admission ledger is fail-closed. not-admitted remains required until every gate "
            "passes and independent clusters meet the minimum. This does not write the catalog."
        ),
    }
