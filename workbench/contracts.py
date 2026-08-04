"""Fail-closed, digest-bound contracts for the Sentinel research workbench."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, Sequence


class ContractViolation(ValueError):
    """Raised when evidence cannot support a Workbench operation or claim."""


def _canonical_digest(value: object) -> str:
    if isinstance(value, Mapping):
        value = dict(value)
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _require(mapping: Mapping[str, Any], key: str) -> Any:
    if key not in mapping:
        raise ContractViolation(f"missing required field: {key}")
    return mapping[key]


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ContractViolation(f"{label} must be a lowercase sha256 digest")
    return value


def _positive_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ContractViolation(f"{label} must be a positive integer")
    return value


@dataclass(frozen=True)
class ExperimentSpec:
    """The immutable v1 protocol. All field values are intentionally exact."""

    data: Mapping[str, Any]

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ExperimentSpec":
        frozen = {
            "schema_version": "sentinel-workbench-experiment/v1",
            "primary_contrast": "B3-B2",
            "metric": "recall_at_12",
            "b3_readings": 3,
            "b3_consensus_min_readings": 2,
            "review_packets_per_arm": 12,
            "review_seconds_per_packet": 90,
            "b3_context_cap_bytes": 8192,
            "b3_temperature": 0,
            "b3_top_p": 1,
            "b3_output_cap_tokens": 2048,
            "b3_transport": "chat-only",
            "b3_tools_enabled": False,
            "b3_post_dispatch_retry": False,
            "bootstrap_resamples": 10000,
            "bootstrap_seed": 20260804,
            "minimum_paired_repositories": 20,
            "minimum_power": 0.8,
            "minimum_effect": 0.02,
            "calibration_is_confirmatory": False,
        }
        unknown = set(data) - (set(frozen) | {"calibration_corpus_digest"})
        if unknown:
            raise ContractViolation(f"unknown experiment spec fields: {sorted(unknown)}")
        for key, expected in frozen.items():
            actual = _require(data, key)
            if actual != expected:
                raise ContractViolation(f"{key} must equal frozen v1 value {expected!r}")
        calibration_digest = _digest(_require(data, "calibration_corpus_digest"), "calibration_corpus_digest")
        return cls(MappingProxyType({**frozen, "calibration_corpus_digest": calibration_digest}))

    @property
    def digest(self) -> str:
        return _canonical_digest(self.data)


@dataclass(frozen=True)
class TruthMatch:
    claimed_vulnerability_ids: tuple[str, ...]
    not_measured_unit_ids: tuple[str, ...]
    duplicate_claim_unit_ids: tuple[str, ...]


@dataclass(frozen=True)
class TruthManifest:
    candidate_snapshot_digest: str
    negative_universe_unit_ids: tuple[str, ...]
    defects: tuple[dict[str, Any], ...]

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "TruthManifest":
        if _require(data, "schema_version") != "sentinel-workbench-truth-manifest/v1":
            raise ContractViolation("unsupported truth manifest schema_version")
        candidate = _digest(_require(data, "candidate_snapshot_digest"), "candidate_snapshot_digest")
        negatives = _require(data, "negative_universe_unit_ids")
        if not isinstance(negatives, list) or not negatives or not all(isinstance(unit, str) and unit for unit in negatives):
            raise ContractViolation("negative_universe_unit_ids must be a non-empty, labelled list")
        if len(set(negatives)) != len(negatives):
            raise ContractViolation("negative_universe_unit_ids must be unique")
        audit = _require(data, "control_audit")
        if not isinstance(audit, Mapping) or not audit.get("outcome_blind") or not audit.get("auditor"):
            raise ContractViolation("truth requires an independent outcome-blind control audit")
        controls = audit.get("unplanted_control_ids")
        if not isinstance(controls, list) or not controls or not all(isinstance(item, str) and item for item in controls):
            raise ContractViolation("truth control audit requires unplanted controls")
        defects = _require(data, "defects")
        if not isinstance(defects, list) or not defects:
            raise ContractViolation("truth manifest requires adjudicated defects")
        seen_ids: set[str] = set()
        claimed_units: set[str] = set()
        normalized: list[dict[str, Any]] = []
        for defect in defects:
            if not isinstance(defect, Mapping):
                raise ContractViolation("truth defect must be an object")
            required = ("vulnerability_id", "class", "precondition", "canonical_unit_id", "allowed_alternatives", "provenance", "license")
            for field in required:
                if not isinstance(_require(defect, field), str if field != "allowed_alternatives" else list):
                    raise ContractViolation(f"truth defect {field} has invalid type")
            vulnerability_id = defect["vulnerability_id"]
            canonical = defect["canonical_unit_id"]
            alternatives = defect["allowed_alternatives"]
            if not vulnerability_id or vulnerability_id in seen_ids:
                raise ContractViolation("truth vulnerability IDs must be unique and labelled")
            if not canonical:
                raise ContractViolation("truth canonical units must be unique and labelled")
            if not alternatives or not all(isinstance(unit, str) and unit for unit in alternatives):
                raise ContractViolation("truth alternatives must be non-empty labelled spans")
            if canonical in negatives or set(alternatives) & set(negatives):
                raise ContractViolation("truth alternatives must not leak into negative universe")
            units_for_defect = (canonical, *alternatives)
            if len(set(units_for_defect)) != len(units_for_defect) or claimed_units.intersection(units_for_defect):
                raise ContractViolation("a truth unit/span must belong to exactly one vulnerability")
            seen_ids.add(vulnerability_id)
            claimed_units.update(units_for_defect)
            normalized.append(dict(defect))
        return cls(candidate, tuple(negatives), tuple(normalized))

    def match_proposals(self, proposed_unit_ids: Sequence[str]) -> TruthMatch:
        by_unit: dict[str, str] = {}
        for defect in self.defects:
            vulnerability_id = defect["vulnerability_id"]
            by_unit[defect["canonical_unit_id"]] = vulnerability_id
            for unit in defect["allowed_alternatives"]:
                by_unit[unit] = vulnerability_id
        claimed: list[str] = []
        duplicates: list[str] = []
        not_measured: list[str] = []
        claimed_ids: set[str] = set()
        for unit in proposed_unit_ids:
            vulnerability_id = by_unit.get(unit)
            if vulnerability_id is None:
                not_measured.append(unit)
            elif vulnerability_id in claimed_ids:
                duplicates.append(unit)
            else:
                claimed_ids.add(vulnerability_id)
                claimed.append(vulnerability_id)
        return TruthMatch(tuple(claimed), tuple(not_measured), tuple(duplicates))


_ADMISSION_OUTCOMES = {
    "case-study-only",
    "rejected",
    "underpowered/descriptive",
    "contamination-bound",
    "corpus-only",
}


def validate_corpus_catalog(document: Mapping[str, Any]) -> None:
    if _require(document, "schema_version") != "sentinel-workbench-corpus-catalog/v1":
        raise ContractViolation("unsupported corpus catalog schema_version")
    corpora = _require(document, "corpora")
    if not isinstance(corpora, list) or not corpora:
        raise ContractViolation("corpus catalog must include at least one auditable record")
    identifiers: set[str] = set()
    eligible = 0
    for corpus in corpora:
        if not isinstance(corpus, Mapping):
            raise ContractViolation("corpus entry must be an object")
        corpus_id = _require(corpus, "corpus_id")
        if not isinstance(corpus_id, str) or not corpus_id or corpus_id in identifiers:
            raise ContractViolation("corpus_id must be unique and labelled")
        identifiers.add(corpus_id)
        outcome = _require(corpus, "admission_outcome")
        if outcome not in _ADMISSION_OUTCOMES:
            raise ContractViolation("unsupported corpus admission outcome")
        if corpus.get("private_code_capability_claim"):
            raise ContractViolation("v1 workbench cannot claim private-code capability")
        for field in ("base_snapshot_digest", "candidate_snapshot_digest", "pair_digest"):
            _digest(_require(corpus, field), f"{corpus_id}.{field}")
        truth_digest = corpus.get("truth_manifest_digest")
        truth_status = corpus.get("truth_status")
        if outcome == "case-study-only" and truth_status == "not-admitted":
            if truth_digest is not None:
                raise ContractViolation("case-study-only corpus without truth must not invent a truth digest")
        else:
            _digest(_require(corpus, "truth_manifest_digest"), f"{corpus_id}.truth_manifest_digest")
        for field in ("license", "authorship", "model_cutoff_contamination"):
            if not isinstance(_require(corpus, field), str) or not corpus[field]:
                raise ContractViolation(f"{corpus_id}.{field} must be a labelled string")
        for field in ("base_revision", "candidate_revision", "snapshot_method"):
            if not isinstance(_require(corpus, field), str) or not corpus[field]:
                raise ContractViolation(f"{corpus_id}.{field} must be a labelled string")
        for field in ("language_counts", "class_counts"):
            values = _require(corpus, field)
            if not isinstance(values, Mapping) or not values or not all(isinstance(key, str) and _positive_int(value, field) for key, value in values.items()):
                raise ContractViolation(f"{corpus_id}.{field} must be non-empty positive counts")
        repository_count = _positive_int(_require(corpus, "repository_count"), f"{corpus_id}.repository_count")
        repository_power = _require(corpus, "repository_power")
        if not isinstance(repository_power, Mapping):
            raise ContractViolation(f"{corpus_id}.repository_power must be an object")
        paired_count = _positive_int(
            _require(repository_power, "paired_repository_count"), f"{corpus_id}.repository_power.paired_repository_count"
        )
        required_count = _positive_int(
            _require(repository_power, "minimum_required"), f"{corpus_id}.repository_power.minimum_required"
        )
        power_status = _require(repository_power, "status")
        if required_count != 20 or paired_count > repository_count:
            raise ContractViolation(f"{corpus_id}.repository_power is inconsistent with the catalog")
        if outcome == "corpus-only":
            if corpus["language_counts"].get("TypeScript", 0) <= 0:
                raise ContractViolation("comparative corpus must contain TypeScript")
            if repository_count < 20:
                raise ContractViolation("comparative corpus requires at least 20 repositories")
            if corpus["authorship"] != "independent":
                raise ContractViolation("comparative corpus must be independently authored")
            if corpus["model_cutoff_contamination"] != "screened":
                raise ContractViolation("comparative corpus must have a completed model-cutoff contamination screen")
            if power_status != "eligible" or paired_count < required_count:
                raise ContractViolation("comparative corpus must establish its repository-level power eligibility")
            eligible += 1
        elif power_status != "not-applicable-case-study-only":
            raise ContractViolation("non-comparative corpus must retain a non-comparative repository-power status")
    comparative_status = document.get("comparative_status")
    if eligible == 0 and comparative_status != "blocked-no-eligible-typescript-corpus":
        raise ContractViolation("catalog without an eligible corpus must explicitly block comparative work")
    if eligible and comparative_status not in (None, "eligible-corpus-catalogued"):
        raise ContractViolation("eligible corpus catalog has invalid comparative status")


def catalog_digest(document: Mapping[str, Any]) -> str:
    """Digest a validated catalog so a publication cannot detach its admission."""
    validate_corpus_catalog(document)
    return _canonical_digest(document)


def validate_publication(document: Mapping[str, Any], spec: ExperimentSpec, catalog: Mapping[str, Any]) -> None:
    """Reject a result unless every preregistered arm and common population exists."""
    if _require(document, "experiment_spec_digest") != spec.digest:
        raise ContractViolation("publication uses a mismatched experiment spec digest")
    if _require(document, "primary_contrast") != "B3-B2" or _require(document, "metric") != "recall_at_12":
        raise ContractViolation("only the B3-B2 recall_at_12 contrast may be inferential")
    if _require(document, "corpus_catalog_digest") != catalog_digest(catalog):
        raise ContractViolation("publication is not bound to the admitted corpus catalog")
    corpus_id = _require(document, "corpus_id")
    if not isinstance(corpus_id, str) or not corpus_id:
        raise ContractViolation("publication requires a corpus ID")
    selected = next((corpus for corpus in catalog["corpora"] if corpus["corpus_id"] == corpus_id), None)
    if selected is None or selected["admission_outcome"] != "corpus-only":
        raise ContractViolation("only an admitted independent corpus may publish a comparative result")
    if document.get("corpus_admission_outcome") != selected["admission_outcome"]:
        raise ContractViolation("publication corpus outcome does not match its catalog admission")
    if catalog.get("comparative_status") != "eligible-corpus-catalogued":
        raise ContractViolation("catalog does not permit comparative publication")
    for field in ("analysis_mask_digest", "candidate_truth_denominator_digest", "calibration_corpus_digest"):
        _digest(_require(document, field), field)
    if document["calibration_corpus_digest"] != spec.data["calibration_corpus_digest"] or document.get("calibration_is_confirmatory"):
        raise ContractViolation("publication needs the independent non-confirmatory calibration record")
    if _positive_int(_require(document, "eligible_repositories"), "eligible_repositories") < spec.data["minimum_paired_repositories"]:
        raise ContractViolation("publication is underpowered: too few paired repositories")
    power = _require(document, "power")
    if not isinstance(power, (int, float)) or isinstance(power, bool) or power < spec.data["minimum_power"]:
        raise ContractViolation("publication is underpowered: preregistered power not met")
    arms = _require(document, "arms")
    if not isinstance(arms, Mapping) or set(arms) != {"B0", "B1", "B2", "B3"}:
        raise ContractViolation("publication requires exactly B0, B1, B2 and B3 arms")
    for arm_id, arm in arms.items():
        if not isinstance(arm, Mapping) or arm.get("review_packets") != spec.data["review_packets_per_arm"]:
            raise ContractViolation(f"{arm_id} does not preserve the fixed human review budget")
        if arm.get("analysis_mask_digest") != document["analysis_mask_digest"]:
            raise ContractViolation(f"{arm_id} does not use the frozen common analysis mask")
        if not isinstance(arm.get("information_inputs"), list) or not arm["information_inputs"]:
            raise ContractViolation(f"{arm_id} must persist its information inputs")
    b3 = arms["B3"]
    required_b3 = {
        "readings": spec.data["b3_readings"],
        "context_cap_bytes": spec.data["b3_context_cap_bytes"],
    }
    for field, expected in required_b3.items():
        if b3.get(field) != expected:
            raise ContractViolation(f"B3 {field} differs from the frozen protocol")
    if b3.get("information_inputs") != ["canonical-unit", "sealed-dependency-context"]:
        raise ContractViolation("B3 may receive only the canonical unit and sealed dependency context")
    units = _positive_int(_require(b3, "eligible_units"), "B3 eligible_units")
    if b3.get("requests_per_reading") != units:
        raise ContractViolation("B3 must send exactly one request for every eligible unit per reading")
    resource_vector = b3.get("resource_vector")
    if not isinstance(resource_vector, Mapping) or set(resource_vector) != {
        "requests", "source_bytes", "input_tokens", "output_tokens", "cost", "worker_seconds"
    }:
        raise ContractViolation("B3 must persist the complete resource vector")
    if resource_vector["requests"] != units * spec.data["b3_readings"]:
        raise ContractViolation("B3 request resource count does not equal k times the frozen unit mask")
    attempts = _require(document, "repository_attempts")
    if not isinstance(attempts, list) or len(attempts) != document["eligible_repositories"]:
        raise ContractViolation("all eligible repositories and terminal attempts must be present")
    identifiers: set[str] = set()
    for attempt in attempts:
        if not isinstance(attempt, Mapping) or attempt.get("terminal") != "complete":
            raise ContractViolation("missing or incomplete arm/reading is instrument-invalid")
        repository_id = attempt.get("repository_id")
        if not isinstance(repository_id, str) or not repository_id or repository_id in identifiers:
            raise ContractViolation("repository attempts must have unique IDs")
        identifiers.add(repository_id)
        admissible = attempt.get("admissible_units_by_arm")
        if not isinstance(admissible, Mapping) or set(admissible) != {"B0", "B1", "B2", "B3"}:
            raise ContractViolation("repository attempt has an incomplete arm population")
        if any(count < spec.data["review_packets_per_arm"] for count in admissible.values()):
            raise ContractViolation("an arm has fewer than twelve admissible review units")
    interval = _require(document, "interval")
    if not isinstance(interval, Mapping) or not all(isinstance(interval.get(field), (int, float)) for field in ("lower", "upper")):
        raise ContractViolation("publication requires a paired bootstrap interval")
    if interval["lower"] > interval["upper"]:
        raise ContractViolation("publication interval bounds are reversed")
