#!/usr/bin/env python3
"""The sole private, atomic JSON writer for Sentinel charter run manifests."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


METRICS = (
    "duration_ms", "request_count", "warning_count", "approve_count",
    "reject_count", "llm_error_count", "application_error_count",
)
SENSITIVE_KEY = re.compile(r"(?:token|secret|password|credential|authorization|body)", re.I)
SENSITIVE_VALUE = re.compile(
    r"(?:\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|"
    r"\b(?:\+?\d[ .()-]?){8,15}\b|\b(?:\d[ -]?){13,19}\b)"
)
SHA256 = re.compile(r"[0-9a-f]{64}")
STAGE = re.compile(r"[a-z][a-z0-9-]{0,63}")
RESOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
MODEL_ALIAS = re.compile(r"[a-z][a-z0-9-]{0,63}")
NUCLEI_VERSION = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?")
RELATIVE_PATH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*")

# Resume input is deliberately an enumerated document.  It is tempting to make
# this a generic digest map, but that would let a caller omit an authority while
# still producing a perfectly well-formed aggregate hash.
IDENTITY_FIELDS = {
    "controller": {"sentinel_demo_sha256", "sentinel_manifest_sha256", "stage_order_sha256", "profile", "source", "request_kind"},
    "target_and_scan": {"target_origin", "target_allowlist_sha256", "run_nuclei_sha256", "redact_report_sha256", "scan_and_import_sha256", "template_manifest_sha256", "scanner_runtime"},
    "analysis": {"normalize_findings_sha256", "recon_sha256", "report_sha256", "charter_contracts_sha256", "response_guard_sha256", "pii_sha256", "prompt_sha256", "llm_sha256", "corpus_manifest_sha256", "retrieval_contract_sha256", "model_alias", "model_config_sha256"},
    "gateway_and_request": {"kong_render_script_sha256", "kong_rendered_config_sha256", "charter_requests_sha256", "charter_proposal_sha256", "charter_approval_sha256", "charter_receipt_sha256", "executor_sha256", "adapter_capture_sha256"},
    "evaluation": {"result_report_sha256", "cases_sha256", "gold_sha256"},
    "ci_handoff": {"value"},
}

STAGE_ARTIFACTS = {
    "scan-redact-import": {
        "phase1/scan-admission.json": "scan-admission/v1", "phase1/nuclei.sanitized.jsonl": "nuclei-sanitized-jsonl/v1",
        "phase1/import-intent.json": "import-intent/v1", "phase1/import-observation.json": "import-observation/v1",
    },
    "analysis-report": {"normalized.jsonl": "normalized-jsonl/v1", "report.jsonl": "report-jsonl/v1"},
    "proposal": {"request-spec.json": "request-spec/v1"},
    "approval": {"approval.json": "approval/v1"},
    "executor": {"receipt.json": {"receipt/v1", "receipt/v2"}, "request-descriptor.json": "request-descriptor/v1"},
    "verify-ci-artifact": {"trivy.admitted.json": "trivy-sanitized-json/v1", "trivy.admitted.metadata.json": "trivy-metadata/v1"},
    "ci-normalize-import": {"trivy.normalized.jsonl": "normalized-jsonl/v1"},
}
NO_OUTPUT_STAGES = {"preflight", "labelled-chat", "topology-ready", "response-guard", "final-report", "evaluation", "finalize"}


def fail(message: str) -> None:
    raise SystemExit(message)


def load(path: Path) -> dict:
    try:
        def no_duplicates(pairs: list[tuple[str, object]]) -> dict:
            value: dict[str, object] = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError(f"duplicate key: {key}")
                value[key] = item
            return value
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid manifest: {exc}")


def canonical_json(value: object) -> bytes:
    """The single serialization used for resume identities and ledger hashes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def json_digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def valid_resume_identity(identity: object, source: str) -> None:
    if not isinstance(identity, dict) or set(identity) != {"schema_version", "inputs", "sha256"}:
        fail("invalid resume identity")
    if identity["schema_version"] != "sentinel-charter-resume-identity/v1" or not _is_digest(identity["sha256"]):
        fail("invalid resume identity")
    inputs = identity["inputs"]
    if not isinstance(inputs, dict) or set(inputs) != set(IDENTITY_FIELDS):
        fail("invalid resume identity groups")
    for group, required in IDENTITY_FIELDS.items():
        value = inputs[group]
        if not isinstance(value, dict) or set(value) != required:
            fail("invalid resume identity group")
    controller = inputs["controller"]
    if controller["profile"] != "charter" or controller["source"] != source or controller["request_kind"] not in {"get", "post"}:
        fail("invalid controller resume identity")
    for group, fields in IDENTITY_FIELDS.items():
        for name in fields:
            if name in {"profile", "source", "request_kind", "target_origin", "model_alias", "scanner_runtime", "value"}:
                continue
            if not _is_digest(inputs[group][name]):
                fail("invalid resume identity digest")
    scan = inputs["target_and_scan"]
    if scan["target_origin"] != "http://127.0.0.1:13000":
        fail("invalid target identity")
    runtime = scan["scanner_runtime"]
    if not isinstance(runtime, dict):
        fail("invalid scanner runtime")
    if runtime.get("kind") == "image":
        if set(runtime) != {"kind", "digest"} or not _is_digest(runtime["digest"]):
            fail("invalid image scanner runtime")
    elif runtime.get("kind") == "local-binary":
        if set(runtime) != {"kind", "sha256", "version"} or not _is_digest(runtime["sha256"]) or not isinstance(runtime["version"], str) or not NUCLEI_VERSION.fullmatch(runtime["version"]):
            fail("invalid local scanner runtime")
    else:
        fail("invalid scanner runtime")
    analysis = inputs["analysis"]
    if not isinstance(analysis["model_alias"], str) or not MODEL_ALIAS.fullmatch(analysis["model_alias"]):
        fail("invalid model alias")
    ci = inputs["ci_handoff"]["value"]
    if source == "local":
        if ci != "not-applicable": fail("invalid local ci identity")
    elif not isinstance(ci, dict) or set(ci) != {"type", "version", "artifact_sha256", "metadata_sha256"} or ci["type"] != "trivy-sanitized-json" or ci["version"] != "1" or not _is_digest(ci["artifact_sha256"]) or not _is_digest(ci["metadata_sha256"]):
        fail("invalid ci handoff identity")
    if identity["sha256"] != json_digest(inputs):
        fail("resume identity digest mismatch")


def _safe_relative_path(value: object) -> bool:
    return isinstance(value, str) and RELATIVE_PATH.fullmatch(value) is not None and not value.startswith("/") and ".." not in Path(value).parts


def _typed_json(raw: bytes, kind: str) -> dict:
    try:
        # Type/version admission is separate from the response-guard's strict
        # duplicate-key receipt decoder.  A persisted receipt remains
        # checkpointed evidence; the response guard is the designated boundary
        # that reports a duplicate-key receipt as an executor contract failure.
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict): raise ValueError("non-object JSON")
        return value
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        fail(f"invalid {kind} artifact: {exc}")


def _parse_artifact(kind: str, raw: bytes) -> None:
    """Validate each closed ledger kind, not merely that its bytes are JSON."""
    if kind.endswith("jsonl/v1"):
        try:
            rows = [_typed_json(line.encode("utf-8"), kind) for line in raw.decode("utf-8").splitlines() if line]
        except UnicodeDecodeError as exc:
            fail(f"invalid {kind} artifact: {exc}")
        if not rows: fail(f"invalid {kind} artifact: empty JSONL")
        if kind in {"normalized-jsonl/v1", "report-jsonl/v1"} and any(row.get("schema_version") != "1.0" for row in rows):
            fail(f"invalid {kind} artifact: wrong schema version")
        return
    if kind in {"receipt/v1", "receipt/v2"}:
        try:
            from agent.charter_receipt import ReceiptContractError, decode_object
            value = decode_object(raw)
        except (ImportError, ReceiptContractError) as exc:
            fail(f"invalid {kind} artifact: {exc}")
    else:
        value = _typed_json(raw, kind)
    if kind == "scan-admission/v1":
        if value.get("schema_version") != "sentinel-scan-admission/v1": fail("invalid scan-admission/v1 artifact")
    elif kind == "import-intent/v1":
        if (value.get("state") != "intent" or value.get("scanner") != "nuclei" or value.get("scan_type") != "Nuclei Scan"
                or value.get("test_title") != "Sentinel charter nuclei" or not _is_digest(value.get("sanitized_sha256"))
                or value.get("request") != {"close_old_findings": False, "deduplication_execution_mode": "async_wait"}):
            fail("invalid import-intent/v1 artifact")
    elif kind == "import-observation/v1":
        gate = value.get("gate")
        if (value.get("state") != "completed" or not _is_digest(value.get("sanitized_sha256"))
                or not isinstance(value.get("remote_test_id"), (str, int)) or not str(value["remote_test_id"])
                or not _is_digest(value.get("response_sha256"))
                or not isinstance(gate, dict) or gate.get("state") != "passed"
                or type(gate.get("reported")) is not int or gate["reported"] < 0):
            fail("invalid import-observation/v1 artifact")
    elif kind == "request-spec/v1":
        # The immutable-policy check belongs to the approval/executor boundary.
        # Ledger validation proves this is one exact JSON object; it must not
        # turn an existing invalid-spec preflight fixture into a different
        # resume failure before that boundary can report it.
        if not value:
            fail("invalid request-spec/v1 artifact")
    elif kind == "approval/v1":
        required = {"decision_id", "decision", "request_id", "run_id", "spec_digest", "policy_digest", "issued_at", "expires_at", "nonce", "signature"}
        if (set(value) != required or value.get("decision") not in {"approve", "reject", "revoke"}
                or not all(isinstance(value.get(key), str) and value[key] for key in required - {"decision", "issued_at", "expires_at"})
                or type(value.get("issued_at")) not in {int, float} or type(value.get("expires_at")) not in {int, float}):
            fail("invalid approval/v1 artifact")
    elif kind == "receipt/v1":
        if (value.get("schema_version") != "sentinel-charter-receipt/v1"
                or set(value) != {"schema_version", "request_id", "status", "bytes", "receipt_digest"}
                or not isinstance(value.get("request_id"), str) or not value["request_id"]
                or type(value.get("status")) is not int or type(value.get("bytes")) is not int
                or not _is_digest(value.get("receipt_digest"))):
            fail("invalid receipt/v1 artifact")
    elif kind == "receipt/v2":
        allowed = {"media-missing", "media-duplicate", "media-malformed", "media-unsupported", "decode-invalid-utf8", "objective-change", "secret-disclosure", "out-of-scope-tool", "pii-card", "pii-phone", "pii-email", "pii-jwt", "pii-uuid"}
        common = {"schema_version", "request_id", "status", "bytes", "receipt_digest"}
        if (value.get("schema_version") != "sentinel-charter-receipt/v2" or not isinstance(value.get("request_id"), str) or not value["request_id"]
                or type(value.get("status")) is not int or not 200 <= value["status"] < 300
                or type(value.get("bytes")) is not int or not 0 <= value["bytes"] <= 65536
                or not _is_digest(value.get("receipt_digest"))):
            fail("invalid receipt/v2 artifact")
        if set(value) == common | {"preview", "preview_truncated"}:
            if (not isinstance(value["preview"], str) or len(value["preview"]) > 256
                    or type(value["preview_truncated"]) is not bool):
                fail("invalid receipt/v2 artifact")
            try:
                if len(value["preview"].encode("utf-8", "strict")) > 512:
                    fail("invalid receipt/v2 artifact")
            except UnicodeEncodeError:
                fail("invalid receipt/v2 artifact")
        elif set(value) == common | {"quarantine"}:
            quarantine = value["quarantine"]
            if (not isinstance(quarantine, dict) or not quarantine or any(key not in allowed or type(count) is not int or not 1 <= count <= 65536 for key, count in quarantine.items())):
                fail("invalid receipt/v2 artifact")
        else:
            fail("invalid receipt/v2 artifact")
    elif kind == "request-descriptor/v1":
        if value != {"schema_version": "sentinel-request-descriptor/v1", "receipt": "receipt.json"}:
            fail("invalid request-descriptor/v1 artifact")
    elif kind == "trivy-metadata/v1":
        if set(value) != {"type", "version", "sha256"} or value.get("type") != "trivy-sanitized-json" or value.get("version") != "1" or not _is_digest(value.get("sha256")):
            fail("invalid trivy-metadata/v1 artifact")
    elif kind == "trivy-sanitized-json/v1":
        if value.get("SchemaVersion") != 2 or value.get("ArtifactType") != "filesystem" or not isinstance(value.get("Results"), list):
            fail("invalid trivy-sanitized-json/v1 artifact")


def valid_artifact_ledger(doc: dict, run_root: Path | None = None) -> None:
    ledger = doc.get("artifact_ledger")
    if not isinstance(ledger, list): fail("invalid artifact ledger")
    # JSON is written with sorted keys, so map iteration is lexical rather than
    # controller progression order.  The immutable stored index is the ledger's
    # sole ordering authority.
    passed = sorted(
        ((name, record) for name, record in doc["stages"].items() if record["status"] == "passed"),
        key=lambda item: item[1]["index"],
    )
    if len(ledger) != len(passed): fail("missing artifact checkpoint")
    paths: set[str] = set()
    for position, (checkpoint, (stage, record)) in enumerate(zip(ledger, passed)):
        if not isinstance(checkpoint, dict) or set(checkpoint) != {"stage", "index", "entries", "sha256"}:
            fail("invalid artifact checkpoint")
        if checkpoint["stage"] != stage or checkpoint["index"] != record["index"] or not isinstance(checkpoint["entries"], list) or not _is_digest(checkpoint["sha256"]):
            fail(f"detached artifact checkpoint: expected {stage}/{record['index']} got {checkpoint.get('stage')}/{checkpoint.get('index')}")
        proof = {"stage": checkpoint["stage"], "index": checkpoint["index"], "entries": checkpoint["entries"]}
        if checkpoint["sha256"] != json_digest(proof) or record.get("checkpoint_sha256") != checkpoint["sha256"]:
            fail("artifact checkpoint digest mismatch")
        expected = STAGE_ARTIFACTS.get(stage, {})
        if stage not in STAGE_ARTIFACTS and stage not in NO_OUTPUT_STAGES: expected = {}
        got: dict[str, str] = {}
        for entry in checkpoint["entries"]:
            if not isinstance(entry, dict) or set(entry) != {"path", "type", "sha256"} or not _safe_relative_path(entry["path"]) or not isinstance(entry["type"], str) or not _is_digest(entry["sha256"]):
                fail("invalid artifact ledger entry")
            if entry["path"] in paths or entry["path"] in got: fail("duplicate artifact ledger path")
            paths.add(entry["path"]); got[entry["path"]] = entry["type"]
            if run_root is not None:
                raw = regular_bytes(run_root / entry["path"], root=run_root, nonempty=True)
                if digest(raw) != entry["sha256"]: fail("artifact digest mismatch")
                _parse_artifact(entry["type"], raw)
        if set(got) != set(expected) or any(
                got[path] != allowed if isinstance(allowed, str) else got[path] not in allowed
                for path, allowed in expected.items()):
            fail("artifact checkpoint does not match stage contract")


def valid_effect_ledger(doc: dict, run_root: Path | None = None) -> None:
    events = doc.get("effect_ledger")
    if not isinstance(events, list): fail("invalid effect ledger")
    if doc["input"]["source"] == "ci" and events: fail("ci effect ledger must be empty")
    pending: dict[tuple[str, str], dict] = {}
    complete: set[tuple[str, str]] = set()
    observed: set[tuple[str, str]] = set()
    for event in events:
        if not isinstance(event, dict) or not {"stage", "effect", "state", "intent_path", "intent_sha256"}.issubset(event): fail("invalid effect event")
        stage, effect, state = event["stage"], event["effect"], event["state"]
        pair = (stage, effect)
        if (stage, effect) not in {("scan-redact-import", "defectdojo-import"), ("executor", "charter-request")} or state not in {"prepared", "observed", "unknown"} or not _safe_relative_path(event["intent_path"]) or not _is_digest(event["intent_sha256"]):
            fail("invalid effect event")
        exact = {"stage", "effect", "state", "intent_path", "intent_sha256"}
        if state == "observed": exact |= {"observation_path", "observation_sha256"}
        if set(event) != exact: fail("invalid effect event fields")
        if state == "prepared":
            if pair in pending or pair in complete: fail("invalid effect transition")
            pending[pair] = event
        else:
            prior = pending.pop(pair, None)
            if prior is None or prior["intent_path"] != event["intent_path"] or prior["intent_sha256"] != event["intent_sha256"]: fail("invalid effect transition")
            if state == "observed" and (not _safe_relative_path(event["observation_path"]) or not _is_digest(event["observation_sha256"])): fail("invalid observed effect")
            complete.add(pair)
            if state == "observed": observed.add(pair)
        if run_root is not None:
            intent = regular_bytes(run_root / event["intent_path"], root=run_root, nonempty=True)
            if digest(intent) != event["intent_sha256"]: fail("effect intent digest mismatch")
            _parse_artifact("import-intent/v1" if effect == "defectdojo-import" else "request-spec/v1", intent)
            if state == "observed":
                observation = regular_bytes(run_root / event["observation_path"], root=run_root, nonempty=True)
                if digest(observation) != event["observation_sha256"]: fail("effect observation digest mismatch")
                if effect == "defectdojo-import":
                    _parse_artifact("import-observation/v1", observation)
                else:
                    receipt = _typed_json(observation, "receipt observation")
                    schema = receipt.get("schema_version")
                    if schema == "sentinel-charter-receipt/v1":
                        _parse_artifact("receipt/v1", observation)
                    elif schema == "sentinel-charter-receipt/v2":
                        _parse_artifact("receipt/v2", observation)
                    else:
                        fail("invalid receipt observation")
    # A passed remote-producer stage without its terminal observation would make
    # a checkpoint look resumable even though the effect had no durable outcome.
    for stage, effect in (("scan-redact-import", "defectdojo-import"), ("executor", "charter-request")):
        if doc.get("stages", {}).get(stage, {}).get("status") == "passed" and (stage, effect) not in observed:
            fail("passed remote stage lacks observed effect")


def unresolved_effect(doc: dict) -> bool:
    last: dict[tuple[str, str], str] = {}
    for event in doc.get("effect_ledger", []):
        last[(event["stage"], event["effect"])] = event["state"]
    return any(state in {"prepared", "unknown"} for state in last.values())


def incomplete_stage_effect(doc: dict) -> bool:
    """A durable remote outcome without its paired passed checkpoint is not replayable."""
    passed = {
        stage for stage, record in doc.get("stages", {}).items()
        if record.get("status") == "passed"
    }
    return any(event["stage"] not in passed for event in doc.get("effect_ledger", []))


def output_digest(doc: dict) -> str:
    """Hash completed output without making identity.output_sha256 self-referential."""
    value = {
        "input": doc["input"],
        "identity": {key: value for key, value in doc["identity"].items() if key != "output_sha256"},
        "stage_order": doc["stage_order"],
        "stages": doc["stages"],
        "required_skips": doc["required_skips"],
        "metrics": doc["metrics"],
        "result": doc["result"],
    }
    if doc["input"]["source"] == "ci":
        value["ci_handoff"] = doc["ci_handoff"]
    if doc.get("schema_version") == "sentinel-run/v2":
        value["resume_identity"] = doc["resume_identity"]
        value["artifact_ledger"] = doc["artifact_ledger"]
        value["effect_ledger"] = doc["effect_ledger"]
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def valid(doc: dict) -> None:
    def check_sensitive(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if SENSITIVE_KEY.search(str(key)):
                    fail("sensitive manifest key")
                check_sensitive(item)
        elif isinstance(value, list):
            for item in value:
                check_sensitive(item)
        elif isinstance(value, str) and SENSITIVE_VALUE.search(value):
            fail("sensitive manifest value")

    check_sensitive(doc)
    if not isinstance(doc, dict) or doc.get("schema_version") not in {"sentinel-run/v1", "sentinel-run/v2"}:
        fail("invalid manifest schema")
    is_v2 = doc["schema_version"] == "sentinel-run/v2"
    base_fields = {"schema_version", "run_id", "profile", "input", "identity", "stage_order", "stages",
                   "required_skips", "resources", "recovery_hint", "metrics", "result", "created_at_ms"}
    v2_fields = {"resume_identity", "artifact_ledger", "effect_ledger"} if is_v2 else set()
    if not isinstance(doc, dict) or set(doc) - (base_fields | {"ci_handoff", "ci_publication"} | v2_fields) or (is_v2 and not v2_fields.issubset(doc)):
        fail("unexpected manifest field")
    if not isinstance(doc.get("run_id"), str) or not re.fullmatch(r"[A-Za-z0-9._-]+", doc["run_id"]):
        fail("invalid run id")
    if doc.get("profile") != "charter":
        fail("invalid profile")
    input_value = doc.get("input")
    if (not isinstance(input_value, dict) or set(input_value) != {"source", "type", "version", "sha256"}
            or (input_value["source"], input_value["type"], input_value["version"])
            not in {("local", "local-charter-input", "1"), ("ci", "trivy-sanitized-json", "1")}
            or not isinstance(input_value["sha256"], str)
            or not SHA256.fullmatch(input_value["sha256"])):
        fail("invalid input identity")
    is_ci = input_value["source"] == "ci"
    handoff = doc.get("ci_handoff")
    publication = doc.get("ci_publication")
    if is_ci:
        if handoff is not None:
            if (not isinstance(handoff, dict) or set(handoff) != {"metadata_sha256", "normalized_sha256", "binding_core_sha256"}
                    or any(not isinstance(handoff[key], str) or not SHA256.fullmatch(handoff[key]) for key in handoff)):
                fail("invalid ci handoff")
        if publication is not None:
            if (not isinstance(publication, dict) or set(publication) != {"state", "candidate_sha256", "binding_sha256"}
                    or publication["state"] not in {"candidate-planned", "candidate-created", "binding-created"}
                    or any(not isinstance(publication[key], str) or not SHA256.fullmatch(publication[key])
                           for key in ("candidate_sha256", "binding_sha256"))):
                fail("invalid ci publication")
            if handoff is None or doc["result"]["status"] != "pending":
                fail("invalid ci publication state")
    elif handoff is not None or publication is not None:
        fail("local manifest contains ci state")
    identity = doc.get("identity")
    expected_identity = {"target_sha256", "config_sha256", "policy_sha256", "output_sha256"}
    if not isinstance(identity, dict) or set(identity) != expected_identity:
        fail("invalid immutable identity")
    if any(not isinstance(identity[key], str) or not SHA256.fullmatch(identity[key])
           for key in expected_identity - {"output_sha256"}):
        fail("invalid immutable identity")
    if identity["output_sha256"] and not SHA256.fullmatch(identity["output_sha256"]):
        fail("invalid output hash")
    stage_order = doc.get("stage_order")
    if (not isinstance(stage_order, list) or not stage_order or len(set(stage_order)) != len(stage_order)
            or any(not isinstance(name, str) or not STAGE.fullmatch(name) for name in stage_order)):
        fail("invalid stage order")
    stages = doc.get("stages")
    if not isinstance(stages, dict) or any(name not in stage_order for name in stages):
        fail("invalid stages")
    for name, stage in stages.items():
        index = stage_order.index(name)
        allowed_stage = {"status", "at_ms", "index"}
        if is_v2 and isinstance(stage, dict) and stage.get("status") == "passed": allowed_stage.add("checkpoint_sha256")
        if (not isinstance(stage, dict)
                or set(stage) != allowed_stage
                or stage["status"] not in {"passed", "failed", "skipped", "rejected"}
                or not isinstance(stage["at_ms"], int) or stage["at_ms"] < 0
                or stage["index"] != index):
            fail("invalid stage record")
        if is_v2 and stage["status"] == "passed" and not _is_digest(stage.get("checkpoint_sha256")):
            fail("invalid stage checkpoint digest")
    if {stage["index"] for stage in stages.values()} != set(range(len(stages))):
        fail("non-contiguous stages")
    skips = doc.get("required_skips")
    if (not isinstance(skips, list) or len(set(skips)) != len(skips)
            or any(name not in stages or stages[name]["status"] != "skipped" for name in skips)):
        fail("invalid required skips")
    resources = doc.get("resources")
    if not isinstance(resources, list):
        fail("invalid resources")
    for resource in resources:
        if (not isinstance(resource, dict) or set(resource) != {"owner", "kind", "id", "status"}
                or resource["owner"] != "controller" or resource["kind"] != "container"
                or not isinstance(resource["id"], str) or not RESOURCE_ID.fullmatch(resource["id"])
                or resource["status"] not in {"active", "released"}):
            fail("invalid controller resource")
    if len({resource["id"] for resource in resources}) != len(resources):
        fail("duplicate controller resource")
    metrics = doc.get("metrics")
    if (not isinstance(metrics, dict) or metrics.get("version") != "RunMetrics/v1"
            or set(metrics) != {"version", *METRICS}
            or any(not isinstance(metrics[key], int) or metrics[key] < 0 for key in METRICS)):
        fail("invalid RunMetrics/v1")
    result = doc.get("result")
    if (not isinstance(result, dict) or set(result) != {"status", "action_sent"}
            or result["status"] not in {"pending", "passed", "failed", "rejected"}
            or not isinstance(result["action_sent"], bool)):
        fail("invalid result")
    if result["status"] == "passed" and result["action_sent"] != bool(metrics["request_count"]):
        fail("passed action result does not match request metric")
    if result["status"] != "passed" and result["action_sent"]:
        fail("non-passed result cannot send an action")
    if result["status"] == "rejected" and metrics["request_count"] != 0:
        fail("rejected result cannot record a request")
    if not isinstance(doc.get("created_at_ms"), int) or doc["created_at_ms"] < 0:
        fail("invalid created timestamp")
    if doc.get("recovery_hint") != "resume only with exact immutable identity":
        fail("invalid recovery hint")
    if is_v2:
        valid_resume_identity(doc["resume_identity"], input_value["source"])
        valid_artifact_ledger(doc)
        valid_effect_ledger(doc)
    if result["status"] in {"passed", "rejected"}:
        if not identity["output_sha256"] or identity["output_sha256"] != output_digest(doc):
            fail("output hash mismatch")
    elif identity["output_sha256"]:
        fail("unfinished manifest has output hash")
    if is_ci and result["status"] == "passed":
        if handoff is None or publication is not None:
            fail("completed ci manifest lacks terminal handoff")
        if (metrics["request_count"] != 0 or result["action_sent"] or skips
                or stage_order != ["preflight", "labelled-chat", "verify-ci-artifact", "ci-normalize-import"]
                or len(stages) != 4 or any(stages.get(name, {}).get("status") != "passed" for name in stage_order)):
            fail("invalid ci terminal semantics")

def write(path: Path, doc: dict) -> None:
    valid(doc)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd, tmp = tempfile.mkstemp(prefix=".manifest.", dir=path.parent)
    os.fchmod(fd, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(doc, out, sort_keys=True, separators=(",", ":"))
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def complete_output_hash(doc: dict) -> None:
    doc["identity"]["output_sha256"] = output_digest(doc)


def canonical_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def regular_bytes(path: Path, *, root: Path | None = None, mode: int = 0o600, nonempty: bool = False) -> bytes:
    """Read a private file without following its final file or any run-relative parent."""
    try:
        root = root or path.parent
        relative = path.relative_to(root)
        if not _safe_relative_path(relative.as_posix()):
            fail(f"unsafe private file: {path.name}")
        root_stat = root.lstat()
        if root.is_symlink() or not root.is_dir() or root_stat.st_mode & 0o777 != 0o700:
            fail(f"unsafe private directory: {root.name}")
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        try:
            if not os.path.samestat(root_stat, os.fstat(directory_fd)):
                fail(f"raced private directory: {root.name}")
            parts = relative.parts
            for component in parts[:-1]:
                item = os.stat(component, dir_fd=directory_fd, follow_symlinks=False)
                if not stat.S_ISDIR(item.st_mode) or item.st_mode & 0o777 != 0o700:
                    fail(f"unsafe private directory: {component}")
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
                os.close(directory_fd); directory_fd = next_fd
            file_stat = os.stat(parts[-1], dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_mode & 0o777 != mode:
                fail(f"unsafe private file: {path.name}")
            fd = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
        finally:
            os.close(directory_fd)
        try:
            current = os.fstat(fd)
            if not os.path.samestat(file_stat, current):
                fail(f"raced private file: {path.name}")
            chunks = []
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
            value = b"".join(chunks)
        finally:
            os.close(fd)
    except OSError as exc:
        fail(f"unsafe private file: {path.name}: {exc}")
    if nonempty and not value:
        fail(f"empty private file: {path.name}")
    return value


def write_exclusive(path: Path, value: bytes) -> None:
    if path.exists() or path.is_symlink():
        fail(f"refusing existing artifact: {path.name}")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(value); out.flush(); os.fsync(out.fileno())
        os.link(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
    except FileExistsError:
        fail(f"refusing existing artifact: {path.name}")
    finally:
        try: os.unlink(temporary)
        except FileNotFoundError: pass


def binding_core(doc: dict) -> str:
    handoff = doc["ci_handoff"]
    stable = {"schema_version": "sentinel-ci-artifact-binding/v1", "run_id": doc["run_id"],
              "input_sha256": doc["input"]["sha256"], "metadata_sha256": handoff["metadata_sha256"],
              "normalized_sha256": handoff["normalized_sha256"]}
    return digest(canonical_bytes(stable))


def ci_candidate_and_binding(doc: dict) -> tuple[bytes, bytes]:
    candidate = json.loads(json.dumps(doc))
    candidate.pop("ci_publication", None)
    # A checkpoint stores hashes, not a second copy of the candidate.  Keep the
    # candidate derivation stable across a crash/restart; elapsed wall time is not
    # a trustworthy recovery input and therefore remains the pending metric (0).
    candidate["result"] = {"status": "passed", "action_sent": False}
    complete_output_hash(candidate)
    valid(candidate)
    candidate_bytes = canonical_bytes(candidate)
    handoff = candidate["ci_handoff"]
    binding = {"schema_version": "sentinel-ci-artifact-binding/v1", "run_id": candidate["run_id"],
               "input_sha256": candidate["input"]["sha256"], "metadata_sha256": handoff["metadata_sha256"],
               "manifest_output_sha256": candidate["identity"]["output_sha256"], "manifest_sha256": digest(candidate_bytes),
               "normalized_sha256": handoff["normalized_sha256"]}
    return candidate_bytes, canonical_bytes(binding)


def ci_publish(path: Path) -> None:
    """Recover exactly the five allowed CI publication states; never replay stages."""
    doc = load(path); valid(doc)
    if doc["input"]["source"] != "ci" or doc["result"]["status"] != "pending":
        fail("ci publication requires a pending ci manifest")
    run = path.parent
    normalized = regular_bytes(run / "trivy.normalized.jsonl", nonempty=True)
    metadata = regular_bytes(run / "trivy.admitted.metadata.json", nonempty=True)
    artifact = regular_bytes(run / "trivy.admitted.json", nonempty=True)
    if digest(artifact) != doc["input"]["sha256"]:
        fail("admitted artifact digest mismatch")
    if "ci_handoff" not in doc:
        doc["ci_handoff"] = {"metadata_sha256": digest(metadata), "normalized_sha256": digest(normalized), "binding_core_sha256": ""}
        doc["ci_handoff"]["binding_core_sha256"] = binding_core(doc)
    handoff = doc["ci_handoff"]
    if digest(metadata) != handoff["metadata_sha256"] or digest(normalized) != handoff["normalized_sha256"] or binding_core(doc) != handoff["binding_core_sha256"]:
        fail("ci handoff anchor mismatch")
    candidate, binding = ci_candidate_and_binding(doc)
    candidate_path, binding_path = run / "manifest.final.json", run / "ci-artifact-binding.json"
    if "ci_publication" not in doc:
        doc["ci_publication"] = {"state": "candidate-planned", "candidate_sha256": digest(candidate), "binding_sha256": digest(binding)}
        write(path, doc)
    else:
        publication = doc["ci_publication"]
        if publication["candidate_sha256"] != digest(candidate) or publication["binding_sha256"] != digest(binding):
            fail("ci publication checkpoint mismatch")
    state = load(path)["ci_publication"]["state"]
    if state == "candidate-planned":
        # The recovery table permits no binding at this checkpoint.  Even an
        # exact-looking one is unexpected evidence and must not advance state.
        if binding_path.exists() or binding_path.is_symlink():
            fail("binding unexpectedly exists before candidate checkpoint")
        if candidate_path.exists() or candidate_path.is_symlink():
            if regular_bytes(candidate_path) != candidate:
                fail("candidate differs from checkpoint")
        else:
            write_exclusive(candidate_path, candidate)
        doc = load(path); doc["ci_publication"]["state"] = "candidate-created"; write(path, doc); state = "candidate-created"
    if state == "candidate-created":
        if regular_bytes(candidate_path) != candidate:
            fail("candidate differs from checkpoint")
        if binding_path.exists() or binding_path.is_symlink():
            if regular_bytes(binding_path) != binding:
                fail("binding differs from checkpoint")
        else:
            write_exclusive(binding_path, binding)
        doc = load(path); doc["ci_publication"]["state"] = "binding-created"; write(path, doc); state = "binding-created"
    if state != "binding-created" or regular_bytes(candidate_path) != candidate or regular_bytes(binding_path) != binding:
        fail("incomplete ci publication")
    # Candidate is private and fully validated; its rename atomically replaces only
    # the controller's pending manifest and leaves no final candidate artifact.
    os.replace(candidate_path, path)
    if regular_bytes(path) != candidate:
        fail("final manifest install mismatch")


def ci_verify(path: Path) -> None:
    doc = load(path); valid(doc)
    if doc["input"]["source"] != "ci": fail("not a ci manifest")
    run = path.parent
    artifact = regular_bytes(run / "trivy.admitted.json", nonempty=True)
    metadata = regular_bytes(run / "trivy.admitted.metadata.json", nonempty=True)
    normalized = regular_bytes(run / "trivy.normalized.jsonl", nonempty=True)
    binding_raw = regular_bytes(run / "ci-artifact-binding.json", nonempty=True)
    if digest(artifact) != doc["input"]["sha256"] or digest(metadata) != doc["ci_handoff"]["metadata_sha256"] or digest(normalized) != doc["ci_handoff"]["normalized_sha256"]:
        fail("ci artifact hash mismatch")
    try:
        binding = json.loads(binding_raw.decode("utf-8"), object_pairs_hook=lambda pairs: _unique_object(pairs))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        fail(f"invalid ci binding: {exc}")
    expected = {"schema_version": "sentinel-ci-artifact-binding/v1", "run_id": doc["run_id"], "input_sha256": doc["input"]["sha256"],
                "metadata_sha256": doc["ci_handoff"]["metadata_sha256"], "manifest_output_sha256": doc["identity"]["output_sha256"],
                "manifest_sha256": digest(regular_bytes(path)), "normalized_sha256": doc["ci_handoff"]["normalized_sha256"]}
    if binding != expected or binding_core(doc) != doc["ci_handoff"]["binding_core_sha256"]:
        fail("ci binding mismatch")
    try:
        from agent.charter_contracts import NormalizedFinding
        for line in normalized.decode("utf-8").splitlines(): NormalizedFinding.model_validate(json.loads(line))
    except Exception as exc:
        fail(f"invalid normalized ci jsonl: {exc}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result: raise ValueError("duplicate key")
        result[key] = value
    return result


def _json_argument(value: str, label: str) -> object:
    try:
        return json.loads(value, object_pairs_hook=_unique_object)
    except (ValueError, json.JSONDecodeError) as exc:
        fail(f"invalid {label}: {exc}")


def init_v2(path: Path, run_id: str, source: str, input_type: str, input_version: str, input_digest: str, target: str, config: str, policy: str, stage_order: str, resume_identity: str) -> None:
    order = _json_argument(stage_order, "stage order")
    identity = _json_argument(resume_identity, "resume identity")
    doc = {
        "schema_version": "sentinel-run/v2", "run_id": run_id, "profile": "charter",
        "input": {"source": source, "type": input_type, "version": input_version, "sha256": input_digest},
        "identity": {"target_sha256": target, "config_sha256": config, "policy_sha256": policy, "output_sha256": ""},
        "resume_identity": identity, "artifact_ledger": [], "effect_ledger": [],
        "stage_order": order, "stages": {}, "required_skips": [], "resources": [],
        "recovery_hint": "resume only with exact immutable identity",
        "metrics": {"version": "RunMetrics/v1", **{key: 0 for key in METRICS}},
        "result": {"status": "pending", "action_sent": False}, "created_at_ms": int(time.time() * 1000),
    }
    write(path, doc)


def stage_v2(path: Path, name: str, status: str, increments: dict, checkpoint: object | None) -> None:
    doc = load(path); valid(doc)
    if doc["result"]["status"] != "pending": fail("terminal manifest cannot advance")
    expected = doc["stage_order"][len(doc["stages"])] if len(doc["stages"]) < len(doc["stage_order"]) else None
    if name != expected: fail("stage is not the first incomplete stage")
    if not isinstance(increments, dict) or any(key not in METRICS or not isinstance(value, int) or value < 0 for key, value in increments.items()): fail("invalid metric increments")
    if status == "rejected" and increments.get("request_count", 0): fail("rejected stage cannot record a request")
    if status == "passed":
        if not isinstance(checkpoint, dict) or set(checkpoint) != {"entries"}: fail("v2 passed stage requires a checkpoint")
        entries = checkpoint["entries"]
        if not isinstance(entries, list): fail("invalid checkpoint entries")
        index = len(doc["stages"])
        proof = {"stage": name, "index": index, "entries": entries}
        ledger = {**proof, "sha256": json_digest(proof)}
        # Validate actual bytes before exposing either member of the pair.
        trial = json.loads(json.dumps(doc))
        trial["stages"][name] = {"status": status, "at_ms": int(time.time() * 1000), "index": index, "checkpoint_sha256": ledger["sha256"]}
        trial["artifact_ledger"].append(ledger)
        valid_artifact_ledger(trial, path.parent)
        doc = trial
    else:
        if checkpoint is not None: fail("only passed stages may checkpoint")
        doc["stages"][name] = {"status": status, "at_ms": int(time.time() * 1000), "index": len(doc["stages"])}
    for key, value in increments.items(): doc["metrics"][key] += value
    if status == "skipped": doc["required_skips"].append(name)
    elif status == "failed":
        doc["result"]["status"] = "failed"; doc["metrics"]["application_error_count"] += 1
    elif status == "rejected":
        doc["result"] = {"status": "rejected", "action_sent": False}; doc["metrics"]["reject_count"] += 1; complete_output_hash(doc)
    write(path, doc)


def effect(path: Path, event: object) -> None:
    if not isinstance(event, dict): fail("invalid effect event")
    doc = load(path); valid(doc)
    if doc["schema_version"] != "sentinel-run/v2" or doc["result"]["status"] != "pending": fail("effect requires a pending v2 manifest")
    trial = json.loads(json.dumps(doc)); trial["effect_ledger"].append(event)
    valid_effect_ledger(trial, path.parent)
    write(path, trial)


def authorize_resume(path: Path, resume_identity: object) -> str:
    doc = load(path); valid(doc)
    if doc["schema_version"] == "sentinel-run/v1": fail("legacy manifest lacks exhaustive resume identity")
    if doc["result"]["status"] != "pending" or doc["required_skips"]: fail("manifest is not resumable")
    valid_resume_identity(resume_identity, doc["input"]["source"])
    if canonical_json(resume_identity) != canonical_json(doc["resume_identity"]): fail("resume identity mismatch")
    valid_artifact_ledger(doc, path.parent); valid_effect_ledger(doc, path.parent)
    if unresolved_effect(doc) or incomplete_stage_effect(doc): fail("remote effect requires reconciliation")
    if len(doc["stages"]) == len(doc["stage_order"]): return ""
    return doc["stage_order"][len(doc["stages"])]


def main(args: list[str]) -> None:
    if len(args) == 1:
        write(Path(args[0]), json.load(sys.stdin))
        return
    if args and args[0] == "init" and len(args) == 11:
        path, run_id, source, input_type, input_version, input_digest, target, config, policy, stage_order = map(str, args[1:])
        try:
            order = json.loads(stage_order)
        except json.JSONDecodeError:
            fail("invalid stage order")
        write(Path(path), {
            "schema_version": "sentinel-run/v1", "run_id": run_id, "profile": "charter",
            "input": {"source": source, "type": input_type, "version": input_version, "sha256": input_digest},
            "identity": {"target_sha256": target, "config_sha256": config,
                         "policy_sha256": policy, "output_sha256": ""},
            "stage_order": order, "stages": {}, "required_skips": [], "resources": [],
            "recovery_hint": "resume only with exact immutable identity",
            "metrics": {"version": "RunMetrics/v1", **{key: 0 for key in METRICS}},
            "result": {"status": "pending", "action_sent": False},
            "created_at_ms": int(time.time() * 1000),
        })
        return
    if args and args[0] == "init-v2" and len(args) == 12:
        init_v2(Path(args[1]), *map(str, args[2:]))
        return
    if args and args[0] == "verify" and len(args) == 2:
        doc = load(Path(args[1]))
        valid(doc)
        if doc["schema_version"] == "sentinel-run/v2":
            valid_artifact_ledger(doc, Path(args[1]).parent)
            valid_effect_ledger(doc, Path(args[1]).parent)
            if unresolved_effect(doc): fail("unresolved remote effect requires reconciliation")
        if doc["required_skips"] or doc["result"]["status"] != "passed":
            fail("manifest is not a successful terminal run")
        if len(doc["stages"]) != len(doc["stage_order"]) or any(
            doc["stages"][name]["status"] != "passed" for name in doc["stage_order"]
        ):
            fail("manifest does not contain every passed stage")
        return
    if args and args[0] == "ci-publish" and len(args) == 2:
        ci_publish(Path(args[1]))
        return
    if args and args[0] == "ci-verify" and len(args) == 2:
        ci_verify(Path(args[1]))
        return
    if args and args[0] == "stage" and len(args) in {4, 5}:
        path, name, status = Path(args[1]), args[2], args[3]
        if status not in {"passed", "failed", "skipped", "rejected"}:
            fail("invalid stage status")
        doc = load(path)
        valid(doc)
        if doc["result"]["status"] != "pending":
            fail("terminal manifest cannot advance")
        expected = doc["stage_order"][len(doc["stages"])] if len(doc["stages"]) < len(doc["stage_order"]) else None
        if name != expected:
            fail("stage is not the first incomplete stage")
        increments = {}
        if len(args) == 5:
            try:
                increments = json.loads(args[4])
            except json.JSONDecodeError:
                fail("invalid metric increments")
        if (not isinstance(increments, dict) or any(
                key not in METRICS or not isinstance(value, int) or value < 0
                for key, value in increments.items())):
            fail("invalid metric increments")
        if status == "rejected" and increments.get("request_count", 0):
            fail("rejected stage cannot record a request")
        doc["stages"][name] = {
            "status": status, "at_ms": int(time.time() * 1000), "index": len(doc["stages"]),
        }
        for key, value in increments.items():
            doc["metrics"][key] += value
        if status == "skipped":
            doc["required_skips"].append(name)
        elif status == "failed":
            doc["result"]["status"] = "failed"
            doc["metrics"]["application_error_count"] += 1
        elif status == "rejected":
            doc["result"] = {"status": "rejected", "action_sent": False}
            doc["metrics"]["reject_count"] += 1
            complete_output_hash(doc)
        write(path, doc)
        return
    if args and args[0] == "stage-v2" and len(args) in {5, 6}:
        path, name, status = Path(args[1]), args[2], args[3]
        if status not in {"passed", "failed", "skipped", "rejected"}: fail("invalid stage status")
        increments = _json_argument(args[4], "metric increments")
        checkpoint = _json_argument(args[5], "checkpoint") if len(args) == 6 else None
        stage_v2(path, name, status, increments, checkpoint)
        return
    if args and args[0] == "effect" and len(args) == 3:
        effect(Path(args[1]), _json_argument(args[2], "effect event"))
        return
    if args and args[0] == "authorize-resume" and len(args) == 3:
        print(authorize_resume(Path(args[1]), _json_argument(args[2], "resume identity")))
        return
    if args and args[0] == "finalize" and len(args) == 2:
        path = Path(args[1])
        doc = load(path)
        valid(doc)
        if doc["schema_version"] == "sentinel-run/v2":
            valid_artifact_ledger(doc, path.parent); valid_effect_ledger(doc, path.parent)
            if unresolved_effect(doc): fail("unresolved remote effect requires reconciliation")
        if (doc["result"]["status"] != "pending" or doc["required_skips"]
                or len(doc["stages"]) != len(doc["stage_order"]) or any(
                    doc["stages"][name]["status"] != "passed" for name in doc["stage_order"]
                )):
            fail("cannot finalize incomplete manifest")
        doc["metrics"]["duration_ms"] = max(0, int(time.time() * 1000) - doc["created_at_ms"])
        doc["result"] = {"status": "passed", "action_sent": bool(doc["metrics"]["request_count"])}
        complete_output_hash(doc)
        write(path, doc)
        return
    if args and args[0] == "resource" and len(args) == 4:
        path, kind, resource_id = Path(args[1]), args[2], args[3]
        doc = load(path)
        valid(doc)
        if doc["result"]["status"] != "pending":
            fail("terminal manifest cannot add resources")
        resource = {"owner": "controller", "kind": kind, "id": resource_id, "status": "active"}
        doc["resources"].append(resource)
        write(path, doc)
        return
    if args and args[0] == "release" and len(args) == 3:
        path, resource_id = Path(args[1]), args[2]
        doc = load(path)
        valid(doc)
        for resource in doc["resources"]:
            if resource["id"] == resource_id:
                if resource["status"] != "active":
                    fail("resource already released")
                resource["status"] = "released"
                write(path, doc)
                return
        fail("unknown controller resource")
    if args and args[0] == "read" and len(args) == 2:
        doc = load(Path(args[1]))
        valid(doc)
        print(json.dumps(doc, sort_keys=True))
        return
    fail("usage: manifest.py <path> | init|init-v2 ... | stage|stage-v2 ... | effect <path> <event-json> | authorize-resume <path> <identity-json>")


if __name__ == "__main__":
    main(sys.argv[1:])
