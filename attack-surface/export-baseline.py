#!/usr/bin/env python3
"""Build a deterministic, locator-only Juice Shop attack-surface baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parent
SCHEMA = ROOT / "attack-surface.schema.json"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX16 = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
FORBIDDEN_KEYS = {"value", "raw", "request", "response", "authorization", "cookie", "credentials", "secret", "token"}
OBSERVATION_KEYS = {"method", "path", "evidence_source", "source_ref", "source_sha256", "observed_at",
                    "auth_class", "state_change", "confidence", "rationale", "parameters", "finding_refs"}
COMPONENT_KEYS = {"name", "version", "evidence_source", "source_ref", "source_sha256", "observed_at",
                  "confidence", "rationale"}
SUSPICIOUS_STRING = re.compile(r"(?i)(?:token|secret|password|session|sid|authorization|cookie)\s*=")
UUID_TOKEN = re.compile(r"(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b")


class ValidationError(ValueError):
    pass


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"cannot read JSON {path}: {exc}") from exc


def manifest_target(manifest: dict) -> dict:
    if not isinstance(manifest, dict):
        raise ValidationError("manifest root must be an object")
    target = manifest.get("target")
    if not isinstance(target, dict):
        raise ValidationError("manifest.target must be an object")
    digest = target.get("image_digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValidationError("manifest image_digest must be a full sha256 digest")
    image = target.get("image", "")
    if image != f"bkimminich/juice-shop@{digest}":
        raise ValidationError("manifest image must be the pinned Juice Shop digest")
    for field in ("name", "container", "version", "oci_source_revision", "source_url"):
        if not isinstance(target.get(field), str) or not target[field]:
            raise ValidationError(f"manifest target.{field} must be a non-empty string")
    for field in ("runtime_port", "container_port"):
        if not isinstance(target.get(field), int) or isinstance(target[field], bool):
            raise ValidationError(f"manifest target.{field} must be an integer")
    origin = target.get("origin", "")
    try:
        parsed = urllib.parse.urlparse(origin)
        parsed_port = parsed.port
    except ValueError as exc:
        raise ValidationError(f"manifest origin is malformed: {exc}") from exc
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.username or parsed.password:
        raise ValidationError("manifest origin must be loopback HTTP")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValidationError("manifest origin must be a bare loopback origin")
    if parsed_port != target.get("runtime_port"):
        raise ValidationError("manifest origin port does not match runtime_port")
    if target.get("source_revision_label") and target["source_revision_label"] != target.get("oci_source_revision"):
        raise ValidationError("manifest source revision label is inconsistent")
    version_path = target.get("runtime_version_path", "")
    if not isinstance(version_path, str) or normalize_path(version_path) != version_path:
        raise ValidationError("runtime_version_path must be a normalized path")
    if not re.fullmatch(r"[0-9a-f]{40}", target.get("source_commit", "")):
        raise ValidationError("manifest source_commit must be a full commit")
    return target


def reject_forbidden_values(value, path="root", allowed_tokens=()) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_lower = key.lower()
            if key_lower in FORBIDDEN_KEYS and child not in (None, [], {}):
                raise ValidationError(f"forbidden evidence field: {path}.{key}")
            if key_lower != "source_sha256":
                reject_forbidden_values(child, f"{path}.{key}", allowed_tokens)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_forbidden_values(child, f"{path}[{index}]", allowed_tokens)
    elif isinstance(value, str):
        if SUSPICIOUS_STRING.search(value) or re.search(r"(?i)%(?:3f|23|3b)", value):
            raise ValidationError(f"token-like evidence string: {path}")
        scrubbed = value
        for token in allowed_tokens:
            scrubbed = scrubbed.replace(token, "")
        if UUID_TOKEN.search(scrubbed) or re.search(r"(?i)(?:^|[/=:])([0-9a-f]{16,})(?=$|[/?:])", scrubbed):
            raise ValidationError(f"opaque token-like evidence string: {path}")
        if path.endswith("source_ref") and ":/" in scrubbed:
            candidate_path = scrubbed.split(":/", 1)[1]
            normalize_path("/" + candidate_path.lstrip("/"))
            if re.search(r"/[A-Za-z0-9_+~=-]{20,}(?:/|$)", "/" + candidate_path.lstrip("/")):
                raise ValidationError(f"opaque token-like evidence string: {path}")


def normalize_path(path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValidationError("path must be an absolute path")
    decoded = urllib.parse.unquote(path)
    if decoded != path and any(char in decoded for char in "?#;"):
        raise ValidationError(f"path contains encoded delimiter: {path}")
    if any(char in decoded for char in "?#;"):
        raise ValidationError(f"path contains query, fragment or matrix token: {path}")
    segments = decoded.split("/")
    for segment in segments:
        if not segment:
            continue
        if segment in (".", ".."):
            raise ValidationError(f"path contains traversal segment: {path}")
        if segment.startswith(":"):
            if not re.fullmatch(r":[A-Za-z][A-Za-z0-9_-]*", segment):
                raise ValidationError(f"path contains unsafe placeholder: {path}")
            continue
        if HEX16.fullmatch(segment) or (len(segment) >= 20 and re.fullmatch(r"[A-Za-z0-9_-]+", segment)):
            raise ValidationError(f"path contains opaque token: {path}")
    return "/" + "/".join(segment for segment in segments[1:] if segment != "")


def source_hash(reference: str) -> str:
    if reference.startswith("image@sha256:"):
        return reference.split(":", 1)[1]
    return hashlib.sha256(reference.encode("utf-8")).hexdigest()


def validate_observation_hash(record: dict) -> None:
    declared = record.get("source_sha256")
    reference = record.get("source_ref")
    if not isinstance(reference, str) or not reference:
        raise ValidationError("source_ref must be a non-empty string")
    if not HEX64.fullmatch(declared or ""):
        raise ValidationError("source_sha256 must be lowercase hexadecimal")
    if declared != source_hash(reference):
        raise ValidationError(f"source hash mismatch for {reference}")


def validate_observations(manifest: dict, observations: dict) -> tuple[list[dict], list[dict]]:
    target = manifest_target(manifest)
    if not isinstance(observations, dict):
        raise ValidationError("observations root must be an object")
    if observations.get("schema_version") != "0.1":
        raise ValidationError("observations schema_version must be 0.1")
    if set(observations) != {"schema_version", "target_digest", "observations", "components"}:
        raise ValidationError("observations contains unsupported top-level fields")
    if observations.get("target_digest") != target["image_digest"]:
        raise ValidationError("observation target digest does not match manifest")
    reject_forbidden_values(observations, allowed_tokens=(target["source_commit"], target["image_digest"].split(":", 1)[1]))
    raw_endpoints = observations.get("observations")
    raw_components = observations.get("components")
    if not isinstance(raw_endpoints, list) or not isinstance(raw_components, list):
        raise ValidationError("observations and components must be arrays")
    endpoints = []
    keys = set()
    for item in raw_endpoints:
        if not isinstance(item, dict) or set(item) != OBSERVATION_KEYS:
            raise ValidationError("endpoint observation has unsupported or missing fields")
        if item.get("evidence_source") == "semgrep":
            raise ValidationError("Semgrep evidence is excluded from v0.1")
        validate_observation_hash(item)
        if item.get("evidence_source") not in {"pinned-source", "pinned-openapi", "sanitized-nuclei"}:
            raise ValidationError("unsupported endpoint evidence source")
        if not str(item.get("source_ref", "")).startswith(f"juice-shop@{target['source_commit']}"):
            raise ValidationError("endpoint source_ref is not pinned to the target commit")
        if item.get("auth_class") in {"unknown", "hypothesis"} and item.get("confidence") != "hypothesis":
            raise ValidationError("unsupported auth classification must be hypothesis confidence")
        if item.get("state_change") in {"unknown", "hypothesis"} and item.get("confidence") != "hypothesis":
            raise ValidationError("unsupported state classification must be hypothesis confidence")
        item = dict(item)
        item["path"] = normalize_path(item["path"])
        parameter_names = {parameter.get("name") for parameter in item.get("parameters", []) if isinstance(parameter, dict)}
        placeholders = {segment[1:] for segment in item["path"].split("/") if segment.startswith(":")}
        if not placeholders.issubset(parameter_names):
            raise ValidationError("path placeholder is missing from parameter declarations")
        key = "|".join((target["image_digest"], item["method"], item["path"], item["evidence_source"]))
        if key in keys:
            raise ValidationError(f"duplicate endpoint key: {key}")
        keys.add(key)
        endpoints.append(item)
    components = []
    component_keys = set()
    for item in raw_components:
        if not isinstance(item, dict) or set(item) != COMPONENT_KEYS:
            raise ValidationError("component observation has unsupported or missing fields")
        validate_observation_hash(item)
        if item.get("evidence_source") != "trivy-digest":
            raise ValidationError("only digest-bound Trivy component metadata is accepted")
        expected_component_ref = f"image@{target['image_digest']}"
        if item.get("source_ref") != expected_component_ref or item.get("source_sha256") != target["image_digest"].split(":", 1)[1]:
            raise ValidationError("component is not bound to the manifest image digest")
        component_key = (item.get("name"), item.get("version"), item.get("source_ref"))
        if component_key in component_keys:
            raise ValidationError("duplicate component key")
        component_keys.add(component_key)
        components.append(dict(item))
    return endpoints, components


def validate_baseline(baseline: dict) -> None:
    schema = read_json(SCHEMA)
    errors = sorted(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(baseline), key=str)
    if errors:
        raise ValidationError("; ".join(error.message for error in errors[:3]))


def build(manifest_path: Path, observations_path: Path, output_path: Path) -> None:
    manifest = read_json(manifest_path)
    target = manifest_target(manifest)
    observations = read_json(observations_path)
    endpoints, components = validate_observations(manifest, observations)
    endpoints.sort(key=lambda item: (item["path"], item["method"], item["evidence_source"]))
    components.sort(key=lambda item: (item["name"], item["version"], item["evidence_source"]))
    baseline = {
        "schema_version": "0.1",
        "target": {
            "name": target["name"],
            "version": target["version"],
            "image_digest": target["image_digest"],
            "source_commit": target["source_commit"],
            "source_revision_label": target["oci_source_revision"],
        },
        "coverage": {
            "mode": "anonymous-locator-only",
            "limitations": [
                "No authenticated or state-changing requests were executed.",
                "OCI source revision is declared provenance, not a build attestation.",
                "Semgrep/SAST and live scanner output are excluded from this baseline.",
            ],
        },
        "endpoints": endpoints,
        "components": components,
    }
    validate_baseline(baseline)
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(baseline, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with tempfile.NamedTemporaryFile("wb", dir=output_path.parent, prefix=f".{output_path.name}.", delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, output_path)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValidationError(f"unexpected redirect from runtime version endpoint: {code}")


def verify_runtime(manifest_path: Path) -> None:
    manifest = read_json(manifest_path)
    target = manifest_target(manifest)
    try:
        inspected = subprocess.run(
            ["docker", "inspect", target["container"]],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        container = json.loads(inspected.stdout)[0]
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, IndexError) as exc:
        raise ValidationError(f"docker inspect failed: {exc}") from exc
    if not (container.get("State") or {}).get("Running"):
        raise ValidationError("named Juice Shop container is not running")
    image_id = container.get("Image")
    if not image_id:
        raise ValidationError("running container has no image identifier")
    try:
        image_inspected = subprocess.run(
            ["docker", "inspect", image_id],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        image = json.loads(image_inspected.stdout)[0]
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, IndexError) as exc:
        raise ValidationError(f"docker image inspect failed: {exc}") from exc
    repo_digests = image.get("RepoDigests") or []
    expected_ref = f"{target['image'].split('@', 1)[0]}@{target['image_digest']}"
    if expected_ref not in repo_digests:
        raise ValidationError("running container RepoDigest does not match manifest")
    labels = (container.get("Config") or {}).get("Labels") or {}
    image_labels = (image.get("Config") or {}).get("Labels") or {}
    if image_labels.get("org.opencontainers.image.revision") != target["oci_source_revision"]:
        raise ValidationError("running container OCI revision label does not match manifest")
    if image_labels.get("org.opencontainers.image.source") != target["source_url"]:
        raise ValidationError("running image source label does not match manifest")
    if image_labels.get("org.opencontainers.image.version") != target["version"]:
        raise ValidationError("running image version label does not match manifest")
    all_ports = ((container.get("NetworkSettings") or {}).get("Ports") or {})
    expected_port = f"{target['container_port']}/tcp"
    ports = all_ports.get(expected_port) or []
    if set(all_ports) != {expected_port} or not ports or any(
        binding.get("HostIp") != "127.0.0.1" or binding.get("HostPort") != str(target["runtime_port"])
        for binding in ports
    ):
        raise ValidationError("running container port mapping does not match manifest")
    url = urllib.parse.urljoin(target["origin"].rstrip("/") + "/", target["runtime_version_path"].lstrip("/"))
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(urllib.request.Request(url, method="GET"), timeout=10) as response:
            if response.status != 200:
                raise ValidationError(f"runtime version endpoint returned HTTP {response.status}")
            body = response.read(1024 * 1024)
    except (OSError, urllib.error.URLError) as exc:
        raise ValidationError(f"runtime version endpoint failed: {exc}") from exc
    try:
        version = json.loads(body).get("version")
    except (json.JSONDecodeError, AttributeError) as exc:
        raise ValidationError(f"runtime version response is not JSON: {exc}") from exc
    if version != target["version"]:
        raise ValidationError("runtime version does not match manifest")
    print(f"runtime verified: {target['container']} {target['image_digest']} {version}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("--manifest", type=Path, required=True)
    build_parser.add_argument("--observations", type=Path, required=True)
    build_parser.add_argument("--output", type=Path, required=True)
    runtime_parser = subparsers.add_parser("verify-runtime")
    runtime_parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            build(args.manifest, args.observations, args.output)
            print(f"baseline written: {args.output}")
        else:
            verify_runtime(args.manifest)
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
