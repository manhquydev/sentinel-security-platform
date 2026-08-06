"""Fail-closed B0 scanner capability and admission contracts.

This module deliberately models *admission*, not a scan verdict.  A missing
image, ruleset, DB, parser, or completion record is an unavailable measurement
and can never be represented as a clean B0 result.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .contracts import ContractViolation, _digest


SCANNER_CAPABILITY_SCHEMA = "sentinel-workbench-scanner-capability/v1"
_ENGINE_ORDER = ("codeql", "semgrep", "trivy")
_PARSER_BY_ENGINE = {
    "codeql": "sarif",
    "semgrep": "semgrep-json",
    "trivy": "trivy-json",
}
_REQUIRED_SCOPE_BY_ENGINE = {
    "codeql": frozenset({"JavaScript", "TypeScript", "GitHub Actions"}),
    "semgrep": frozenset({"TypeScript", "TSX", "YAML"}),
    "trivy": frozenset({"filesystem", "config", "secret"}),
}
_REQUIRED_FILE_SCOPE_BY_ENGINE = {
    "codeql": frozenset({"**/*.js", "**/*.ts", "**/*.tsx", ".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"}),
    "semgrep": frozenset({"**/*.ts", "**/*.tsx", "**/*.yml", "**/*.yaml"}),
    "trivy": frozenset({"**/*"}),
}
_SHELL_PIN = re.compile(r"^export\s+(CODEQL_IMAGE|SEMGREP_IMAGE|TRIVY_IMAGE)=(?:\"([^\"]*)\"|'([^']*)')\s*$")


class ScannerContractViolation(ValueError):
    """Raised when B0 admission evidence is incomplete or inconsistent."""


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ScannerContractViolation(f"{label} must be a labelled string")
    return value


def _require_digest(value: object, label: str) -> str:
    try:
        return _digest(value, label)
    except ContractViolation as error:
        raise ScannerContractViolation(str(error)) from error


def _require_list(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise ScannerContractViolation(f"{label} must be a non-empty labelled list")
    return tuple(value)


def _require_pinned_image(image: object, image_digest: object, engine: str) -> str:
    image_text = _require_text(image, f"{engine}.image")
    digest = _require_digest(image_digest, f"{engine}.image_digest")
    if not image_text.endswith(f"@sha256:{digest}"):
        raise ScannerContractViolation(f"{engine}.image must be digest pinned to its image_digest")
    return image_text


@dataclass(frozen=True)
class ScannerEngineCapability:
    """A complete, engine-specific evidence contract for one B0 participant."""

    engine: str
    language_scope: tuple[str, ...]
    file_scope: tuple[str, ...]
    image: str
    image_digest: str
    cli_digest: str
    tool_version: str
    policy_digest: str
    acquisition: Mapping[str, str]
    parser: str
    network_policy: str
    unsupported_coverage: tuple[str, ...]
    completion: Mapping[str, str]

    @property
    def acquisition_digest(self) -> str:
        """Digest the complete source-less dependency set for one engine."""
        return _canonical_digest(dict(self.acquisition))

    @classmethod
    def from_mapping(cls, value: object) -> "ScannerEngineCapability":
        if not isinstance(value, Mapping):
            raise ScannerContractViolation("scanner engine capability must be an object")
        allowed = {
            "engine",
            "language_scope",
            "file_scope",
            "image",
            "image_digest",
            "cli_digest",
            "tool_version",
            "policy_digest",
            "acquisition",
            "parser",
            "network_policy",
            "unsupported_coverage",
            "completion",
        }
        if set(value) != allowed:
            raise ScannerContractViolation("scanner engine capability must use the exact v1 fields")
        engine = value["engine"]
        if engine not in _ENGINE_ORDER:
            raise ScannerContractViolation("scanner engine is not a frozen B0 engine")
        parser = value["parser"]
        if parser != _PARSER_BY_ENGINE[engine]:
            raise ScannerContractViolation(f"{engine} must use parser {_PARSER_BY_ENGINE[engine]}")
        if value["network_policy"] != "source-mounted-network-none":
            raise ScannerContractViolation(f"{engine} source-mounted work must use network-none")
        acquisition = value["acquisition"]
        if not isinstance(acquisition, Mapping):
            raise ScannerContractViolation(f"{engine}.acquisition must be an object")
        expected_acquisition = (
            {"distribution_digest", "query_suite_digest", "database_creation_policy_digest"}
            if engine == "codeql"
            else {"ruleset_digest"}
            if engine == "semgrep"
            else {"db_snapshot_digest"}
        )
        if set(acquisition) != expected_acquisition:
            raise ScannerContractViolation(f"{engine}.acquisition does not record every frozen dependency digest")
        frozen_acquisition = {
            key: _require_digest(item, f"{engine}.acquisition.{key}") for key, item in acquisition.items()
        }
        completion = value["completion"]
        if not isinstance(completion, Mapping):
            raise ScannerContractViolation(f"{engine}.completion must be an object")
        expected_completion = {"runner_metadata", "raw_artifact", "parse"}
        if engine == "codeql":
            expected_completion |= {"database", "sarif", "conversion"}
        if engine == "trivy":
            expected_completion |= {"database"}
        if set(completion) != expected_completion or not all(item == "present" or item == "complete" or item == "current" for item in completion.values()):
            raise ScannerContractViolation(f"{engine}.completion is absent or incomplete")
        if completion.get("parse") != "complete":
            raise ScannerContractViolation(f"{engine}.completion parse must be complete")
        if engine == "codeql" and (
            completion.get("database") != "complete"
            or completion.get("sarif") != "present"
            or completion.get("conversion") != "complete"
        ):
            raise ScannerContractViolation("codeql completion is absent or incomplete")
        if engine == "trivy" and completion.get("database") != "current":
            raise ScannerContractViolation("trivy completion is absent or incomplete")
        language_scope = _require_list(value["language_scope"], f"{engine}.language_scope")
        if frozenset(language_scope) != _REQUIRED_SCOPE_BY_ENGINE[engine]:
            raise ScannerContractViolation(f"{engine} language scope must match the frozen B0 coverage")
        file_scope = _require_list(value["file_scope"], f"{engine}.file_scope")
        if frozenset(file_scope) != _REQUIRED_FILE_SCOPE_BY_ENGINE[engine]:
            raise ScannerContractViolation(f"{engine} file scope must match the frozen B0 coverage")
        return cls(
            engine=engine,
            language_scope=language_scope,
            file_scope=file_scope,
            image=_require_pinned_image(value["image"], value["image_digest"], engine),
            image_digest=_require_digest(value["image_digest"], f"{engine}.image_digest"),
            cli_digest=_require_digest(value["cli_digest"], f"{engine}.cli_digest"),
            tool_version=_require_text(value["tool_version"], f"{engine}.tool_version"),
            policy_digest=_require_digest(value["policy_digest"], f"{engine}.policy_digest"),
            acquisition=frozen_acquisition,
            parser=parser,
            network_policy="source-mounted-network-none",
            unsupported_coverage=_require_list(value["unsupported_coverage"], f"{engine}.unsupported_coverage"),
            completion=dict(completion),
        )


@dataclass(frozen=True)
class ScannerCapabilityManifest:
    """The all-engine B0 admission object, bound to one sealed snapshot."""

    profile: str
    snapshot_id: str
    config_digest: str
    engines: tuple[ScannerEngineCapability, ...]

    @classmethod
    def from_mapping(cls, value: object) -> "ScannerCapabilityManifest":
        if not isinstance(value, Mapping) or set(value) != {
            "schema_version",
            "profile",
            "snapshot_id",
            "config_digest",
            "engines",
        }:
            raise ScannerContractViolation("scanner capability manifest must use the exact v1 envelope")
        if value["schema_version"] != SCANNER_CAPABILITY_SCHEMA:
            raise ScannerContractViolation("unsupported scanner capability schema")
        engines_value = value["engines"]
        if not isinstance(engines_value, list):
            raise ScannerContractViolation("scanner capability engines must be a list")
        engines = tuple(ScannerEngineCapability.from_mapping(item) for item in engines_value)
        if tuple(item.engine for item in engines) != _ENGINE_ORDER:
            raise ScannerContractViolation("B0 requires exactly CodeQL, Semgrep and Trivy in frozen order")
        return cls(
            profile=_require_text(value["profile"], "profile"),
            snapshot_id=_require_digest(value["snapshot_id"], "snapshot_id"),
            config_digest=_require_digest(value["config_digest"], "config_digest"),
            engines=engines,
        )

    @property
    def digest(self) -> str:
        return _canonical_digest(
            {
                "schema_version": SCANNER_CAPABILITY_SCHEMA,
                "profile": self.profile,
                "snapshot_id": self.snapshot_id,
                "config_digest": self.config_digest,
                "engines": [
                    {
                        "engine": item.engine,
                        "language_scope": list(item.language_scope),
                        "file_scope": list(item.file_scope),
                        "image": item.image,
                        "image_digest": item.image_digest,
                        "cli_digest": item.cli_digest,
                        "tool_version": item.tool_version,
                        "policy_digest": item.policy_digest,
                        "acquisition": dict(item.acquisition),
                        "parser": item.parser,
                        "network_policy": item.network_policy,
                        "unsupported_coverage": list(item.unsupported_coverage),
                        "completion": dict(item.completion),
                    }
                    for item in self.engines
                ],
            }
        )

    def engine(self, engine_id: str) -> ScannerEngineCapability:
        for item in self.engines:
            if item.engine == engine_id:
                return item
        raise ScannerContractViolation("scanner engine is not admitted by this manifest")

    def run_admission(self) -> dict[str, object]:
        """Return admission metadata, never scanner findings or a clean status."""
        return {
            "schema_version": "sentinel-workbench-run-admission/v1",
            "state": "admitted",
            "profile": self.profile,
            "snapshot_id": self.snapshot_id,
            "config_digest": self.config_digest,
            "capability_manifest_digest": self.digest,
            "engines": [
                {
                    "engine": item.engine,
                    "state": "ready",
                    "image_digest": item.image_digest,
                    "cli_digest": item.cli_digest,
                    "policy_digest": item.policy_digest,
                    "acquisition": dict(item.acquisition),
                    "parser": item.parser,
                }
                for item in self.engines
            ],
        }


def _read_pins(path: Path) -> dict[str, str]:
    """Read only the expected export assignments; never execute a policy file."""
    pins: dict[str, str] = {}
    if not path.is_file():
        return pins
    for line in path.read_text(encoding="utf-8").splitlines():
        match = _SHELL_PIN.fullmatch(line.strip())
        if match:
            pins[match.group(1)] = match.group(2) if match.group(2) is not None else match.group(3)
    return pins


_B0_POLICY_SCHEMA = "sentinel-workbench-b0-policy/v1"
_B0_POLICY_FILES = {
    "codeql": (
        ("distribution_policy", "distribution_digest"),
        ("query_suite", "query_suite_digest"),
        ("database_creation_policy", "database_creation_policy_digest"),
    ),
    "semgrep": (("ruleset", "ruleset_digest"),),
    "trivy": (("db_snapshot_policy", "db_snapshot_digest"),),
}
_B0_NOT_READY_REASON = {
    "codeql": "missing-frozen-query-pack-and-db-policy",
    "semgrep": "missing-frozen-typescript-yaml-ruleset",
    "trivy": "missing-frozen-db-snapshot-policy",
}


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_b0_policy(policy_root: Path) -> Mapping[str, Any] | None:
    """Load committed B0 policy when present and well-formed; else None."""
    policy_path = policy_root / "policy.json"
    if not policy_path.is_file() or policy_path.is_symlink():
        return None
    try:
        document = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(document, Mapping):
        return None
    if document.get("schema_version") != _B0_POLICY_SCHEMA:
        return None
    engines = document.get("engines")
    if not isinstance(engines, Mapping):
        return None
    return document


def _engine_policy_ready(policy_root: Path, engine: str, engine_policy: Mapping[str, Any]) -> bool:
    """Return True only when every frozen policy file matches its admitted digest."""
    files = engine_policy.get("files")
    acquisition = engine_policy.get("acquisition")
    if not isinstance(files, Mapping) or not isinstance(acquisition, Mapping):
        return False
    expected_pairs = _B0_POLICY_FILES.get(engine)
    if expected_pairs is None:
        return False
    if set(acquisition) != {digest_key for _, digest_key in expected_pairs}:
        return False
    for file_key, digest_key in expected_pairs:
        relative = files.get(file_key)
        expected = acquisition.get(digest_key)
        if not isinstance(relative, str) or not relative or not isinstance(expected, str):
            return False
        if ".." in Path(relative).parts or Path(relative).is_absolute():
            return False
        path = policy_root / relative
        if path.is_symlink() or not path.is_file():
            return False
        try:
            if _file_sha256(path) != expected:
                return False
        except OSError:
            return False
    return True


def default_engine_statuses(
    image_pins_path: Path | str,
    *,
    policy_root: Path | str | None = None,
) -> dict[str, dict[str, str]]:
    """Truthful local viability states for the repository B0 policy.

    These are capability preflight facts, deliberately not results from a scan.
    An engine becomes ``ready`` only when its image pin and frozen policy files
    are present and digest-matched. Ready is not a clean B0 scan outcome.
    """
    pins_path = Path(image_pins_path)
    pins = _read_pins(pins_path)
    root = Path(policy_root) if policy_root is not None else pins_path.parent / "workbench-b0"
    policy = _load_b0_policy(root)
    engines_policy = policy.get("engines") if isinstance(policy, Mapping) else None
    statuses: dict[str, dict[str, str]] = {}
    for engine, pin_name in (
        ("codeql", "CODEQL_IMAGE"),
        ("semgrep", "SEMGREP_IMAGE"),
        ("trivy", "TRIVY_IMAGE"),
    ):
        image = pins.get(pin_name, "")
        if not image or "@sha256:" not in image:
            statuses[engine] = {"state": "not-ready", "reason": "missing-digest-pinned-image"}
            continue
        engine_policy = engines_policy.get(engine) if isinstance(engines_policy, Mapping) else None
        if not isinstance(engine_policy, Mapping) or not _engine_policy_ready(root, engine, engine_policy):
            statuses[engine] = {
                "state": "not-ready",
                "reason": _B0_NOT_READY_REASON[engine],
            }
            continue
        statuses[engine] = {
            "state": "ready",
            "reason": "image-and-frozen-policy-present",
            "image": image,
        }
    return statuses
