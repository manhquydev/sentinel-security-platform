from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from agent.normalize_trivy import normalize_trivy_sanitized_json, normalize_trivy_sanitized_to_jsonl


def artifact(results: list[dict] | None = None) -> dict:
    return {
        "SchemaVersion": 2,
        "ArtifactName": "sentinel-source",
        "ArtifactType": "filesystem",
        "Results": results if results is not None else [{
            "Target": "src/alice@example.test/config.json",
            "Class": "secret",
            "Secrets": [{
                "RuleID": "generic-api-key", "Category": "general", "Severity": "HIGH",
                "Title": "Generic API Key for alice@example.test phone +84 912 345 678 token=raw-title-value", "StartLine": 17, "EndLine": 17,
            }],
            "Vulnerabilities": [], "Misconfigurations": [],
        }, {
            "Target": "Dockerfile", "Class": "config", "Type": "dockerfile",
            "Vulnerabilities": [], "Secrets": [],
            "Misconfigurations": [{
                "ID": "DS002", "AVDID": "AVD-DS-0002", "Severity": "HIGH",
                "Title": "Image user should not be root", "Description": "email=alice@example.test",
                "Resolution": "Add a USER directive", "Message": "phone=+84 912 345 678",
            }],
        }],
    }


class TrivyAdapterTest(unittest.TestCase):
    def write(self, directory: str, value: object, metadata: dict | None = None) -> tuple[Path, Path]:
        path = Path(directory) / "trivy.san.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        sidecar = Path(directory) / "trivy.san.metadata.json"
        sidecar.write_text(json.dumps(metadata or {
            "type": "trivy-sanitized-json", "version": "1", "sha256": digest,
        }), encoding="utf-8")
        return path, sidecar

    def test_valid_exact_handoff_normalizes_only_safe_trivy_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            source, metadata = self.write(directory, artifact())
            output = Path(directory) / "normalized.jsonl"
            result = normalize_trivy_sanitized_to_jsonl(source, metadata, output)
            self.assertIsNone(result.failure)
            self.assertEqual(len(result.records), 2)
            self.assertTrue(output.exists())
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
            payload = output.read_text(encoding="utf-8")
            self.assertNotIn("alice@example.test", payload)
            self.assertNotIn("+84 912 345 678", payload)
            self.assertNotIn("raw-title-value", payload)
            self.assertNotIn("Add a USER directive", payload)
            records = [json.loads(line) for line in payload.splitlines()]
            self.assertTrue(all(record["tool"] == "trivy" and record["scanner"] == "SAST" for record in records))
            self.assertTrue(all(record["location"].startswith("file:") for record in records))
            self.assertTrue(all("nuclei" not in json.dumps(record) for record in records))

    def test_schema_mismatch_and_empty_report_fail_without_output(self):
        with tempfile.TemporaryDirectory() as directory:
            malformed = artifact()
            malformed["Results"][0]["Secrets"][0]["Match"] = "raw-secret-should-not-be-accepted"
            source, metadata = self.write(directory, malformed)
            output = Path(directory) / "bad.jsonl"
            result = normalize_trivy_sanitized_to_jsonl(source, metadata, output)
            self.assertEqual(result.failure.code, "invalid-record")
            self.assertFalse(output.exists())

            wrong_version = artifact()
            wrong_version["SchemaVersion"] = 3
            source, metadata = self.write(directory, wrong_version)
            result = normalize_trivy_sanitized_to_jsonl(source, metadata, output)
            self.assertEqual(result.failure.code, "invalid-record")
            self.assertFalse(output.exists())

            source, metadata = self.write(directory, artifact([]))
            result = normalize_trivy_sanitized_to_jsonl(source, metadata, output)
            self.assertEqual(result.failure.code, "empty-input")
            self.assertFalse(output.exists())

    def test_metadata_mismatch_or_missing_metadata_produces_typed_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source, metadata = self.write(directory, artifact(), {
                "type": "trivy-sanitized-json", "version": "2", "sha256": "0" * 64,
            })
            output = Path(directory) / "never.jsonl"
            result = normalize_trivy_sanitized_to_jsonl(source, metadata, output)
            self.assertEqual(result.failure.code, "metadata-mismatch")
            self.assertFalse(output.exists())

            source, metadata = self.write(directory, artifact(), {
                "type": "trivy-sanitized-json", "version": "1", "sha256": "0" * 64,
            })
            result = normalize_trivy_sanitized_to_jsonl(source, metadata, output)
            self.assertEqual(result.failure.code, "metadata-mismatch")
            self.assertFalse(output.exists())

            result = normalize_trivy_sanitized_json(source, Path(directory) / "missing.metadata.json")
            self.assertEqual(result.failure.code, "metadata-mismatch")
            self.assertFalse(output.exists())

            metadata.write_bytes(b"\xff")
            result = normalize_trivy_sanitized_to_jsonl(source, metadata, output)
            self.assertEqual(result.failure.code, "metadata-mismatch")
            self.assertFalse(output.exists())

    def test_dependency_vulnerability_is_sca_not_sast(self):
        with tempfile.TemporaryDirectory() as directory:
            source, metadata = self.write(directory, artifact([{
                "Target": "package-lock.json", "Class": "lang-pkgs", "Type": "npm",
                "Secrets": [], "Misconfigurations": [],
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2024-1234", "PkgName": "example-package",
                    "InstalledVersion": "1.0.0", "FixedVersion": "1.0.1",
                    "Severity": "MEDIUM", "Title": "Example dependency vulnerability",
                }],
            }]))
            result = normalize_trivy_sanitized_json(source, metadata)
            self.assertIsNone(result.failure)
            self.assertEqual(result.records[0].tool, "trivy")
            self.assertEqual(result.records[0].scanner, "SCA")

    def test_exclusive_output_refuses_existing_regular_file_or_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            source, metadata = self.write(directory, artifact())
            output = Path(directory) / "normalized.jsonl"
            output.write_text("caller-owned\n", encoding="utf-8")
            output.chmod(0o644)
            result = normalize_trivy_sanitized_to_jsonl(source, metadata, output, exclusive_output=True)
            self.assertEqual(result.failure.code, "artifact-publication-failed")
            self.assertEqual(output.read_text(encoding="utf-8"), "caller-owned\n")
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o644)

            output.unlink()
            target = Path(directory) / "target"
            target.write_text("caller-owned\n", encoding="utf-8")
            output.symlink_to(target)
            result = normalize_trivy_sanitized_to_jsonl(source, metadata, output, exclusive_output=True)
            self.assertEqual(result.failure.code, "artifact-publication-failed")
            self.assertEqual(target.read_text(encoding="utf-8"), "caller-owned\n")


if __name__ == "__main__":
    unittest.main()
