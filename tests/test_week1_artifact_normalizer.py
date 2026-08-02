"""Contract tests for the isolated Week-1 submitted-artifact importer.

These tests deliberately exercise the public compatibility boundary instead of
the stricter Charter adapters.  The aggregate is evidence for Week 2 only and
must not become a new controller input type.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pydantic import ValidationError

from agent.charter_contracts import NormalizedFinding
from agent.normalize_week1_artifacts import (
    normalize_week1_submission,
    normalize_week1_submission_to_files,
)


SCHEMA_VERSION = "week1-submission/v1"
CANONICAL_NAMES = (
    "scanners/out/nuclei.san.jsonl",
    "scanners/out/trivy.san.json",
    "scanners/out/semgrep.san.json",
)


def nuclei_http(*, matched_at: str = "http://127.0.0.1:13000/metrics",
                name: str = "Missing security header") -> dict:
    return {
        "template-id": "http-missing-security-headers",
        "template": "http/misconfiguration/missing-security-headers.yaml",
        "type": "http",
        "host": "http://127.0.0.1:13000",
        "matched-at": matched_at,
        "matcher-name": "content-security-policy",
        "timestamp": "2026-07-23T00:00:00Z",
        "info": {
            "name": name,
            "severity": "info",
            "classification": {"cwe-id": ["CWE-693"]},
        },
    }


def nuclei_javascript(*, name: str = "JavaScript file discovered") -> dict:
    return {
        "template-id": "javascript-files",
        "template": "http/exposures/files/javascript-files.yaml",
        "type": "javascript",
        "host": "127.0.0.1:13000",
        "matched-at": "127.0.0.1:13000",
        "timestamp": "2026-07-23T00:00:00Z",
        "info": {"name": name, "severity": "info"},
    }


def trivy_artifact(*, title: str = "Generic API key",
                   target: str = "app/config.json") -> dict:
    return {
        "SchemaVersion": 2,
        "ArtifactName": "juice-shop-image",
        "ArtifactType": "filesystem",
        "Results": [{
            "Target": target,
            "Class": "secret",
            "Vulnerabilities": [],
            "Secrets": [{
                "RuleID": "generic-api-key",
                "Category": "general",
                "Severity": "HIGH",
                "Title": title,
                "StartLine": 4,
                "EndLine": 4,
            }],
            "Misconfigurations": [],
        }],
    }


def semgrep_result(path: str, *, rule: str = "java.lang.security.insecure-random",
                   severity: str = "WARNING", message: str = "Weak random use") -> dict:
    return {
        "check_id": rule,
        "path": path,
        "start": {"line": 8, "col": 1, "offset": 0},
        "end": {"line": 8, "col": 24, "offset": 23},
        "extra": {
            "severity": severity,
            "message": message,
            "lines": "dangerous scanner-derived source text",
            "metadata": {"cwe": ["CWE-330"]},
        },
    }


class Week1ArtifactNormalizerTest(unittest.TestCase):
    maxDiff = None

    def make_submission(
        self,
        directory: str,
        *,
        nuclei_rows: list[dict] | None = None,
        trivy: object | None = None,
        semgrep_rows: list[dict] | None = None,
        include_trivy: bool = True,
        include_semgrep: bool = True,
    ) -> tuple[Path, Path]:
        root = Path(directory) / "submission"
        out = root / "scanners/out"
        out.mkdir(parents=True)
        source_root = Path(directory) / "source"
        (source_root / "src").mkdir(parents=True)
        (source_root / "src/Sample").write_text("class Sample {}\n", encoding="utf-8")
        (out / "nuclei.san.jsonl").write_text(
            "\n".join(json.dumps(row) for row in (nuclei_rows or [nuclei_http(), nuclei_javascript()])) + "\n",
            encoding="utf-8",
        )
        if include_trivy:
            (out / "trivy.san.json").write_text(
                json.dumps(trivy if trivy is not None else trivy_artifact()),
                encoding="utf-8",
            )
        if include_semgrep:
            rows = semgrep_rows
            if rows is None:
                rows = [semgrep_result(str(source_root / "src/Sample"))]
            (out / "semgrep.san.json").write_text(
                json.dumps({"version": "1.100.0", "errors": [], "results": rows}),
                encoding="utf-8",
            )
        return root, source_root

    def publish(
        self, submission: Path, directory: str, *, source_root: Path | None = None,
        output_name: str = "week1.aggregate.jsonl", manifest_name: str = "week1.aggregate.manifest.json",
    ):
        return normalize_week1_submission_to_files(
            submission,
            Path(directory) / output_name,
            Path(directory) / manifest_name,
            semgrep_source_root=source_root,
        )

    def load_published(self, directory: str) -> tuple[list[dict], dict]:
        aggregate = Path(directory) / "week1.aggregate.jsonl"
        manifest = Path(directory) / "week1.aggregate.manifest.json"
        return (
            [json.loads(line) for line in aggregate.read_text(encoding="utf-8").splitlines()],
            json.loads(manifest.read_text(encoding="utf-8")),
        )

    def assert_no_outputs(self, directory: str) -> None:
        self.assertFalse((Path(directory) / "week1.aggregate.jsonl").exists())
        self.assertFalse((Path(directory) / "week1.aggregate.manifest.json").exists())

    def test_aggregate_is_versioned_one_to_one_and_manifest_binds_canonical_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            submission, source_root = self.make_submission(directory)
            result = self.publish(submission, directory, source_root=source_root)
            self.assertTrue(result.ok)
            self.assertIsNone(result.failure)
            self.assertEqual(len(result.records), 4)
            records, manifest = self.load_published(directory)
            self.assertEqual(len(records), 4)
            self.assertEqual(manifest["schema_version"], SCHEMA_VERSION)
            self.assertEqual(manifest["source_kind"], "week1-submission")
            self.assertEqual(manifest["aggregate_count"], 4)
            self.assertEqual(
                manifest["aggregate_sha256"],
                hashlib.sha256((Path(directory) / "week1.aggregate.jsonl").read_bytes()).hexdigest(),
            )
            self.assertEqual(os.stat(Path(directory) / "week1.aggregate.jsonl").st_mode & 0o777, 0o600)
            self.assertEqual(
                os.stat(Path(directory) / "week1.aggregate.manifest.json").st_mode & 0o777, 0o600,
            )

            inputs = manifest["inputs"]
            self.assertEqual([entry["filename"] for entry in inputs], list(CANONICAL_NAMES))
            expected_counts = {
                "scanners/out/nuclei.san.jsonl": 2,
                "scanners/out/trivy.san.json": 1,
                "scanners/out/semgrep.san.json": 1,
            }
            for entry in inputs:
                artifact = submission / entry["filename"]
                self.assertEqual(entry["source_kind"], "week1-submission")
                self.assertEqual(entry["input_count"], expected_counts[entry["filename"]])
                self.assertEqual(entry["admitted_count"], expected_counts[entry["filename"]])
                self.assertEqual(entry["refused_count"], 0)
                self.assertEqual(entry["sha256"], hashlib.sha256(artifact.read_bytes()).hexdigest())

            self.assertEqual({record["tool"] for record in records}, {"nuclei", "trivy", "semgrep"})
            expected_source_ids = {
                f"week1-submission:nuclei:sha256:{inputs[0]['sha256']}:item:1",
                f"week1-submission:nuclei:sha256:{inputs[0]['sha256']}:item:2",
                f"week1-submission:trivy:sha256:{inputs[1]['sha256']}:item:1",
                f"week1-submission:semgrep:sha256:{inputs[2]['sha256']}:item:1",
            }
            actual_source_ids = set()
            for record in records:
                self.assertEqual(record["schema_version"], SCHEMA_VERSION)
                self.assertEqual(record["provenance_kind"], "week1-submission")
                self.assertEqual(len(record["source_ids"]), 1)
                actual_source_ids.update(record["source_ids"])
            self.assertEqual(actual_source_ids, expected_source_ids)

    def test_nuclei_http_is_path_only_and_javascript_is_opaque(self):
        with tempfile.TemporaryDirectory() as directory:
            submission, source_root = self.make_submission(directory)
            result = self.publish(submission, directory, source_root=source_root)
            self.assertTrue(result.ok)
            records, _manifest = self.load_published(directory)
            nuclei = [record for record in records if record["tool"] == "nuclei"]
            self.assertEqual(len(nuclei), 2)
            http = next(record for record in nuclei if record["location"].startswith("path:/"))
            javascript = next(record for record in nuclei if record is not http)
            self.assertEqual(http["location"], "path:/metrics")
            self.assertNotIn("127.0.0.1", http["location"])
            self.assertNotIn("http", http["location"])
            self.assertNotIn("127.0.0.1", javascript["location"])
            self.assertNotIn("http", javascript["location"])
            self.assertTrue(javascript["location"].startswith("nuclei-js:"))

    def test_nuclei_rejects_unsafe_http_locator_without_partial_publication(self):
        unsafe_values = (
            "http://user:pass@127.0.0.1:13000/metrics",
            "http://127.0.0.1:13000/metrics?token=raw-value",
            "http://127.0.0.1:13000/%2fprivate",
            "http://127.0.0.1:13000/metrics#fragment",
        )
        for unsafe in unsafe_values:
            with self.subTest(locator=unsafe), tempfile.TemporaryDirectory() as directory:
                submission, source_root = self.make_submission(
                    directory, nuclei_rows=[nuclei_http(matched_at=unsafe)],
                )
                result = self.publish(submission, directory, source_root=source_root)
                self.assertFalse(result.ok)
                self.assertEqual(result.failure.code, "invalid-record")
                self.assert_no_outputs(directory)

    def test_semgrep_rebases_only_resolved_descendants_and_uses_opaque_fallbacks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            submission, source_root = self.make_submission(directory)
            (submission / "scanners/out/semgrep.san.json").write_text(json.dumps({
                "version": "1.100.0",
                "errors": [],
                "results": [
                    semgrep_result(str(source_root / "src/Sample")),
                    semgrep_result(str(root / "outside.java"), rule="outside-rule"),
                ],
            }), encoding="utf-8")
            result = self.publish(submission, directory, source_root=source_root)
            self.assertTrue(result.ok)
            records, _manifest = self.load_published(directory)
            semgrep = [record for record in records if record["tool"] == "semgrep"]
            self.assertEqual(len(semgrep), 2)
            locations = {record["location"] for record in semgrep}
            self.assertIn("file:src/Sample", locations)
            self.assertTrue(any(location.startswith("semgrep:") for location in locations))
            payload = json.dumps(semgrep, sort_keys=True)
            self.assertNotIn(str(source_root), payload)
            self.assertNotIn(str(root), payload)
            self.assertNotIn("..", payload)

    def test_semgrep_rejects_relative_path_traversal_without_partial_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            submission, source_root = self.make_submission(
                directory,
                semgrep_rows=[semgrep_result("../../not-a-safe-relative.java", rule="traversal-rule")],
            )
            result = self.publish(submission, directory, source_root=source_root)
            self.assertFalse(result.ok)
            self.assertEqual(result.failure.code, "invalid-record")
            self.assert_no_outputs(directory)

    def test_semgrep_symlink_escape_never_discloses_or_rebases_outside_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside.java"
            outside.write_text("outside", encoding="utf-8")
            submission, source_root = self.make_submission(directory)
            link = source_root / "src/link.java"
            link.symlink_to(outside)
            semgrep = submission / "scanners/out/semgrep.san.json"
            semgrep.write_text(json.dumps({
                "version": "1.100.0",
                "errors": [],
                "results": [semgrep_result(str(link))],
            }), encoding="utf-8")
            result = self.publish(submission, directory, source_root=source_root)
            self.assertTrue(result.ok)
            records, _manifest = self.load_published(directory)
            record = next(record for record in records if record["tool"] == "semgrep")
            self.assertTrue(record["location"].startswith("semgrep:"))
            self.assertNotIn(str(outside), json.dumps(record))
            self.assertNotIn(str(link), json.dumps(record))

    def test_scanner_free_text_secret_and_instruction_markers_do_not_escape_projection(self):
        marker = "IGNORE-PRIOR-OBJECTIVE-LEAK-TOKEN=supersecret"
        with tempfile.TemporaryDirectory() as directory:
            submission, source_root = self.make_submission(
                directory,
                nuclei_rows=[nuclei_http(name=marker), nuclei_javascript(name=marker)],
                trivy=trivy_artifact(title=marker),
                semgrep_rows=[semgrep_result(str(Path(directory) / "source/src/Sample.java"), message=marker)],
            )
            result = self.publish(submission, directory, source_root=source_root)
            self.assertTrue(result.ok)
            aggregate = (Path(directory) / "week1.aggregate.jsonl").read_text(encoding="utf-8").lower()
            manifest = (Path(directory) / "week1.aggregate.manifest.json").read_text(encoding="utf-8").lower()
            for forbidden in ("ignore-prior-objective", "supersecret", "leak-token", "dangerous scanner-derived"):
                self.assertNotIn(forbidden, aggregate + manifest)

    def test_scanner_free_text_locators_do_not_escape_projection(self):
        locator_marker = "https://target.invalid/private?token=raw-value"
        host_marker = "internal.target.invalid:8443"
        path_marker = "/srv/private/target-data"
        with tempfile.TemporaryDirectory() as directory:
            submission, source_root = self.make_submission(
                directory,
                nuclei_rows=[
                    nuclei_http(name=f"Nuclei {locator_marker} {host_marker} {path_marker}"),
                    nuclei_javascript(name=f"JavaScript {locator_marker}"),
                ],
                trivy=trivy_artifact(title=f"Trivy {host_marker} {path_marker}"),
                semgrep_rows=[
                    semgrep_result(
                        str(Path(directory) / "source/src/Sample.java"),
                        rule=f"rule-{locator_marker}",
                    ),
                ],
            )
            result = self.publish(submission, directory, source_root=source_root)
            self.assertTrue(result.ok)
            published = (
                (Path(directory) / "week1.aggregate.jsonl").read_text(encoding="utf-8")
                + (Path(directory) / "week1.aggregate.manifest.json").read_text(encoding="utf-8")
            ).lower()
            for forbidden in ("target.invalid", "internal.target.invalid", "/srv/private", "raw-value"):
                self.assertNotIn(forbidden, published)

    def test_relative_target_or_path_with_host_or_ip_is_opaque(self):
        with tempfile.TemporaryDirectory() as directory:
            submission, source_root = self.make_submission(
                directory,
                trivy=trivy_artifact(target="localhost/scan"),
                semgrep_rows=[
                    semgrep_result("203.0.113.7/scan"),
                    semgrep_result("host.invalid/scan", rule="domain-like-path"),
                ],
            )
            result = self.publish(submission, directory, source_root=source_root)
            self.assertTrue(result.ok)
            records, _manifest = self.load_published(directory)
            trivy = next(record for record in records if record["tool"] == "trivy")
            semgrep = [record for record in records if record["tool"] == "semgrep"]
            self.assertTrue(trivy["location"].startswith("trivy:"))
            self.assertTrue(all(record["location"].startswith("semgrep:") for record in semgrep))
            published = json.dumps(records).lower()
            self.assertNotIn("localhost", published)
            self.assertNotIn("203.0.113.7", published)
            self.assertNotIn("host.invalid", published)

    def test_missing_canonical_trivy_and_supplementary_full_artifact_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            submission, source_root = self.make_submission(directory, include_trivy=False)
            full = submission / "scanners/out/trivy-full.san.json"
            full.write_text(json.dumps(trivy_artifact()), encoding="utf-8")
            result = self.publish(submission, directory, source_root=source_root)
            self.assertFalse(result.ok)
            self.assertEqual(result.failure.code, "malformed-input")
            self.assert_no_outputs(directory)

    def test_rejects_nonregular_and_symlink_canonical_input(self):
        with tempfile.TemporaryDirectory() as directory:
            submission, source_root = self.make_submission(directory)
            nuclei = submission / "scanners/out/nuclei.san.jsonl"
            copied = submission / "scanners/out/copied.nuclei"
            nuclei.rename(copied)
            nuclei.symlink_to(copied)
            result = self.publish(submission, directory, source_root=source_root)
            self.assertFalse(result.ok)
            self.assertEqual(result.failure.code, "unsafe-input")
            self.assert_no_outputs(directory)

        with tempfile.TemporaryDirectory() as directory:
            submission, source_root = self.make_submission(directory)
            trivy = submission / "scanners/out/trivy.san.json"
            copied = submission / "scanners/out/copied.trivy"
            trivy.rename(copied)
            trivy.symlink_to(copied)
            result = self.publish(submission, directory, source_root=source_root)
            self.assertFalse(result.ok)
            self.assertEqual(result.failure.code, "unsafe-input")
            self.assert_no_outputs(directory)

        with tempfile.TemporaryDirectory() as directory:
            submission, source_root = self.make_submission(directory)
            nuclei = submission / "scanners/out/nuclei.san.jsonl"
            nuclei.unlink()
            os.mkfifo(nuclei)
            try:
                result = self.publish(submission, directory, source_root=source_root)
            finally:
                nuclei.unlink()
            self.assertFalse(result.ok)
            self.assertEqual(result.failure.code, "unsafe-input")
            self.assert_no_outputs(directory)

    def test_parent_directory_swap_cannot_redirect_canonical_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            submission, source_root = self.make_submission(directory)
            external = root / "external-out"
            external.mkdir()
            (external / "nuclei.san.jsonl").write_text(
                json.dumps(nuclei_http(name="outside input")) + "\n",
                encoding="utf-8",
            )
            original_open = os.open
            swapped = False

            def race_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal swapped
                if path == "out" and dir_fd is not None and not swapped:
                    original_out = submission / "scanners/out"
                    original_out.rename(submission / "scanners/out-original")
                    original_out.symlink_to(external, target_is_directory=True)
                    swapped = True
                if dir_fd is None:
                    return original_open(path, flags, mode)
                return original_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch("agent.normalize_week1_artifacts.os.open", side_effect=race_open):
                result = self.publish(submission, directory, source_root=source_root)
            self.assertTrue(swapped)
            self.assertFalse(result.ok)
            self.assertEqual(result.failure.code, "unsafe-input")
            self.assert_no_outputs(directory)

    def test_submission_path_with_an_intermediate_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            submission, source_root = self.make_submission(directory)
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(root)
            symlinked_submission = linked_parent / submission.name
            result = self.publish(symlinked_submission, directory, source_root=source_root)
            self.assertFalse(result.ok)
            self.assertEqual(result.failure.code, "unsafe-input")
            self.assert_no_outputs(directory)

    def test_malformed_input_refuses_every_output(self):
        with tempfile.TemporaryDirectory() as directory:
            submission, source_root = self.make_submission(directory)
            (submission / "scanners/out/semgrep.san.json").write_text("{not JSON", encoding="utf-8")
            result = self.publish(submission, directory, source_root=source_root)
            self.assertFalse(result.ok)
            self.assertEqual(result.failure.code, "malformed-input")
            self.assert_no_outputs(directory)

    def test_existing_regular_or_symlink_destinations_are_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            submission, source_root = self.make_submission(directory)
            aggregate = root / "week1.aggregate.jsonl"
            aggregate.write_text("caller-owned\n", encoding="utf-8")
            aggregate.chmod(0o644)
            result = self.publish(submission, directory, source_root=source_root)
            self.assertFalse(result.ok)
            self.assertEqual(result.failure.code, "output-exists")
            self.assertEqual(aggregate.read_text(encoding="utf-8"), "caller-owned\n")
            self.assertEqual(stat.S_IMODE(aggregate.stat().st_mode), 0o644)
            self.assertFalse((root / "week1.aggregate.manifest.json").exists())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            submission, source_root = self.make_submission(directory)
            aggregate = root / "week1.aggregate.jsonl"
            target = root / "caller-owned"
            target.write_text("caller-owned\n", encoding="utf-8")
            aggregate.symlink_to(target)
            result = self.publish(submission, directory, source_root=source_root)
            self.assertFalse(result.ok)
            self.assertEqual(result.failure.code, "output-exists")
            self.assertEqual(target.read_text(encoding="utf-8"), "caller-owned\n")
            self.assertTrue(aggregate.is_symlink())
            self.assertFalse((root / "week1.aggregate.manifest.json").exists())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            submission, source_root = self.make_submission(directory)
            manifest = root / "week1.aggregate.manifest.json"
            target = root / "caller-owned-manifest"
            target.write_text("caller-owned\n", encoding="utf-8")
            manifest.symlink_to(target)
            result = self.publish(submission, directory, source_root=source_root)
            self.assertFalse(result.ok)
            self.assertEqual(result.failure.code, "output-exists")
            self.assertEqual(target.read_text(encoding="utf-8"), "caller-owned\n")
            self.assertTrue(manifest.is_symlink())
            self.assertFalse((root / "week1.aggregate.jsonl").exists())

    def test_compatibility_aggregate_is_not_a_charter_normalized_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            submission, source_root = self.make_submission(directory)
            result = normalize_week1_submission(submission, semgrep_source_root=source_root)
            self.assertTrue(result.ok)
            self.assertTrue(result.records)
            for record in result.records:
                with self.assertRaises(ValidationError):
                    NormalizedFinding.model_validate(record.model_dump())


if __name__ == "__main__":
    unittest.main()
