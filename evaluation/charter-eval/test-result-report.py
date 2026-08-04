from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import asdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCRIPT = HERE / "result-report.py"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.charter_requests import make_spec


REQUEST_ID = "12345678-a0b1-4c2d-8e3f-123456789abc"


def result_report_module():
    spec = importlib.util.spec_from_file_location("charter_result_report", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def manifest_writer():
    spec = importlib.util.spec_from_file_location("manifest_contract", ROOT / "scripts" / "sentinel-manifest.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha() -> str:
    return "a" * 64


def create_run(directory: Path) -> Path:
    run = directory / "current-run"
    run.mkdir(mode=0o700)
    manifest = {
        "schema_version": "sentinel-run/v1", "run_id": "current-run", "profile": "charter",
        "input": {"source": "local", "type": "local-charter-input", "version": "1", "sha256": sha()},
        "identity": {"target_sha256": sha(), "config_sha256": sha(), "policy_sha256": sha(), "output_sha256": ""},
        "stage_order": ["preflight"], "stages": {"preflight": {"status": "passed", "at_ms": int(time.time() * 1000), "index": 0}},
        "required_skips": [], "resources": [], "recovery_hint": "resume only with exact immutable identity",
        "metrics": {"version": "RunMetrics/v1", "duration_ms": 1, "request_count": 0, "warning_count": 0,
                    "approve_count": 0, "reject_count": 0, "llm_error_count": 0, "application_error_count": 0},
        "result": {"status": "passed", "action_sent": False}, "created_at_ms": int(time.time() * 1000) - 1,
    }
    contract = manifest_writer()
    manifest["identity"]["output_sha256"] = contract.output_digest(manifest)
    contract.write(run / "manifest.json", manifest)
    request_spec = make_spec(run_id="current-run", method="GET",
                             path="/sentinel-charter/rest/products/search", query="q=apple")
    spec_doc = asdict(request_spec)
    spec_doc["headers"] = [list(pair) for pair in request_spec.headers]
    (run / "request-spec.json").write_text(json.dumps(spec_doc), encoding="utf-8")
    normalized = [
        {"schema_version": "1.0", "finding_id": "finding:54f7ccdc0641c2fa090d1e7a541bc195ba01e5026b05484d6ff34fcfa07dde21", "source_ids": ["nuclei:one"],
         "tool": "nuclei", "scanner": "DAST", "title": "Charter HTTP missing security headers", "severity": "Info",
         "location": "http://127.0.0.1:13000/", "evidence": ["template-id=header"]},
        {"schema_version": "1.0", "finding_id": "finding:charter-trivy-secret", "source_ids": ["trivy:one"],
         "tool": "trivy", "scanner": "SAST", "title": "Generic API key", "severity": "High",
         "location": "file:package-lock.json", "evidence": ["rule-id=generic-api-key"]},
    ]
    report = [{"schema_version": "1.0", "finding_id": "finding:54f7ccdc0641c2fa090d1e7a541bc195ba01e5026b05484d6ff34fcfa07dde21", "name": "Charter HTTP missing security headers",
               "severity": "Info", "location": "http://127.0.0.1:13000/", "scanner_evidence": ["template-id=header"],
               "explanation": "Scanner observed a missing header.", "remediation": "Set the documented header.",
               "confidence": "high", "source_ids": ["nuclei:one"], "knowledge_provenance": ["owasp:headers"]}]
    for name, records in (("normalized.jsonl", normalized), ("report.jsonl", report)):
        (run / name).write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    (run / "request.json").write_text(json.dumps({
        "schema_version": "charter-request-outcome/v1", "action_sent": False,
        "request_count": 0, "receipt_sha256": None,
    }), encoding="utf-8")
    for name in ("manifest.json", "request-spec.json", "normalized.jsonl", "report.jsonl", "request.json"):
        (run / name).chmod(0o600)
    refresh_bindings(run, manifest)
    return run


def refresh_bindings(run: Path, manifest: dict | None = None) -> None:
    manifest = manifest or json.loads((run / "manifest.json").read_text())
    bindings = {
        "schema_version": "charter-artifact-bindings/v2", "run_id": "current-run",
        "manifest_output_sha256": manifest["identity"]["output_sha256"],
        "manifest_sha256": hashlib.sha256((run / "manifest.json").read_bytes()).hexdigest(),
        "normalized_sha256": hashlib.sha256((run / "normalized.jsonl").read_bytes()).hexdigest(),
        "report_sha256": hashlib.sha256((run / "report.jsonl").read_bytes()).hexdigest(),
        "request_sha256": hashlib.sha256((run / "request.json").read_bytes()).hexdigest(),
        "receipt_sha256": (hashlib.sha256((run / "receipt.json").read_bytes()).hexdigest()
                           if (run / "receipt.json").exists() else None),
        "request_spec_sha256": hashlib.sha256((run / "request-spec.json").read_bytes()).hexdigest(),
    }
    (run / "artifact-bindings.json").write_text(json.dumps(bindings), encoding="utf-8")
    (run / "artifact-bindings.json").chmod(0o600)


def create_action_run(directory: Path, *, receipt_v2: str | None = None) -> Path:
    run = create_run(directory)
    manifest = json.loads((run / "manifest.json").read_text())
    manifest["metrics"]["request_count"] = 1
    manifest["metrics"]["approve_count"] = 1
    manifest["result"]["action_sent"] = True
    contract = manifest_writer()
    manifest["identity"]["output_sha256"] = contract.output_digest(manifest)
    contract.write(run / "manifest.json", manifest)
    spec = json.loads((run / "request-spec.json").read_text())
    receipt = {"schema_version": "sentinel-charter-receipt/v1", "request_id": spec["request_id"],
               "status": 200, "bytes": 0, "receipt_digest": "a" * 64}
    if receipt_v2 == "accepted":
        receipt = {"schema_version": "sentinel-charter-receipt/v2", "request_id": spec["request_id"],
                   "status": 200, "bytes": 2, "receipt_digest": "a" * 64,
                   "preview": "ok", "preview_truncated": False}
    elif receipt_v2 == "quarantine":
        receipt = {"schema_version": "sentinel-charter-receipt/v2", "request_id": spec["request_id"],
                   "status": 200, "bytes": 2, "receipt_digest": "a" * 64,
                   "quarantine": {"pii-email": 1}}
    (run / "receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
    (run / "request-descriptor.json").write_text(json.dumps({"schema_version": "sentinel-request-descriptor/v1", "receipt": "receipt.json"}), encoding="utf-8")
    request = {"schema_version": "charter-request-outcome/v1", "action_sent": True,
               "request_count": 1, "receipt_sha256": hashlib.sha256((run / "receipt.json").read_bytes()).hexdigest()}
    (run / "request.json").write_text(json.dumps(request), encoding="utf-8")
    for name in ("manifest.json", "receipt.json", "request-descriptor.json", "request.json"):
        (run / name).chmod(0o600)
    refresh_bindings(run, manifest)
    return run


class ResultReportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result_report = result_report_module()

    def command(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["python3", str(SCRIPT), *args], text=True, capture_output=True, check=False)

    def test_canonical_request_id_is_the_only_generic_pii_exception(self):
        self.result_report._assert_sanitized({"request_id": REQUEST_ID})
        self.result_report._assert_sanitized({
            "artifact-bindings": {
                "bindings": {"request_id": REQUEST_ID, "manifest_sha256": "a" * 64},
            },
        })

        with self.assertRaises(self.result_report.EvaluationError):
            self.result_report._assert_sanitized({"trace_id": REQUEST_ID})

    def test_request_id_keeps_sensitive_values_and_keys_fail_closed(self):
        values = (
            "1234567890123",
            "12345678-A0B1-4c2d-8e3f-123456789abc",
            "12345678-a0b1-4c2d-8e3f-123456789abc0",
            "person@example.test",
            "eyJabc.def.ghi",
            "token=secret-value",
        )
        for value in values:
            with self.subTest(value=value), self.assertRaises(self.result_report.EvaluationError):
                self.result_report._assert_sanitized({"request_id": value})
        with self.assertRaises(self.result_report.EvaluationError):
            self.result_report._assert_sanitized({"authorization": REQUEST_ID})

    def test_sent_action_with_canonical_request_id_evaluates_and_verifies(self):
        with tempfile.TemporaryDirectory() as directory:
            run = create_action_run(Path(directory))
            spec_path, receipt_path, request_path = (run / "request-spec.json", run / "receipt.json", run / "request.json")
            spec = json.loads(spec_path.read_text())
            receipt = json.loads(receipt_path.read_text())
            spec["request_id"] = REQUEST_ID
            receipt["request_id"] = REQUEST_ID
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            request = json.loads(request_path.read_text())
            request["receipt_sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
            request_path.write_text(json.dumps(request), encoding="utf-8")
            for path in (spec_path, receipt_path, request_path):
                path.chmod(0o600)
            refresh_bindings(run)

            evaluated = self.command("evaluate", "--run-dir", str(run))
            self.assertEqual(evaluated.returncode, 0, evaluated.stderr)
            verified = self.command("verify", "--run-dir", str(run))
            self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_current_run_report_has_all_metrics_and_hash_bindings(self):
        with tempfile.TemporaryDirectory() as directory:
            run = create_run(Path(directory))
            result = self.command("evaluate", "--run-dir", str(run))
            self.assertEqual(result.returncode, 0, result.stderr)
            output = run / "charter-evaluation.json"
            value = json.loads(output.read_text())
            self.assertEqual(value["confusion"], {"tp": 3, "fp": 0, "fn": 1, "tn": 1})
            self.assertEqual(set(value["run_metrics"]), {"version", "duration_ms", "request_count", "warning_count", "approve_count", "reject_count", "llm_error_count", "application_error_count"})
            self.assertEqual(len(value["case_analysis"]), 5)
            self.assertTrue(value["limitations"] and value["improvement_proposals"])
            self.assertEqual(stat.S_IMODE(os.stat(output).st_mode), 0o600)
            verified = self.command("verify", "--run-dir", str(run))
            self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_stale_or_outside_or_empty_artifacts_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            run = create_run(Path(directory))
            self.assertEqual(self.command("evaluate", "--run-dir", str(run)).returncode, 0)
            result_path = run / "charter-evaluation.json"
            forged = json.loads(result_path.read_text())
            forged["confusion"] = {"tp": 999, "fp": 0, "fn": 0, "tn": 0}
            forged["case_analysis"] = []
            forged["limitations"] = ["forged"]
            result_path.write_text(json.dumps(forged), encoding="utf-8")
            self.assertEqual(self.command("verify", "--run-dir", str(run)).returncode, 2)
            self.assertEqual(self.command("evaluate", "--run-dir", str(run)).returncode, 0)
            result_path.chmod(0o644)
            self.assertEqual(self.command("verify", "--run-dir", str(run)).returncode, 2)
            result_path.chmod(0o600)
            original_normalized = (run / "normalized.jsonl").read_text(encoding="utf-8")
            (run / "normalized.jsonl").write_text("{}\n", encoding="utf-8")
            stale = self.command("verify", "--run-dir", str(run))
            self.assertEqual(stale.returncode, 2)
            outside = self.command("evaluate", "--run-dir", str(run), "--normalized", str(HERE.parent / "pentest-eval" / "captured" / "recon-map.json"))
            self.assertEqual(outside.returncode, 2)
            (run / "normalized.jsonl").write_text(original_normalized, encoding="utf-8")
            refresh_bindings(run)
            (run / "report.jsonl").write_text("", encoding="utf-8")
            empty = self.command("evaluate", "--run-dir", str(run))
            self.assertEqual(empty.returncode, 2)

    def test_receipt_contract_and_self_consistent_cross_request_binding_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            run = create_action_run(Path(directory))
            evaluated = self.command("evaluate", "--run-dir", str(run))
            self.assertEqual(evaluated.returncode, 0, evaluated.stderr)
            self.assertNotIn("q=apple", evaluated.stdout)
            self.assertEqual(self.command("verify", "--run-dir", str(run)).returncode, 0)
            receipt = json.loads((run / "receipt.json").read_text())
            receipt["request_id"] = "other-request"
            (run / "receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
            (run / "receipt.json").chmod(0o600)
            request = json.loads((run / "request.json").read_text())
            request["receipt_sha256"] = hashlib.sha256((run / "receipt.json").read_bytes()).hexdigest()
            (run / "request.json").write_text(json.dumps(request), encoding="utf-8")
            (run / "request.json").chmod(0o600)
            refresh_bindings(run)
            self.assertEqual(self.command("evaluate", "--run-dir", str(run)).returncode, 2)
            self.assertEqual(self.command("verify", "--run-dir", str(run)).returncode, 2)

    def test_receipt_v2_accepted_and_quarantine_are_strictly_evaluated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for kind in ("accepted", "quarantine"):
                with self.subTest(kind=kind):
                    case_root = root / kind
                    case_root.mkdir()
                    run = create_action_run(case_root, receipt_v2=kind)
                    self.assertEqual(self.command("evaluate", "--run-dir", str(run)).returncode, 0)
            invalid_root = root / "invalid"
            invalid_root.mkdir()
            invalid = create_action_run(invalid_root, receipt_v2="accepted")
            receipt_path = invalid / "receipt.json"
            receipt = json.loads(receipt_path.read_text())
            receipt["quarantine"] = {"pii-email": 1}
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            receipt_path.chmod(0o600)
            request = json.loads((invalid / "request.json").read_text())
            request["receipt_sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
            (invalid / "request.json").write_text(json.dumps(request), encoding="utf-8")
            (invalid / "request.json").chmod(0o600)
            refresh_bindings(invalid)
            self.assertEqual(self.command("evaluate", "--run-dir", str(invalid)).returncode, 2)

    def test_self_consistent_duplicate_status_receipt_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            run = create_action_run(Path(directory))
            receipt = json.loads((run / "receipt.json").read_text())
            (run / "receipt.json").write_text(
                '{"schema_version":"sentinel-charter-receipt/v1","request_id":%s,"status":200,"status":200,"bytes":%d,"receipt_digest":%s}\n'
                % (json.dumps(receipt["request_id"]), receipt["bytes"], json.dumps(receipt["receipt_digest"])),
                encoding="utf-8",
            )
            (run / "receipt.json").chmod(0o600)
            request = json.loads((run / "request.json").read_text())
            request["receipt_sha256"] = hashlib.sha256((run / "receipt.json").read_bytes()).hexdigest()
            (run / "request.json").write_text(json.dumps(request), encoding="utf-8")
            (run / "request.json").chmod(0o600)
            refresh_bindings(run)
            self.assertEqual(self.command("evaluate", "--run-dir", str(run)).returncode, 2)
            self.assertEqual(self.command("verify", "--run-dir", str(run)).returncode, 2)

    def test_action_artifacts_must_be_private_regular_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("request-spec.json", "request.json", "receipt.json", "artifact-bindings.json"):
                with self.subTest(name=name):
                    case_root = root / name
                    case_root.mkdir()
                    run = create_action_run(case_root)
                    (run / name).chmod(0o644)
                    self.assertEqual(self.command("evaluate", "--run-dir", str(run)).returncode, 2)

            symlink_root = root / "symlink"
            symlink_root.mkdir()
            run = create_action_run(symlink_root)
            receipt = run / "receipt.json"
            copied_receipt = run / "receipt-copy.json"
            copied_receipt.write_bytes(receipt.read_bytes())
            copied_receipt.chmod(0o600)
            receipt.unlink()
            receipt.symlink_to(copied_receipt.name)
            self.assertEqual(self.command("evaluate", "--run-dir", str(run)).returncode, 2)

    def test_zero_action_stray_evidence_and_world_readable_binding_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            run = create_run(Path(directory))
            (run / "receipt.json").write_text("{}", encoding="utf-8")
            (run / "receipt.json").chmod(0o600)
            self.assertEqual(self.command("evaluate", "--run-dir", str(run)).returncode, 2)
            (run / "receipt.json").unlink()
            (run / "artifact-bindings.json").chmod(0o644)
            self.assertEqual(self.command("evaluate", "--run-dir", str(run)).returncode, 2)

    def test_confusion_matrix_exercises_false_negative_and_false_positive(self):
        with tempfile.TemporaryDirectory() as directory:
            run = create_run(Path(directory))
            normalized = [json.loads(line) for line in (run / "normalized.jsonl").read_text().splitlines()]
            normalized = [record for record in normalized if record["finding_id"] != "finding:charter-trivy-secret"]
            normalized.append({
                "schema_version": "1.0", "finding_id": "finding:charter-forbidden-false-positive",
                "source_ids": ["trivy:forbidden"], "tool": "trivy", "scanner": "SAST",
                "title": "Unexpected finding", "severity": "Low", "location": "file:forbidden.env",
                "evidence": ["rule-id=unexpected"],
            })
            (run / "normalized.jsonl").write_text("".join(json.dumps(record) + "\n" for record in normalized), encoding="utf-8")
            refresh_bindings(run)
            result = self.command("evaluate", "--run-dir", str(run))
            self.assertEqual(result.returncode, 0, result.stderr)
            value = json.loads((run / "charter-evaluation.json").read_text())
            self.assertEqual(value["confusion"], {"tp": 3, "fp": 1, "fn": 1, "tn": 0})
            outcomes = {entry["case_id"]: entry["outcome"] for entry in value["case_analysis"]}
            self.assertEqual(outcomes["CE-02"], "TP")
            self.assertEqual(outcomes["CE-04"], "FP")

    def test_vacuous_review_or_malformed_metrics_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            run = create_run(Path(directory))
            cases = json.loads((HERE / "cases.json").read_text())
            gold = json.loads((HERE / "gold.json").read_text())
            for case in cases["cases"]:
                case["truth"] = "positive"
            cases_path, gold_path = Path(directory) / "cases.json", Path(directory) / "gold.json"
            cases_path.write_text(json.dumps(cases), encoding="utf-8")
            gold_path.write_text(json.dumps(gold), encoding="utf-8")
            vacuous = self.command("evaluate", "--run-dir", str(run), "--cases", str(cases_path), "--gold", str(gold_path))
            self.assertEqual(vacuous.returncode, 2)

            manifest_path = run / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["metrics"]["extra"] = 0
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            malformed = self.command("evaluate", "--run-dir", str(run))
            self.assertEqual(malformed.returncode, 2)


if __name__ == "__main__":
    unittest.main()
