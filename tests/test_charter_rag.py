"""Offline contract tests for the committed six-week charter knowledge corpus."""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rag import ingest, retrieve
from rag.store import Hit


MANIFEST = REPO_ROOT / "rag" / "charter-corpus-manifest.json"


class CharterCorpusTests(unittest.TestCase):
    def test_committed_corpus_is_complete_and_digest_bound(self) -> None:
        corpus = ingest.validate_charter_corpus(MANIFEST)
        self.assertEqual(len(corpus.documents), 24)
        self.assertEqual(len([item for item in corpus.documents if item.id.startswith(("sqli-", "xss-"))]), 8)
        self.assertRegex(corpus.corpus_digest, r"^[0-9a-f]{64}$")
        for document in corpus.documents:
            self.assertTrue(document.content)
            self.assertTrue(document.source)
            self.assertTrue(document.source_ref.startswith("https://"))
            self.assertTrue(document.license)
            self.assertTrue(document.version)
            self.assertRegex(document.sha256, r"^[0-9a-f]{64}$")

    def test_sqli_and_xss_retrieval_return_bounded_content_and_provenance(self) -> None:
        for query in ("SQL Injection", "XSS"):
            result = retrieve.retrieve_charter(query, k=3)
            self.assertEqual(len(result.results), 3)
            self.assertRegex(result.corpus_digest, r"^[0-9a-f]{64}$")
            self.assertRegex(result.retrieval_digest, r"^[0-9a-f]{64}$")
            for item in result.results:
                self.assertTrue(item.content)
                self.assertLessEqual(len(item.content), retrieve.MAX_CHARTER_CONTENT_CHARS)
                self.assertIn("https://", item.provenance)
                self.assertIn("sha256:", item.provenance)
        self.assertNotEqual(
            retrieve.retrieve_charter("SQL Injection").retrieval_digest,
            retrieve.retrieve_charter("XSS").retrieval_digest,
        )

    def test_phase_two_report_adapter_returns_knowledge_items(self) -> None:
        from agent.report import KnowledgeItem

        items = retrieve.charter_knowledge_items("SQL Injection", k=2)
        self.assertEqual(len(items), 2)
        self.assertTrue(all(isinstance(item, KnowledgeItem) for item in items))
        self.assertTrue(all(item.content and item.provenance for item in items))

    def test_bad_digest_fails_before_store_connection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "rag"
            shutil.copytree(REPO_ROOT / "rag" / "charter-examples", root / "charter-examples")
            manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
            manifest["examples"][0]["sha256"] = "0" * 64
            target = root / "manifest.json"
            target.write_text(json.dumps(manifest), encoding="utf-8")
            args = SimpleNamespace(charter_manifest=str(target))
            with mock.patch("rag.ingest.store.connect") as connect:
                with self.assertRaisesRegex(ingest.CharterCorpusError, "SHA-256 mismatch"):
                    ingest.ingest(["charter"], args)
            connect.assert_not_called()

    def test_unmanifested_example_and_missing_coverage_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "rag"
            shutil.copytree(REPO_ROOT / "rag" / "charter-examples", root / "charter-examples")
            manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
            manifest["examples"].pop()
            target = root / "manifest.json"
            target.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ingest.CharterCorpusError, "unmanifested"):
                ingest.validate_charter_corpus(target)

            manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
            manifest["documents"] = manifest["documents"][1:]
            target.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ingest.CharterCorpusError, "OWASP Top 10 coverage is incomplete"):
                ingest.validate_charter_corpus(target)

    def test_out_of_range_examples_and_missing_provenance_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "rag"
            shutil.copytree(REPO_ROOT / "rag" / "charter-examples", root / "charter-examples")
            manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
            manifest["examples"] = manifest["examples"][:9]
            target = root / "manifest.json"
            target.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ingest.CharterCorpusError, "10-20"):
                ingest.validate_charter_corpus(target)

            manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
            manifest["documents"][0]["source"] = ""
            target.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ingest.CharterCorpusError, "empty source"):
                ingest.validate_charter_corpus(target)

    def test_malformed_or_unavailable_charter_retrieval_is_explicit(self) -> None:
        with self.assertRaisesRegex(retrieve.CharterRetrievalError, "non-empty query"):
            retrieve.retrieve_charter("")
        with self.assertRaisesRegex(retrieve.CharterRetrievalError, "unavailable"):
            retrieve.retrieve_charter("SQL Injection", manifest_path="/does/not/exist.json")

    def test_legacy_hybrid_fusion_remains_unchanged(self) -> None:
        first = Hit(1, 1, "legacy", "one", None, "one", 1.0)
        second = Hit(2, 2, "legacy", "two", None, "two", 1.0)
        fused = retrieve.rrf_fuse([[first, second], [second]])
        self.assertEqual([item.chunk_id for item in fused], [2, 1])


if __name__ == "__main__":
    unittest.main()
