"""Ingest sources into the pgvector store: normalise -> chunk -> embed -> insert (idempotent).

Idempotent by construction: documents upsert on (source, source_ref) and chunks insert
ON CONFLICT (content_sha256) DO NOTHING, so a second run of the same corpus adds zero chunks.

    rag/.venv/bin/python -m rag.ingest --sources owasp nvd attack-surface
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from agent import pii

from . import chunking, embedding, sources, store

DEFAULT_ATTACK_SURFACE = os.path.join(
    os.path.dirname(__file__), "..", "attack-surface", "baselines", "juice-shop-df1b6bbd8bce.json"
)
DEFAULT_CHARTER_MANIFEST = Path(__file__).with_name("charter-corpus-manifest.json")
CHARTER_SCHEMA_VERSION = "sentinel-charter-corpus/v1"
CHARTER_EXAMPLE_MIN = 10
CHARTER_EXAMPLE_MAX = 20


class CharterCorpusError(ValueError):
    """The committed charter knowledge corpus is absent or cannot be trusted."""


@dataclass(frozen=True)
class CharterDocument:
    id: str
    title: str
    content: str
    source: str
    source_ref: str
    license: str
    version: str
    sha256: str


@dataclass(frozen=True)
class CharterCorpus:
    documents: tuple[CharterDocument, ...]
    corpus_digest: str


def _content_sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _require_text(entry: dict, field: str, label: str) -> str:
    value = entry.get(field)
    if not isinstance(value, str) or not value.strip():
        raise CharterCorpusError(f"{label}: missing or empty {field}")
    return value


def _validate_digest(entry: dict, content: str, label: str) -> str:
    declared = _require_text(entry, "sha256", label)
    actual = _content_sha256(content)
    if declared != actual:
        raise CharterCorpusError(f"{label}: content SHA-256 mismatch")
    return actual


def _manifest_path(path: str | os.PathLike[str] | None) -> Path:
    return Path(path) if path is not None else DEFAULT_CHARTER_MANIFEST


def _load_manifest(path: Path) -> dict:
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise CharterCorpusError(f"cannot load charter corpus manifest {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise CharterCorpusError("charter corpus manifest must be a JSON object")
    if data.get("schema_version") != CHARTER_SCHEMA_VERSION:
        raise CharterCorpusError("unsupported or missing charter corpus schema_version")
    _require_text(data, "corpus_version", "manifest")
    return data


def _validated_document(entry: dict, label: str, content: str, title: str) -> CharterDocument:
    if not isinstance(entry, dict):
        raise CharterCorpusError(f"{label}: entry must be an object")
    identifier = _require_text(entry, "id", label)
    digest = _validate_digest(entry, content, label)
    source_ref = _require_text(entry, "source_ref", label)
    if not source_ref.startswith("https://"):
        raise CharterCorpusError(f"{label}: source_ref must be an HTTPS URL")
    _require_text(entry, "content_origin", label)
    return CharterDocument(
        id=identifier,
        title=title,
        content=content,
        source=_require_text(entry, "source", label),
        source_ref=source_ref,
        license=_require_text(entry, "license", label),
        version=_require_text(entry, "version", label),
        sha256=digest,
    )


def validate_charter_corpus(
    manifest_path: str | os.PathLike[str] | None = None,
) -> CharterCorpus:
    """Validate the committed, offline charter corpus and return a digest-bound snapshot.

    This deliberately does no network or database I/O. Any malformed coverage, provenance,
    example file, or digest is a terminal error before analysis can use the corpus.
    """
    path = _manifest_path(manifest_path)
    manifest = _load_manifest(path)
    coverage = manifest.get("required_coverage")
    if not isinstance(coverage, dict):
        raise CharterCorpusError("manifest: required_coverage must be an object")
    required_top10 = coverage.get("owasp_top_10")
    required_tools = coverage.get("scanner_tool_docs")
    if not isinstance(required_top10, list) or not required_top10:
        raise CharterCorpusError("manifest: required OWASP Top 10 coverage is absent")
    if not isinstance(required_tools, list) or not required_tools:
        raise CharterCorpusError("manifest: required scanner/tool coverage is absent")
    if len(set(required_top10)) != len(required_top10) or len(set(required_tools)) != len(required_tools):
        raise CharterCorpusError("manifest: required coverage contains duplicates")

    raw_documents = manifest.get("documents")
    if not isinstance(raw_documents, list):
        raise CharterCorpusError("manifest: documents must be a list")
    documents: list[CharterDocument] = []
    ids: set[str] = set()
    found_top10: set[str] = set()
    found_tools: set[str] = set()
    for index, entry in enumerate(raw_documents):
        label = f"documents[{index}]"
        if not isinstance(entry, dict):
            raise CharterCorpusError(f"{label}: entry must be an object")
        content = _require_text(entry, "content", label)
        document = _validated_document(entry, label, content, _require_text(entry, "title", label))
        if document.id in ids:
            raise CharterCorpusError(f"{label}: duplicate id {document.id!r}")
        ids.add(document.id)
        coverage_item = entry.get("coverage")
        if not isinstance(coverage_item, dict) or len(coverage_item) != 1:
            raise CharterCorpusError(f"{label}: exactly one coverage assertion is required")
        if "owasp_top_10" in coverage_item:
            value = coverage_item["owasp_top_10"]
            if value not in required_top10:
                raise CharterCorpusError(f"{label}: unknown OWASP Top 10 coverage")
            found_top10.add(value)
        elif "scanner_tool_docs" in coverage_item:
            value = coverage_item["scanner_tool_docs"]
            if value not in required_tools:
                raise CharterCorpusError(f"{label}: unknown scanner/tool coverage")
            found_tools.add(value)
        else:
            raise CharterCorpusError(f"{label}: unsupported coverage category")
        documents.append(document)
    if found_top10 != set(required_top10):
        raise CharterCorpusError("manifest: OWASP Top 10 coverage is incomplete")
    if found_tools != set(required_tools):
        raise CharterCorpusError("manifest: scanner/tool documentation coverage is incomplete")

    examples = manifest.get("examples")
    if not isinstance(examples, list) or not CHARTER_EXAMPLE_MIN <= len(examples) <= CHARTER_EXAMPLE_MAX:
        raise CharterCorpusError(
            f"manifest: examples must contain {CHARTER_EXAMPLE_MIN}-{CHARTER_EXAMPLE_MAX} entries"
        )
    root = path.parent.resolve()
    declared_paths: set[Path] = set()
    for index, entry in enumerate(examples):
        label = f"examples[{index}]"
        if not isinstance(entry, dict):
            raise CharterCorpusError(f"{label}: entry must be an object")
        relative = _require_text(entry, "path", label)
        example_path = (root / relative).resolve()
        if root not in example_path.parents or example_path.suffix != ".json":
            raise CharterCorpusError(f"{label}: invalid example path")
        if example_path in declared_paths:
            raise CharterCorpusError(f"{label}: duplicate example path")
        declared_paths.add(example_path)
        try:
            payload = json.loads(example_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CharterCorpusError(f"{label}: cannot load example: {exc}") from exc
        if not isinstance(payload, dict) or payload.get("id") != entry.get("id"):
            raise CharterCorpusError(f"{label}: example id does not match manifest")
        content = _require_text(payload, "content", label)
        document = _validated_document(entry, label, content, entry["id"])
        if document.id in ids:
            raise CharterCorpusError(f"{label}: duplicate id {document.id!r}")
        ids.add(document.id)
        documents.append(document)
    example_dir = root / "charter-examples"
    actual_paths = {candidate.resolve() for candidate in example_dir.rglob("*.json")} if example_dir.is_dir() else set()
    if actual_paths != declared_paths:
        raise CharterCorpusError("manifest: examples contain missing or unmanifested files")

    canonical = [
        {
            "id": document.id,
            "source": document.source,
            "source_ref": document.source_ref,
            "license": document.license,
            "version": document.version,
            "sha256": document.sha256,
            "content": document.content,
        }
        for document in sorted(documents, key=lambda item: item.id)
    ]
    digest = _content_sha256(json.dumps(canonical, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    return CharterCorpus(tuple(documents), digest)


def charter_corpus_digest(manifest_path: str | os.PathLike[str] | None = None) -> str:
    """Return the verified corpus digest for controller/run-manifest binding."""
    return validate_charter_corpus(manifest_path).corpus_digest


def charter_source_docs(manifest_path: str | os.PathLike[str] | None = None) -> list[sources.SourceDoc]:
    """Adapt the verified offline corpus to the existing pgvector ingest contract."""
    corpus = validate_charter_corpus(manifest_path)
    return [
        sources.SourceDoc("charter", f"{document.source_ref}#sentinel-{document.id}",
                          document.title, document.content, "record")
        for document in corpus.documents
    ]


def _docs_for(source: str, args) -> list[sources.SourceDoc]:
    if source == "owasp":
        return sources.fetch_owasp(refresh=args.refresh)
    if source == "nvd":
        return sources.fetch_nvd(keyword=args.nvd_keyword, limit=args.nvd_limit, refresh=args.refresh)
    if source == "attack-surface":
        path = args.attack_surface_path or DEFAULT_ATTACK_SURFACE
        if not os.path.exists(path):
            print(f"  skip attack-surface: {path} not found")
            return []
        return sources.load_attack_surface(path)
    if source == "charter":
        return charter_source_docs(getattr(args, "charter_manifest", None))
    raise SystemExit(f"unknown source: {source}")


def _chunks_for(doc: sources.SourceDoc) -> list[chunking.Chunk]:
    # Week-9 boundary (decision 0017): scrub PII BEFORE chunking, so the content that is hashed
    # (keep-hash below) and stored is the same scrubbed text — the ON CONFLICT (content_sha256)
    # idempotency holds and a re-ingest still prunes/inserts zero chunks (M2). Defence-in-depth:
    # today's sources (owasp/nvd/attack-surface) carry no PII, but any future PII-bearing source
    # (e.g. ingested agent findings) is scrubbed at this one boundary before it reaches pgvector.
    text = pii.scrub(doc.text) or ""
    if doc.kind == "markdown":
        return chunking.chunk_markdown(text)
    # A structured record is short; store it whole (one chunk), section = None.
    return [chunking.Chunk(section=None, content=text)]


def ingest(source_names: list[str], args) -> dict:
    stats = {"documents": 0, "chunks_seen": 0, "chunks_inserted": 0, "chunks_pruned": 0,
             "charter_corpus_digest": None}
    # Build all source docs before opening a transaction.  In particular, a malformed charter
    # corpus must fail before it can add a partial document to the store.
    prepared = [(source, _docs_for(source, args)) for source in source_names]
    if "charter" in source_names:
        stats["charter_corpus_digest"] = charter_corpus_digest(getattr(args, "charter_manifest", None))
    with store.connect() as conn:
        for source, docs in prepared:
            for doc in docs:
                chunks = _chunks_for(doc)
                if not chunks:
                    continue
                vectors = embedding.embed_passages([c.content for c in chunks])
                doc_id = store.upsert_document(conn, doc.source, doc.source_ref, doc.title)
                stats["documents"] += 1
                # Reconcile: prune this document's chunks that are no longer in the current
                # content, then insert the current ones. Unchanged content => 0 pruned, 0
                # inserted (idempotent); changed upstream => stale chunks removed, not orphaned.
                keep = [store.sha256(c.content) for c in chunks]
                stats["chunks_pruned"] += store.delete_stale_chunks(conn, doc_id, keep)
                for ord_, (c, v) in enumerate(zip(chunks, vectors, strict=True)):
                    stats["chunks_seen"] += 1
                    if store.insert_chunk(conn, doc_id, ord_, c.section, c.content, v):
                        stats["chunks_inserted"] += 1
            conn.commit()
            print(f"  {source}: {stats}")
    return stats


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Ingest threat-intel sources into the RAG store.")
    ap.add_argument("--sources", nargs="+", default=["owasp", "nvd", "attack-surface"],
                    choices=["owasp", "nvd", "attack-surface", "charter"])
    ap.add_argument("--nvd-keyword", default="juice shop")
    ap.add_argument("--nvd-limit", type=int, default=20)
    ap.add_argument("--attack-surface-path", default=None)
    ap.add_argument("--charter-manifest", default=None,
                    help="committed offline charter corpus manifest (default: rag/charter-corpus-manifest.json)")
    ap.add_argument("--refresh", action="store_true",
                    help="re-fetch remote sources, ignoring the local cache (picks up upstream changes)")
    args = ap.parse_args(argv)

    stats = ingest(args.sources, args)
    with store.connect() as conn:
        total = store.count_chunks(conn)
    print(f"done: inserted {stats['chunks_inserted']} new chunks, pruned {stats['chunks_pruned']} stale "
          f"({stats['chunks_seen']} seen); store now holds {total} chunks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
