"""Ingest sources into the pgvector store: normalise -> chunk -> embed -> insert (idempotent).

Idempotent by construction: documents upsert on (source, source_ref) and chunks insert
ON CONFLICT (content_sha256) DO NOTHING, so a second run of the same corpus adds zero chunks.

    rag/.venv/bin/python -m rag.ingest --sources owasp nvd attack-surface
"""
from __future__ import annotations

import argparse
import os
import sys

from . import chunking, embedding, sources, store

DEFAULT_ATTACK_SURFACE = os.path.join(
    os.path.dirname(__file__), "..", "attack-surface", "baselines", "juice-shop-df1b6bbd8bce.json"
)


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
    raise SystemExit(f"unknown source: {source}")


def _chunks_for(doc: sources.SourceDoc) -> list[chunking.Chunk]:
    if doc.kind == "markdown":
        return chunking.chunk_markdown(doc.text)
    # A structured record is short; store it whole (one chunk), section = None.
    return [chunking.Chunk(section=None, content=doc.text)]


def ingest(source_names: list[str], args) -> dict:
    stats = {"documents": 0, "chunks_seen": 0, "chunks_inserted": 0, "chunks_pruned": 0}
    with store.connect() as conn:
        for source in source_names:
            docs = _docs_for(source, args)
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
                for ord_, (c, v) in enumerate(zip(chunks, vectors)):
                    stats["chunks_seen"] += 1
                    if store.insert_chunk(conn, doc_id, ord_, c.section, c.content, v):
                        stats["chunks_inserted"] += 1
            conn.commit()
            print(f"  {source}: {stats}")
    return stats


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Ingest threat-intel sources into the RAG store.")
    ap.add_argument("--sources", nargs="+", default=["owasp", "nvd", "attack-surface"],
                    choices=["owasp", "nvd", "attack-surface"])
    ap.add_argument("--nvd-keyword", default="juice shop")
    ap.add_argument("--nvd-limit", type=int, default=20)
    ap.add_argument("--attack-surface-path", default=None)
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
