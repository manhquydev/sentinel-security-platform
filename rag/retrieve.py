"""Hybrid retrieval: dense + lexical fused with Reciprocal Rank Fusion (RRF).

RRF fuses two ranked lists by rank, not score, so it sidesteps the incompatible scales of cosine
similarity and ts_rank. Each list contributes 1/(rrf_k + rank) to an item's fused score. This is
the standard 2024-2026 hybrid recipe and needs no per-corpus score calibration.

Usable as a library (hybrid_search) or a CLI:
    rag/.venv/bin/python -m rag.retrieve "how does SQL injection bypass authentication"
"""
from __future__ import annotations

import argparse
import sys

from . import embedding, store

RRF_K = 60          # standard constant; larger flattens the rank weighting
CANDIDATE_K = 30     # per-retriever shortlist depth before fusion


def rrf_fuse(lists: list[list[store.Hit]], rrf_k: int = RRF_K) -> list[store.Hit]:
    """Fuse ranked lists of Hits by RRF, keyed on chunk_id. Returns Hits sorted by fused score,
    with .score replaced by the fused value."""
    fused: dict[int, float] = {}
    by_id: dict[int, store.Hit] = {}
    for hits in lists:
        for rank, hit in enumerate(hits, start=1):
            fused[hit.chunk_id] = fused.get(hit.chunk_id, 0.0) + 1.0 / (rrf_k + rank)
            by_id.setdefault(hit.chunk_id, hit)
    ranked = sorted(fused.items(), key=lambda kv: kv[1], reverse=True)
    out = []
    for chunk_id, s in ranked:
        h = by_id[chunk_id]
        out.append(store.Hit(h.chunk_id, h.document_id, h.source, h.source_ref,
                             h.section, h.content, s))
    return out


def hybrid_search(conn, query: str, k: int = 5,
                  candidate_k: int = CANDIDATE_K, rrf_k: int = RRF_K) -> list[store.Hit]:
    if k < 1 or candidate_k < 1:
        raise ValueError(f"k and candidate_k must be >= 1 (got k={k}, candidate_k={candidate_k})")
    if rrf_k < 0:
        raise ValueError(f"rrf_k must be >= 0 (got {rrf_k})")
    qvec = embedding.embed_query(query)
    dense = store.dense_search(conn, qvec, candidate_k)
    lexical = store.lexical_search(conn, query, candidate_k)
    return rrf_fuse([dense, lexical], rrf_k)[:k]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Hybrid RAG retrieval over the threat-intel store.")
    def _positive(v):
        iv = int(v)
        if iv < 1:
            raise argparse.ArgumentTypeError("must be >= 1")
        return iv

    ap.add_argument("query")
    ap.add_argument("-k", type=_positive, default=5)
    ap.add_argument("--mode", choices=["hybrid", "dense", "lexical"], default="hybrid")
    args = ap.parse_args(argv)

    with store.connect() as conn:
        if args.mode == "dense":
            hits = store.dense_search(conn, embedding.embed_query(args.query), args.k)
        elif args.mode == "lexical":
            hits = store.lexical_search(conn, args.query, args.k)
        else:
            hits = hybrid_search(conn, args.query, args.k)

    for i, h in enumerate(hits, 1):
        head = f"[{i}] {h.source}:{h.source_ref}"
        if h.section:
            head += f"  ({h.section})"
        print(f"{head}  score={h.score:.4f}")
        print("    " + " ".join(h.content.split())[:200])
    return 0


if __name__ == "__main__":
    sys.exit(main())
