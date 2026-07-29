"""Hybrid retrieval: dense + lexical fused with Reciprocal Rank Fusion (RRF).

RRF fuses two ranked lists by rank, not score, so it sidesteps the incompatible scales of cosine
similarity and ts_rank. Each list contributes 1/(rrf_k + rank) to an item's fused score. This is
the standard 2024-2026 hybrid recipe and needs no per-corpus score calibration.

Usable as a library (hybrid_search) or a CLI:
    rag/.venv/bin/python -m rag.retrieve "how does SQL injection bypass authentication"
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from typing import Any

from . import embedding, ingest, store

RRF_K = 60          # standard constant; larger flattens the rank weighting
CANDIDATE_K = 30     # per-retriever shortlist depth before fusion
MAX_CHARTER_RESULTS = 5
MAX_CHARTER_CONTENT_CHARS = 600


class CharterRetrievalError(RuntimeError):
    """The offline charter retrieval boundary could not return trusted content."""


@dataclass(frozen=True)
class CharterResult:
    id: str
    content: str
    source: str
    source_ref: str
    license: str
    version: str
    sha256: str
    score: int

    @property
    def provenance(self) -> str:
        return f"{self.source} | {self.source_ref} | sha256:{self.sha256}"

    def as_dict(self) -> dict[str, str | int]:
        return {**asdict(self), "provenance": self.provenance}


@dataclass(frozen=True)
class CharterRetrieval:
    query: str
    corpus_digest: str
    retrieval_digest: str
    results: tuple[CharterResult, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "corpus_digest": self.corpus_digest,
            "retrieval_digest": self.retrieval_digest,
            "results": [result.as_dict() for result in self.results],
        }


_QUERY_TOKEN = re.compile(r"[a-z0-9]+")


def _query_terms(query: str) -> set[str]:
    return set(_QUERY_TOKEN.findall(query.casefold()))


def _charter_score(query: str, document: ingest.CharterDocument) -> int:
    terms = _query_terms(query)
    haystack = f"{document.title} {document.content}".casefold()
    score = sum(term in haystack for term in terms)
    phrase = " ".join(query.casefold().split())
    if phrase and phrase in haystack:
        score += len(terms) + 1
    return score


def _digest_retrieval(query: str, corpus_digest: str, results: list[CharterResult]) -> str:
    payload = {
        "query": query,
        "corpus_digest": corpus_digest,
        "results": [
            {"id": result.id, "sha256": result.sha256, "content": result.content}
            for result in results
        ],
    }
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def retrieve_charter(
    query: str,
    k: int = 3,
    *,
    manifest_path: str | None = None,
    max_content_chars: int = MAX_CHARTER_CONTENT_CHARS,
) -> CharterRetrieval:
    """Return bounded committed corpus content with provenance and digest binding.

    Unlike the legacy pgvector search, this adapter is intentionally offline and manifest-bound;
    it is the charter path for the analysis agent.  A damaged or unavailable corpus is an explicit
    failure, never a citation-only result.
    """
    if not isinstance(query, str) or not query.strip():
        raise CharterRetrievalError("charter retrieval requires a non-empty query")
    if not isinstance(k, int) or not 1 <= k <= MAX_CHARTER_RESULTS:
        raise CharterRetrievalError(f"charter retrieval k must be 1-{MAX_CHARTER_RESULTS}")
    if not isinstance(max_content_chars, int) or not 1 <= max_content_chars <= MAX_CHARTER_CONTENT_CHARS:
        raise CharterRetrievalError(f"max_content_chars must be 1-{MAX_CHARTER_CONTENT_CHARS}")
    try:
        corpus = ingest.validate_charter_corpus(manifest_path)
    except ingest.CharterCorpusError as exc:
        raise CharterRetrievalError(f"charter corpus unavailable: {exc}") from exc

    ranked = sorted(
        ((-_charter_score(query, document), document.id, document) for document in corpus.documents),
        key=lambda value: (value[0], value[1]),
    )
    selected: list[CharterResult] = []
    for negative_score, _, document in ranked:
        score = -negative_score
        if score <= 0:
            continue
        content = document.content[:max_content_chars]
        if not content.strip():
            raise CharterRetrievalError(f"charter corpus returned empty content for {document.id}")
        selected.append(CharterResult(
            id=document.id,
            content=content,
            source=document.source,
            source_ref=document.source_ref,
            license=document.license,
            version=document.version,
            sha256=document.sha256,
            score=score,
        ))
        if len(selected) == k:
            break
    if not selected:
        raise CharterRetrievalError("charter corpus has no content relevant to query")
    retrieval_digest = _digest_retrieval(query, corpus.corpus_digest, selected)
    return CharterRetrieval(query, corpus.corpus_digest, retrieval_digest, tuple(selected))


def charter_knowledge_items(query: str, k: int = 3) -> list[Any]:
    """Adapter for Phase-2 report construction: actual content plus auditable provenance.

    `KnowledgeItem` stays owned by `agent.report`; importing it lazily avoids making the legacy
    RAG retrieval path depend on the charter reporting module until that path is selected.
    """
    retrieval = retrieve_charter(query, k=k)
    try:
        from agent.report import KnowledgeItem
    except ImportError as exc:  # pragma: no cover - only while Phase 2 is not installed
        raise CharterRetrievalError("charter report adapter is unavailable") from exc
    return [KnowledgeItem(content=result.content, provenance=result.provenance) for result in retrieval.results]


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
