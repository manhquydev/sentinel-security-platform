"""Retrieval-accuracy evaluation: hybrid vs dense-only vs lexical-only.

Judges relevance at document level against rag/eval_queries.json and reports Recall@k, MRR, and
nDCG@k for each retrieval mode. The point of the eval is to show that hybrid (dense + lexical via
RRF) is at least as good as either retriever alone on this corpus, and to pin a baseline so a
later change that regresses retrieval fails loudly — the same discipline verify-lake applies to
the lake's counts.

    rag/.venv/bin/python -m rag.evaluate               # print the table
    rag/.venv/bin/python -m rag.evaluate --write-baseline
    rag/.venv/bin/python -m rag.evaluate --check       # fail if hybrid regressed vs baseline
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys

from . import embedding, retrieve, store

QUERIES = os.path.join(os.path.dirname(__file__), "eval_queries.json")
BASELINE = os.path.join(os.path.dirname(__file__), "eval_baseline.json")


def _key(hit: store.Hit) -> str:
    return f"{hit.source}:{hit.source_ref}"


def _ranked_doc_keys(hits: list[store.Hit]) -> list[str]:
    """Collapse chunk hits to a document-level ranked list, first occurrence wins."""
    seen, out = set(), []
    for h in hits:
        k = _key(h)
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def _query_metrics(ranked: list[str], expected: list[str], k: int) -> tuple[float, float, float]:
    """Return (recall@k, reciprocal-rank, nDCG@k) for one query. Correct for any number of
    expected docs: recall is the fraction found, DCG sums every relevant hit in the top-k, and
    IDCG is the ideal placement of min(#expected, k) relevant docs."""
    topk = ranked[:k]
    exp = set(expected)
    positions = [i for i, key in enumerate(topk, start=1) if key in exp]
    recall = len({topk[i - 1] for i in positions}) / len(exp) if exp else 0.0
    rr = 1.0 / positions[0] if positions else 0.0
    dcg = sum(1.0 / math.log2(pos + 1) for pos in positions)
    ideal_n = min(len(exp), k)
    idcg = sum(1.0 / math.log2(j + 1) for j in range(1, ideal_n + 1)) or 1.0
    return recall, rr, dcg / idcg


def _retrieve(conn, mode: str, query: str, k: int) -> list[store.Hit]:
    if mode == "dense":
        return store.dense_search(conn, embedding.embed_query(query), k)
    if mode == "lexical":
        return store.lexical_search(conn, query, k)
    return retrieve.hybrid_search(conn, query, k)


def evaluate(k: int = 10) -> dict:
    with open(QUERIES, encoding="utf-8") as f:
        queries = json.load(f)["queries"]
    results = {}
    with store.connect() as conn:
        for mode in ("dense", "lexical", "hybrid"):
            agg = [0.0, 0.0, 0.0]
            for q in queries:
                ranked = _ranked_doc_keys(_retrieve(conn, mode, q["query"], k))
                m = _query_metrics(ranked, q["expected"], k)
                agg = [a + b for a, b in zip(agg, m)]
            n = len(queries)
            results[mode] = {
                f"recall@{k}": round(agg[0] / n, 4),
                "mrr": round(agg[1] / n, 4),
                f"ndcg@{k}": round(agg[2] / n, 4),
            }
    return {"k": k, "n_queries": len(queries), "modes": results}


def _print(report: dict) -> None:
    k = report["k"]
    print(f"\nRetrieval accuracy over {report['n_queries']} queries (k={k}):\n")
    print(f"  {'mode':<8} {'recall@'+str(k):>10} {'mrr':>8} {'ndcg@'+str(k):>10}")
    for mode, m in report["modes"].items():
        print(f"  {mode:<8} {m[f'recall@{k}']:>10} {m['mrr']:>8} {m[f'ndcg@{k}']:>10}")
    print()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Evaluate RAG retrieval accuracy.")
    ap.add_argument("-k", type=int, default=10)
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument("--check", action="store_true",
                    help="fail if hybrid recall/mrr/ndcg dropped below the committed baseline")
    args = ap.parse_args(argv)

    report = evaluate(args.k)
    _print(report)

    if args.write_baseline:
        with open(BASELINE, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"wrote baseline -> {BASELINE}")
        return 0

    if args.check:
        if not os.path.exists(BASELINE):
            print("no baseline to check against; run --write-baseline first", file=sys.stderr)
            return 2
        with open(BASELINE, encoding="utf-8") as f:
            base = json.load(f)["modes"]["hybrid"]
        cur = report["modes"]["hybrid"]
        regressed = [m for m in base if cur.get(m, 0) < base[m] - 1e-9]
        if regressed:
            print(f"REGRESSION in hybrid: {regressed} dropped below baseline {base}", file=sys.stderr)
            return 1
        print("no regression: hybrid meets or beats the baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
