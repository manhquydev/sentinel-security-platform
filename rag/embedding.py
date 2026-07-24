"""Embedding via fastembed (ONNX BGE-base-en-v1.5, 768-dim). No torch.

The model is loaded once per process and downloaded once from the HF hub into a local cache
(gitignored). BGE distinguishes passages from queries, so ingestion uses embed() and retrieval
uses embed_query() — mixing them costs measurable recall.
"""
from __future__ import annotations

import os

MODEL_NAME = os.environ.get("RAG_EMBED_MODEL", "BAAI/bge-base-en-v1.5")
DIM = 768

_model = None


def _get_model():
    global _model
    if _model is None:
        from fastembed import TextEmbedding
        cache = os.environ.get("RAG_MODEL_CACHE",
                               os.path.join(os.path.dirname(__file__), ".cache"))
        os.makedirs(cache, exist_ok=True)
        _model = TextEmbedding(model_name=MODEL_NAME, cache_dir=cache)
    return _model


def embed_passages(texts: list[str]) -> list[list[float]]:
    """Embed documents/passages for storage."""
    return [v.tolist() for v in _get_model().embed(texts)]


def embed_query(text: str) -> list[float]:
    """Embed a single query (BGE query-side encoding)."""
    return list(_get_model().query_embed([text]))[0].tolist()
