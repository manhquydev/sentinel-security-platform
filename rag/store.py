"""pgvector-backed store for the Sentinel Threat-Intel RAG pipeline.

Owns the connection, idempotent inserts, and the two halves of hybrid retrieval (dense vector
similarity and lexical full-text). Fusion of the two lives in retrieve.py; this module only
returns each ranked list so the fusion is testable in isolation.

Connection parameters come from infra/.env (RAG_DB_USER / RAG_DB_PASSWORD) and the loopback
port the rag-store compose publishes. No DSN string carries the password.
"""
from __future__ import annotations

import hashlib
import os
from contextlib import contextmanager
from dataclasses import dataclass

import psycopg
from pgvector import Vector
from pgvector.psycopg import register_vector


def _env(name: str, default: str | None = None) -> str:
    val = os.environ.get(name, default)
    if val is None:
        raise RuntimeError(f"{name} is not set (source infra/.env)")
    return val


@contextmanager
def connect():
    """Yield a connection with the vector type registered. Reads discrete env vars."""
    conn = psycopg.connect(
        host=os.environ.get("RAG_DB_HOST", "127.0.0.1"),
        port=int(os.environ.get("RAG_DB_PORT", "55434")),
        dbname=os.environ.get("RAG_DB_NAME", "rag"),
        user=_env("RAG_DB_USER"),
        password=_env("RAG_DB_PASSWORD"),
    )
    try:
        register_vector(conn)
        yield conn
    finally:
        conn.close()


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def upsert_document(conn, source: str, source_ref: str, title: str | None) -> int:
    """Return the document id for (source, source_ref), creating it if absent. Idempotent."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO documents (source, source_ref, title)
            VALUES (%s, %s, %s)
            ON CONFLICT (source, source_ref) DO UPDATE SET title = EXCLUDED.title
            RETURNING id
            """,
            (source, source_ref, title),
        )
        return cur.fetchone()[0]


def insert_chunk(conn, document_id: int, ordinal: int, section: str | None,
                 content: str, embedding) -> bool:
    """Insert one chunk. Returns True if newly inserted, False if this document already holds an
    identical chunk (idempotent dedup on (document_id, content_sha256))."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO chunks (document_id, ord, section, content, content_sha256, embedding)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (document_id, content_sha256) DO NOTHING
            RETURNING id
            """,
            (document_id, ordinal, section, content, sha256(content), Vector(embedding)),
        )
        return cur.fetchone() is not None


def delete_stale_chunks(conn, document_id: int, keep_hashes: list[str]) -> int:
    """Delete chunks of a document whose content hash is not in the current set — the prune half
    of a reconcile, so a re-ingest of changed upstream content does not leave orphans behind.
    Returns the number deleted. With keep_hashes empty, deletes none (a failed/empty parse must
    not wipe a document's chunks)."""
    if not keep_hashes:
        return 0
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM chunks WHERE document_id = %s AND content_sha256 <> ALL(%s)",
            (document_id, keep_hashes),
        )
        return cur.rowcount


@dataclass
class Hit:
    chunk_id: int
    document_id: int
    source: str
    source_ref: str
    section: str | None
    content: str
    score: float


def _rows_to_hits(rows) -> list[Hit]:
    return [Hit(*r) for r in rows]


def dense_search(conn, query_embedding, k: int) -> list[Hit]:
    """Top-k by cosine similarity (1 - cosine distance)."""
    qv = Vector(query_embedding)
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT c.id, c.document_id, d.source, d.source_ref, c.section, c.content,
                   1 - (c.embedding <=> %s) AS score
            FROM chunks c JOIN documents d ON d.id = c.document_id
            WHERE c.embedding IS NOT NULL
            ORDER BY c.embedding <=> %s
            LIMIT %s
            """,
            (qv, qv, k),
        )
        return _rows_to_hits(cur.fetchall())


def lexical_search(conn, query_text: str, k: int) -> list[Hit]:
    """Top-k by full-text rank using websearch query semantics."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT c.id, c.document_id, d.source, d.source_ref, c.section, c.content,
                   ts_rank_cd(c.tsv, q) AS score
            FROM chunks c
            JOIN documents d ON d.id = c.document_id,
                 websearch_to_tsquery('english', %s) q
            WHERE c.tsv @@ q
            ORDER BY score DESC
            LIMIT %s
            """,
            (query_text, k),
        )
        return _rows_to_hits(cur.fetchall())


def count_chunks(conn) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM chunks")
        return cur.fetchone()[0]
