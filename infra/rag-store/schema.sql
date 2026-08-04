-- Sentinel Threat-Intel RAG schema (Week 3). Applied once at first init.
--
-- Two tables: documents (one row per ingested source item) and chunks (retrievable units).
-- A chunk carries BOTH a dense embedding (pgvector) and a lexical tsvector, so the same store
-- serves hybrid retrieval (dense + BM25-style full-text) fused in the pipeline. Uniqueness is
-- per DOCUMENT (document_id, content_sha256): re-ingesting a document is idempotent (ON CONFLICT
-- DO NOTHING adds zero), while an identical chunk that legitimately recurs in two different
-- documents (shared OWASP boilerplate, a common "References" body) is kept under each. A global
-- hash-unique would silently drop the second and lose that document's provenance.

CREATE EXTENSION IF NOT EXISTS vector;   -- dense similarity
CREATE EXTENSION IF NOT EXISTS pg_trgm;  -- trigram assist for lexical matching

CREATE TABLE IF NOT EXISTS documents (
    id          BIGSERIAL PRIMARY KEY,
    -- Provenance: which charter source, and its stable identifier within that source.
    source      TEXT NOT NULL,          -- 'owasp' | 'nvd' | 'attack-surface' (defectdojo planned)
    source_ref  TEXT NOT NULL,          -- url / CVE id / finding id — stable per item
    title       TEXT,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source, source_ref)
);

CREATE TABLE IF NOT EXISTS chunks (
    id             BIGSERIAL PRIMARY KEY,
    document_id    BIGINT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    ord            INT NOT NULL,                 -- order within the document
    section        TEXT,                         -- heading/section path for provenance
    content        TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,                 -- per-document dedup key (see UNIQUE below)
    embedding      vector(768),                  -- BGE-base-en-v1.5 dimensionality
    -- Lexical vector, generated from content. 'english' config is fine for the corpus.
    tsv            tsvector GENERATED ALWAYS AS (to_tsvector('english', content)) STORED,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (document_id, content_sha256)
);

-- Dense ANN index (HNSW, cosine). Built now; empty is fine, it fills as rows arrive.
CREATE INDEX IF NOT EXISTS chunks_embedding_hnsw
    ON chunks USING hnsw (embedding vector_cosine_ops);

-- Lexical index for the full-text half of hybrid retrieval.
CREATE INDEX IF NOT EXISTS chunks_tsv_gin
    ON chunks USING gin (tsv);

CREATE INDEX IF NOT EXISTS chunks_document_id ON chunks (document_id);
