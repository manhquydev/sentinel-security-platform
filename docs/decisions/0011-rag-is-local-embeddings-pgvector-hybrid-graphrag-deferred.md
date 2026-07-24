# 0011 RAG uses local embeddings + pgvector hybrid; GraphRAG is deferred

Date: 2026-07-24

## Status

Accepted

## Context

Week 3 requires a "highly accurate, continuously updating RAG pipeline (Hybrid Search &
GraphRAG)" over CVE / OWASP / past-pentest content, so later agents get precise vulnerability
context. Two assumptions had to be checked against reality before committing a stack.

**Can the existing gateway embed?** No — verified live. The LiteLLM `embed` alias points at a
chat model (`gemini-flash`), and the gateway's provenance guardrail refuses `/v1/embeddings`
because it only understands a `messages` array (decision 0006's egress hygiene). So the RAG
plane cannot borrow the chat gateway for embeddings; it needs its own embedding path.

**Is GraphRAG needed now?** Research shows GraphRAG is a heavy LLM-indexing pipeline (entity/
relationship extraction, community detection) whose payoff needs multi-hop queries that do not
exist until the multi-agent syndicate (Week 6). Shipping it now would be speculative cost.

## Decision

**RAG is a self-hosted hybrid-retrieval pipeline: fastembed BGE-base-en-v1.5 (local, ONNX, no
torch) + pgvector on a dedicated Postgres, with dense + lexical fused by Reciprocal Rank Fusion.
GraphRAG and a cross-encoder re-ranker are deferred behind explicit triggers.**

- **Embedding** is local and in-process, pinned in `rag/requirements.txt`. Not the chat gateway.
  BGE-M3 is the upgrade path if multilingual/long-context need appears.
- **Store** is pgvector on a dedicated Postgres 16 (`infra/rag-store/`), loopback, digest-pinned.
  One store serves both retrieval halves (a `vector(768)` column and a generated `tsvector`).
  Qdrant is the runner-up, warranted only at tens of millions of vectors.
- **Hybrid = RRF** over dense (cosine) and lexical (Postgres FTS), because rank fusion needs no
  score calibration between incompatible scales.
- **Ingestion is idempotent** (`content_sha256` UNIQUE, `ON CONFLICT DO NOTHING`), the shippable
  form of "continuously updating".
- **Accuracy is measured** offline (Recall@k / MRR / nDCG) against a committed labelled set with
  a baseline regression guard — reproducible and cost-free, like `verify-lake`. LLM-judge
  (RAGAS) is deferred to keep the first number deterministic.

Proven live: 407 chunks across three sources; re-ingest adds 0; hybrid recall@10 = 1.0, never
below dense or lexical.

**Deferred, with triggers (so each deferral is a decision, not an omission):**
- **GraphRAG** — adopt when Recall@k plateaus *and* real multi-hop queries appear (Week 6).
- **Cross-encoder re-ranker** — adopt when a harder eval set shows a ranking gap hybrid misses.
- **Full continuous NVD mirror** and a **network retrieval service** — the bounded slice and
  in-process retrieval prove the design; the continuous feed and the agent-facing API are the
  next steps.

## Alternatives Considered

1. **Embed via the LiteLLM gateway.** Rejected: proven unusable (chat model + guardrail refusal),
   and coupling RAG to the egress plane is the wrong boundary.
2. **A purpose-built vector store (Qdrant/Weaviate) now.** Rejected for this scale: pgvector
   reuses the stack's proven Postgres pattern with native hybrid support and lower lock-in; the
   Qdrant trigger (scale) is recorded.
3. **GraphRAG in Week 3.** Rejected: speculative cost with no multi-hop query to justify it.

## Consequences

Positive:

- Offline, reproducible, GPU-free retrieval with a measured, regression-guarded accuracy number.
- No dependency on an external embedding provider or the chat gateway.
- The accuracy substrate later agents build on is honest about where hybrid does and does not
  yet beat a single retriever.

Tradeoffs:

- A dedicated Postgres to run and pin.
- Dense saturates the first (easy) eval set, so hybrid's lift is asserted for exact-token
  queries but not yet demonstrated; a harder eval set is owed.

## Follow-Up

- Grow the labelled eval set with exact-token/rare-token queries where lexical earns its weight,
  then re-baseline.
- When agents consume retrieved chunks (Week 4+), apply the provenance/guardrail boundary of
  decision 0006 to target-derived corpus text — retrieval is an indirect-injection surface.
