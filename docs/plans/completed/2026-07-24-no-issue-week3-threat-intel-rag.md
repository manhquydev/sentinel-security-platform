# Execution Plan: Week-3 Threat-Intelligence RAG pipeline

Date: 2026-07-24

## Status

Active

## Outcome

A self-hosted, reproducible **retrieval pipeline** that later agents (Week-4 Recon onward)
query for precise web-application-vulnerability context, with a **measured** retrieval-accuracy
number guarded against regression the way the lake's counts are.

Completion (first increment) is observable when:

- a corpus drawn from the three charter sources — CVE (NVD), OWASP guidance, and the local
  "past pentest" findings (DefectDojo + attack-surface) — is ingested into a pgvector store,
  each chunk carrying provenance (source, url/id, section) and a stable content hash;
- a **hybrid** query (dense embedding + lexical/BM25, fused with Reciprocal Rank Fusion)
  returns relevant chunks, demonstrably better than either retriever alone on the eval set;
- retrieval accuracy is **measured** on a committed labelled query set (Recall@k, MRR, nDCG)
  by an offline, deterministic eval script, with the baseline recorded and regression-guarded;
- ingestion is **incremental/idempotent** (re-running does not duplicate; content hash dedups),
  the "continuously updating" requirement in its shippable form; and
- a behavioural test proves the schema, the RRF fusion, and the dedup with negative controls.

## Non-goals (this increment)

- **GraphRAG** — deferred behind an explicit trigger (see decision). The charter names it; the
  research shows it is a large LLM-indexing lift whose payoff needs multi-hop queries that do
  not exist yet. Ship strong hybrid+rerank first.
- A network embedding/retrieval **service** — Week 3 embeds in-process (batch ingest + eval).
  Exposing retrieval as an API for agents is Week-4 wiring.
- Full continuous NVD mirror — a bounded CVE slice proves the multi-source design; the
  continuous full feed is a documented mechanism + trigger, not a Week-3 blocker.
- A cross-encoder **re-ranker** — a bounded add once hybrid+eval baseline exists; not the v0 gate.

## Context

- Predecessors complete/verified live: Week-1 lake + AI-security foundation; Week-2 Kong
  gateway + Agent IAM (branch `week2-api-gateway-agent-iam`).
- Research brief: `plans/reports/researcher-260724-0817-week3-threat-intel-rag-report.md`.
- **De-risked live this session (not assumed):**
  - The existing LiteLLM `embed` alias is **unusable** for RAG: it points at a chat model
    (`gemini-flash`) and the gateway's provenance guardrail refuses `/v1/embeddings` (it only
    understands `messages`). So RAG does **not** use the chat gateway for embeddings.
  - `fastembed` (ONNX, no torch) downloads **BGE-base-en-v1.5** (768-dim) and embeds correctly —
    a security query ranked its matching doc above an unrelated one (0.927 vs 0.647). Offline
    after a one-time model fetch.
  - `pgvector/pgvector:pg16` pulled and digest-pinned.

## Decisions (to promote to docs/decisions/ once proven)

- **Store = pgvector on a dedicated Postgres 16** (own compose, loopback, digest-pinned). Reuses
  the stack's proven Postgres operational pattern; hybrid search is native (vector + `tsvector`
  full-text); low lock-in. Qdrant is the runner-up, warranted only if scale reaches tens of
  millions of vectors (not now).
- **Embedding = self-hosted `fastembed` BGE-base-en-v1.5, in-process.** No torch, offline,
  reviewable in a pinned `requirements.txt`. Not the LiteLLM gateway (proven unusable). BGE-M3
  is the upgrade path if multilingual/long-context need appears.
- **Hybrid = dense (pgvector cosine) + lexical (Postgres FTS) fused with RRF.** Rank-based
  fusion sidesteps score-normalisation between cosine and BM25.
- **GraphRAG deferred** with trigger: adopt only when Recall@k plateaus *and* real multi-hop
  queries appear (Week-6 syndicate). Recorded so the deferral is a decision, not an omission.
- **Eval = offline deterministic Recall@k / MRR / nDCG over a committed labelled set**, baseline
  recorded and regression-guarded. LLM-judge (RAGAS) deferred — keep the first number
  reproducible and cost-free, like `verify-lake`.

## Approach (phases)

1. **Store.** `infra/rag-store/` — pgvector Postgres, loopback, digest-pinned, `vector` +
   `pg_trgm`/FTS extensions; a schema (`documents`, `chunks` with `embedding vector(768)`,
   `tsv tsvector`, `content_sha256`, provenance columns) applied idempotently.
2. **Core (`rag/`).** Python module: `embed` (fastembed), `db` (psycopg + pgvector), `chunk`
   (section-aware for markdown / structured records), `ingest` (idempotent, hash-dedup),
   `retrieve` (dense + FTS + RRF). Config via env; secrets from `infra/.env`.
3. **Corpus.** Normalise each source to a common record shape then ingest: OWASP guidance
   (markdown), a bounded NVD CVE slice (JSON 2.0), and local findings (DefectDojo export +
   attack-surface baseline). Provenance preserved; no secret-bearing raw stored.
4. **Eval.** A committed labelled query set (queries → expected source ids/sections) and an
   eval script reporting Recall@k / MRR / nDCG for dense-only, lexical-only, and hybrid — proving
   hybrid wins. Baseline recorded.
5. **Prove it.** `tests/rag-retrieval-test.sh` (or pytest): schema present, RRF fusion correct on
   a fixture, ingest idempotent (re-run adds 0), hybrid ≥ each single retriever on the eval set,
   each with a negative control.
6. **Review, audit, fix, document**; promote decisions; update READMEs.

## Risks And Recovery

- **Model/CVE fetch depends on network** (HF, NVD). One-time model fetch proven; NVD slice is
  bounded and cached to an ignored path. If a fetch fails, ingest that source is skipped and
  reported, not faked.
- **pgvector recall vs a purpose-built store** at scale — acceptable at this corpus size; the
  Qdrant trigger is recorded.
- **Additive**: new `infra/rag-store/`, `rag/`, tests, docs. Nothing in Week-1/2 paths changes,
  so their suites remain the regression net.

## Progress

- [x] Phase 1 — pgvector store up (pgvector 0.8.5, loopback, digest-pinned), schema applied.
- [x] Phase 2 — `rag/` core: embedding (fastembed BGE-base), store (psycopg + pgvector),
      chunking (section-aware, fence-safe), idempotent+reconciling ingest, RRF hybrid retrieve.
- [x] Phase 3 — corpus ingested: OWASP 8 docs, NVD 1 CVE, attack-surface 10 = **402 chunks**,
      provenance preserved, no secret-bearing raw stored.
- [x] Phase 4 — labelled eval set + committed baseline; hybrid ≥ dense and ≥ lexical.
- [x] Phase 5 — `tests/rag-retrieval-test.sh` (6/0) incl. reconcile-prune + empty-parse controls.
- [x] Phase 6 — code review applied, decisions 0011 promoted, READMEs updated.

## Result

**Complete (first increment), verified live from a clean reseed.** Corpus = 402 chunks across
three charter sources; `tests/rag-retrieval-test.sh` = **6 passed / 0 failed**; re-ingest of an
unchanged source inserts 0 and prunes 0 (idempotent); Week-1/2 suites unregressed (gateway 29/0,
lake 12/0, redaction 43/0).

Measured retrieval accuracy (11 labelled queries, k=10), committed to `rag/eval_baseline.json`
and guarded by `evaluate.py --check`:

| mode | recall@10 | MRR | nDCG@10 |
|---|---|---|---|
| dense | 1.00 | 0.93 | 0.95 |
| lexical | 0.18 | 0.14 | 0.15 |
| hybrid | 1.00 | 0.93 | 0.95 |

Honest limitation: dense saturates this deliberately-clear eval set, so hybrid is proven *not
worse* than either retriever but its *lift* is not yet demonstrated — a harder eval set with
exact-token queries (where lexical earns its weight) is owed (decision 0011 follow-up).

### Review findings applied (provenance)

Code review (no Critical; posture sound — parameterized SQL, loopback, digest-pinned, secrets
clean) surfaced and fixed:

- **H1 — global chunk-hash uniqueness dropped cross-document duplicate chunks.** Changed to a
  composite `UNIQUE (document_id, content_sha256)`, so an identical chunk that legitimately
  recurs in two documents is kept under each with its own provenance.
- **H2 — re-ingest of changed upstream left orphan chunks.** Added a per-document reconcile that
  prunes chunks no longer present (and refuses to wipe a document on an empty parse), plus a
  `--refresh` cache-bypass — the "continuously updating" guarantee now survives changed content.
- **M2 — the chunker mis-read a `#` line inside a code fence as a heading.** Fence-aware now.
- Nits: composite conflict target, `ord` rename, correct multi-expected nDCG, traversal-safe
  cache slug, `with`-managed file handles.
- **M1 (indirect prompt injection)** and **M3 (weak eval)** recorded as explicit
  constraints/debt for Week 4 in `rag/README.md` and decision 0011, not silently closed.

Full review: `plans/reports/code-review-260724-0821-week3-rag.md`. Research that grounded the
stack: `plans/reports/researcher-260724-0817-week3-threat-intel-rag-report.md`.

Move to `docs/plans/completed/` once the harder eval set lands or the current accuracy scope is
formally accepted for the cycle.

## Open questions

- Which OWASP corpora to prioritise (Cheat Sheets vs WSTG vs ASVS) for the first eval — decided
  during ingest by which chunks the labelled queries actually need.
