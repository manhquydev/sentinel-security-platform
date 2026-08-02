# Threat-Intelligence RAG pipeline (Week 3)

Self-hosted **hybrid retrieval** over a security corpus (CVE / OWASP / local pentest findings),
so later agents (Week-4 Recon onward) get precise web-application-vulnerability context. Backed
by pgvector; embeddings run locally with no external dependency and no GPU.

## Architecture

```
sources (OWASP md · NVD CVE · attack-surface)  →  chunk  →  embed (BGE-base, ONNX)  →  pgvector
                                                                                          │
query  →  embed(query)  ┐                                                                 │
query  →  Postgres FTS  ┘→  Reciprocal Rank Fusion  →  top-k  ←── dense + lexical ────────┘
```

- **Store**: pgvector on a dedicated Postgres 16 (`infra/rag-store/`), loopback-only,
  digest-pinned. `chunks` carries both a `vector(768)` embedding and a generated `tsvector`, so
  one store serves both halves of hybrid retrieval.
- **Embedding**: `fastembed` BGE-base-en-v1.5 (768-dim, ONNX, no torch), in-process. The
  existing LiteLLM gateway is **not** used — it points at a chat model and its provenance
  guardrail refuses `/v1/embeddings` (verified). See decision 0011.
- **Hybrid**: dense cosine + lexical FTS fused with Reciprocal Rank Fusion (RRF) — rank-based
  fusion needs no score calibration between cosine and `ts_rank`.
- **Idempotent + reconciling ingest**: uniqueness is per-document `(document_id, content_sha256)`
  and inserts are `ON CONFLICT DO NOTHING`, so re-ingesting unchanged content adds zero chunks; a
  changed document also has its stale chunks pruned. The shippable form of "continuously updating"
  (an identical chunk may legitimately recur across two documents and is kept under each).

## Offline Charter corpus contract

```bash
tests/run-charter-rag-contract.sh
```

This hermetic command runs the committed eight-case Charter corpus and retrieval
contract through `rag/.venv/bin/python`. It does not source an environment file,
start Docker, connect to pgvector, download a model, or run a live suite. It is
not a replacement for `tests/rag-retrieval-test.sh`, which remains the separate
live-store retrieval contract.

## Charter request and contract suite

Use the RAG virtualenv for the combined request/contract suite:

```bash
rag/.venv/bin/python -m pytest -q tests/test_charter_requests.py tests/test_charter_contracts.py
```

This command is an offline contract check; it does not establish a live RAG
store or a completed Sentinel run. If the system `python3` fails because
`psycopg` is unavailable, that is an unsupported interpreter environment, not
by itself a regression in the RAG corpus or retrieval code. Reproduce with the
command above before diagnosing an RAG regression.

## Setup

```bash
# 1. venv (isolated; requirements pinned)
python3 -m venv rag/.venv && rag/.venv/bin/pip install -r rag/requirements.txt

# 2. store (needs RAG_DB_USER / RAG_DB_PASSWORD in infra/.env — see infra/.env.example)
docker compose --env-file infra/.env -f infra/rag-store/docker-compose.yml up -d
```

## Use

```bash
set -a; . infra/.env; set +a

# Ingest (idempotent). First run downloads the BGE model once (~50s).
rag/.venv/bin/python -m rag.ingest --sources owasp nvd attack-surface

# Query (hybrid by default; --mode dense|lexical to compare)
rag/.venv/bin/python -m rag.retrieve "how do I prevent SQL injection" -k 5

# Measure retrieval accuracy vs the committed labelled set
rag/.venv/bin/python -m rag.evaluate                 # print Recall@k / MRR / nDCG
rag/.venv/bin/python -m rag.evaluate --check         # fail if hybrid regressed vs baseline
```

## Measured accuracy (committed baseline, `eval_baseline.json`)

Over 11 labelled queries at k=10:

| mode | recall@10 | MRR | nDCG@10 |
|---|---|---|---|
| dense | 1.00 | 0.93 | 0.95 |
| lexical | 0.18 | 0.14 | 0.15 |
| **hybrid** | **1.00** | **0.93** | **0.95** |

Hybrid is never worse than either retriever and does not degrade the strong dense signal.
Dense saturates this (deliberately clear) eval set, so hybrid's *lift* over dense is not
demonstrated here — lexical earns its place on exact-token queries (CVE ids, code tokens) that a
larger eval set will add. `evaluate.py --check` guards against regression below the baseline.

## Scope of this increment

**Shipped:** store, local embedding, multi-source idempotent ingest, hybrid retrieval, measured
accuracy with a regression guard, behavioural tests (`tests/rag-retrieval-test.sh`).

**Deferred (with triggers, see the plan and decision 0011):**
- **GraphRAG** — until Recall@k plateaus *and* real multi-hop queries appear (Week-6 syndicate).
- **Cross-encoder re-ranker** — a bounded add once a harder eval set shows a ranking gap.
- **Full continuous NVD mirror** — a bounded CVE slice proves the multi-source design; the
  continuous feed is the next step.
- **A network retrieval service** — Week 3 embeds/queries in-process; exposing retrieval as an
  API for agents is Week-4 wiring.

## Note for the agent phases

Retrieved chunks are third-party/target-derived text and therefore an indirect prompt-injection
surface once an agent consumes them (decision 0006). Every chunk keeps its provenance
(`source`, `source_ref`, `section`); the agent boundary that reads these must apply the same
provenance/guardrail posture the LLM-egress plane already defines.
