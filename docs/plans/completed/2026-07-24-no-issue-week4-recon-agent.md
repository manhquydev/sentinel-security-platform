# Execution Plan: Week-4 Recon & Analysis agent

Date: 2026-07-24

## Status

Complete

## Outcome

A read-only Recon agent that fuses the SAST/DAST lake, the threat-intel RAG, and the target
(reached only through the Kong `agent-recon` identity) into a schema-validated **Attack Surface
Map** — with attacker-influenced content kept as labelled data, and the map's counts computed by
code, not the model.

Completion (first increment) is observable when:

- the agent produces an `AttackSurfaceMap` that validates against the frozen schema and passes its
  code-computed consistency check;
- lake findings and RAG context enter the model **only** as `target-derived` (provenance-labelled)
  content; the agent's instructions are the only `operator` content;
- the target is reached only via the gateway with the `agent-recon` OAuth2 identity (admin/state-
  changing routes remain 403); no exploitation, no state change;
- a behavioural test proves the schema strictness, the provenance boundary, and a real end-to-end
  map generation, each with a negative control;
- retrieval is bounded (top-k per endpoint / per CWE), never a whole-lake dump.

## Non-goals (this increment)

- No exploitation / fuzzing / state-changing actions (Week 5+, behind HITL).
- No LangGraph / multi-agent supervisor (Week 6 — decision 0012 trigger).
- No backend structured-output dependency (prompt-guided JSON + strict Pydantic validation).
- WebGoat map (SAST-only, no runtime) — Juice Shop first (it has DAST + a live target).

## Context

- Predecessors complete/verified: Week-1 lake + guardrail gateway; Week-2 Kong Agent IAM (the
  `agent-recon` consumer already exists, scoped read-public); Week-3 RAG (`rag.retrieve`).
- Research: `plans/reports/researcher-260724-0852-week4-recon-agent.md`.
- Decision 0012 (thin provenance-bound pipeline; LangGraph deferred). Provenance contract:
  `docs/product/guardrail-hook-contract.md` (decision 0006).
- **De-risked live this session:** the gateway refuses an unlabelled chat request (provenance
  fail-closed); a provenance-labelled call round-trips; `sast-*` model aliases work for chat.

## Approach (phases)

1. **Contract + boundary (DONE).** `agent/schema.py` (frozen `AttackSurfaceMap`, strict enums from
   real vocabularies, code-computed aggregates + consistency check); `agent/llm.py`
   (provenance-aware client — every message must be labelled `operator`/`target-derived`).
2. **Tools (read-only, framework-agnostic, testable without the LLM).**
   - `agent/lake.py` — query DefectDojo findings via a read-only API token (top-k per endpoint).
   - `agent/gateway.py` — reach the target via the `agent-recon` OAuth2 identity (mint token,
     GET public routes; admin/state-changing stay 403). Reuses the Week-2 mechanism.
   - RAG context via `rag.retrieve.hybrid_search` (exists).
3. **Pipeline (`agent/recon.py`).** Load attack-surface endpoints + lake findings (pre-aggregate
   by endpoint/CWE) → retrieve RAG per top CWE → build ONE bounded, provenance-labelled prompt →
   LLM → parse JSON → Pydantic-validate → `recompute_aggregates` + `consistency_errors` → write the
   map. Fail closed on validation.
4. **Prove it.** A real end-to-end run against the live lake yields a valid map; a regression guard
   (endpoint coverage, allowed CWE set) records a baseline.
5. **Review, audit, fix, document; promote decision; update READMEs.**

## Risks And Recovery

- **Token/cost blow-up** — hard budgets + retrieve-then-reason; fail (not silently truncate) if the
  prompt exceeds budget. A cheap model alias for the run.
- **Mislabelled provenance** — the client makes labelling mandatory; honest labelling is the
  caller's responsibility, enforced by construction (untrusted text cannot be sent unlabelled).
- **DefectDojo API at scale** — bounded top-k queries; fall back to a direct read-only SQL query if
  the API filter is slow (recorded, not built now).
- **Additive**: new `agent/`, tests, docs. Week-1/2/3 paths unchanged (their suites are the net).

## Progress

- [x] Phase 1 — schema contract + provenance-aware LLM client.
- [x] Phase 2 — read-only lake reader (`agent/lake.py`) + gateway probe (`agent/gateway.py`);
      `tests/recon-tools-test.sh` 3/0 (merged, PR #5).
- [x] Phase 3 — recon pipeline (`agent/recon.py`): deterministic map + RAG + one LLM analysis.
- [x] Phase 4 — live end-to-end run; deterministic regression asserted in the suite.
- [x] Phase 5 — CodeRabbit review applied (PR #6); decision 0012 recorded.

## Result

**Complete (first increment), verified live.** `tests/recon-agent-test.sh` = **10/0**
(schema 5, provenance boundary 2, pipeline 3); `tests/recon-tools-test.sh` = **3/0**.

The pipeline fuses the lake, the Week-1 attack-surface baseline, and the RAG into a validated
Attack Surface Map: **10 endpoints** (from the baseline) + **36 findings** (21 Nuclei + 4 Trivy +
11 Semgrep), severity and CWE aggregates **computed by code** and self-checked, 3 RAG references,
and a prioritized LLM analysis produced over provenance-labelled (`target-derived`) input — which
correctly flagged the private-key exposure, the public `/metrics`, the weak-crypto SAST hits, and
that Juice Shop is intentionally vulnerable.

### Grounding that shaped the build (verified live, not assumed)

- **DefectDojo's `test__test_type__name` filter is ignored** (returns every scanner's findings);
  the reader filters by the numeric `test__test_type=<id>` — the same failure class as the lake's
  locator-scheme guard.
- **DefectDojo dedups endpoints**, so Nuclei per-finding endpoint references point at merged-away
  ids (404). Per-finding DAST→endpoint attribution is therefore unreliable, so findings land
  honestly in `app_level_findings` rather than being fabricated onto an endpoint — the "sparse,
  locator-match-only" fusion you chose, applied to what the data actually supports.
- The LLM path is **provenance-fail-closed**: the gateway refuses an unlabelled chat request, so
  the agent's client labels every finding/RAG span `target-derived`.

Follow-ups (owed, not blocking): a harder finding→endpoint link if DefectDojo endpoint integrity
is repaired; a persisted map baseline for cross-run regression; the Week-6 LangGraph adoption
(decision 0012).

## Open questions

- Baseline mutability for regression (freeze vs per-run) — freeze for Week 4, revisit Week 6.
- RAG relevance filtering (score threshold) — include all top-k for Week 4; filter if traces show
  low-relevance chunks.
