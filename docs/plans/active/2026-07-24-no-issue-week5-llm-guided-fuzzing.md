# Execution Plan: Week-5 LLM-guided fuzzing engine

Date: 2026-07-24

## Status

Active

## Outcome

A safe, bounded fuzzing engine that drives malformed requests through the gateway (as
`agent-recon`), generates payloads from a committed corpus ranked/mutated by the LLM, detects
interesting responses (5xx, stack traces, reflected input, drift) by code, and reports them —
without ever changing target state.

Completion (first increment) is observable when:

- the engine fuzzes the public read endpoints of the Attack Surface Map (query params) via Kong,
  and every request is one `agent-recon` is authorized for (no state change; the ACL enforces it);
- interesting responses are flagged **deterministically** against a per-target benign baseline;
- one provenance-labelled LLM call ranks/mutates from a batch of flagged responses (all
  `target-derived`), and the run is bounded (per-target budget, kill-switch, dedup);
- a report of findings (endpoint, payload class, signal) is produced, and raw payloads/responses
  stay out of git;
- a behavioural test proves the detectors (on synthetic responses), the safety bounds, and a live
  bounded run, each with a negative control.

## Non-goals (this increment)

- No state-changing / exploit payloads sent (defined but reserved for Week-8 HITL — decision 0013).
- No broadening of `agent-recon`'s scope; fuzzing inherits its read-only ACL.
- No LangGraph / multi-agent (Week 6).
- No mutation of the target DB or filesystem.

## Context

- Predecessors merged: Week-2 gateway + `agent-recon`; Week-3 RAG; Week-4 Recon `AttackSurfaceMap`
  + `agent/gateway.py` (send via Kong) + `agent/llm.py` (provenance client).
- Research: `plans/reports/researcher-260724-1046-week5-llm-guided-fuzzing.md`.
- Decision 0013 (hybrid, read-only, deterministic signals, LLM-in-the-loop).

## Approach (phases)

1. **Payload corpus** (`agent/fuzz_payloads.py`): a committed, reviewable set of read-safe query
   payloads by class (boundary, injection markers, encoding, oversize, type-confusion). Read-safe:
   values placed in GET query params only; nothing state-changing.
2. **Signal detector** (`agent/fuzz_signals.py`): deterministic, code-owned — 5xx, stack-trace/
   error-signature regexes, reflected input, latency/size/content-type drift vs a benign baseline.
3. **Engine** (`agent/fuzz.py`): select public read endpoints+params from the map → baseline →
   run payloads via `agent/gateway.py` → detect → batch flagged responses → one provenance-labelled
   LLM call to rank/mutate → bounded next round. Budget, dedup, kill-switch. Emit a findings report.
4. **Prove it** live against Juice Shop (bounded), and an offline metric (unique signals, endpoints
   covered) that is regression-guardable.
5. **Review, audit (STRIDE on the new active-probing surface), fix, docs.**

## Risks And Recovery

- **Active probing of a vulnerable target.** Contained: loopback-only, `agent-recon` read-only
  scope (ACL 403s the rest), per-target request budget + kill-switch, no state-change payloads.
- **Token cost.** One batched LLM call per round, hard token/iteration budget; hybrid corpus does
  the bulk, LLM only ranks/mutates.
- **Additive**: new `agent/fuzz_*.py`, a test, docs. Nothing in Weeks 1–4 changes.

## Progress

- [x] Phase 1 — payload corpus (`agent/fuzz_payloads.py`, read-safe, multi-class).
- [x] Phase 2 — deterministic signal detector (`agent/fuzz_signals.py`).
- [x] Phase 3 — bounded engine (`agent/fuzz.py`) with LLM-in-the-loop guidance + report.
- [x] Phase 4 — live bounded run; offline metric asserted in the suite.
- [~] Phase 5 — review/fix (this PR); decision 0013 recorded.

## Result

**Complete (first increment), verified live.** `tests/fuzz-engine-test.sh` = **4/0**; no
regression (recon-agent 10/0, gateway 29/0).

A bounded, read-only run through Kong as `agent-recon` sent **19 requests** to the one public
read-only fuzz target (`GET /rest/products/search?q=`) and produced **11 distinct findings**,
detected deterministically: the SQLi payload `')--` and a raw null byte each tripped **HTTP 500 +
a stack-trace signature + a JSON→HTML content-type drift** — Juice Shop's real search SQL injection
surfaced by code, not asserted by the model. One provenance-labelled LLM call then read the flagged
batch (target-derived) and correctly called it "suspected, not confirmed" with parameterized-query
fixes — leads for a human, not a fabricated confirmation.

Safety held by construction: only public read-only GET targets are selected, the corpus carries no
state-changing verb/command (asserted), the ACL 403s anything else, and the run is bounded by a
per-target budget + kill-switch. Raw payloads/responses stay in a gitignored path.

### Security review applied (provenance)

A STRIDE-focused review (`plans/reports/security-review-260724-1101-week5-fuzzer.md`) found the
**safety posture sound — no reachable state-change** (four stacked controls: read-only-GET target
selection, GET-only transport, full value URL-encoding, no state-changing verb in the corpus, ACL
backstop). Applied: the same URL-encoding that makes it safe was neutering the param-*structure*
classes (type-confusion, nosql, encoded-traversal, `%00`), so those dead probes were removed — an
honest corpus (structural/param-name fuzzing is a follow-up). Added a loopback assertion (refuse
TLS-unverified requests to a non-loopback host), a global request budget, and reconciled the
decision's budget wording.

Follow-ups (owed, not blocking): the reserved state-changing payloads run only behind the Week-8
HITL gate; structural/param-name fuzzing; more fuzzable params as the attack-surface map grows; a
persisted signal baseline for cross-run regression.

## Open questions

- Which endpoints beyond `/rest/products/search?q=` expose fuzzable read params (driven by the map).
- Whether to persist a signal baseline for cross-run regression (freeze for Week 5).
