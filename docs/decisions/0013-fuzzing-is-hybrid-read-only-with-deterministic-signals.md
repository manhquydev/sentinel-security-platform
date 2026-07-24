# 0013 Fuzzing is hybrid, read-only, with deterministic signal detection

Date: 2026-07-24

## Status

Accepted

## Context

Week 5 builds an LLM-guided fuzzing engine: send malformed requests through the gateway, generate
payloads from the Week-4 Attack Surface Map, analyze responses (5xx, stack traces), and mutate to
dig deeper. Three choices decide whether this is durable and safe or a token-burning liability.
Research (`plans/reports/researcher-260724-1046-week5-llm-guided-fuzzing.md`) and the existing
system constrain the answer.

## Decision

**The engine is HYBRID (a deterministic payload library ranked/mutated by the LLM), signal
detection is deterministic and code-owned, the loop is an LLM-in-the-loop over a deterministic
executor, and Week-5 fuzzing stays inside `agent-recon`'s read-only scope.**

- **Hybrid generation, not pure-LLM.** A committed, reviewable payload corpus (boundary values,
  injection markers, encoding/oversize/type-confusion) is the source of truth; the LLM ranks which
  payloads to try next and proposes mutations from observed responses. Pure per-iteration LLM
  generation is costly, non-reproducible, and un-regression-guardable; the hybrid is 60–80% cheaper
  and testable (Fuzz4All ICSE'24, ChatAFL, USENIX'25 hybrid fuzzing).
- **Deterministic signal detection.** "Interesting" is decided by code — 5xx status, stack-trace/
  error-signature regexes, reflected-input, latency/size/content-type drift versus a per-target
  benign baseline — never by an LLM judgment call. The LLM interprets a *batch* of already-flagged
  signals and picks the next payloads. This keeps the finding trustworthy and the metric offline.
- **LLM-in-the-loop over a deterministic executor.** The gateway is chat-only and provenance-gated,
  so there is no native tool-calling: code sends the request, code detects the signal, and the LLM
  is asked (with every response labelled `target-derived`) for the next move. No MCP tool-server;
  LangGraph stays deferred to Week 6 (decision 0012).
- **Read-only scope, state-changing deferred to Week-8 HITL.** The engine sends only requests
  `agent-recon` is already authorized for (public reads; the ACL returns 403 for the rest), so
  fuzzing cannot mutate target state. State-changing/exploit payloads are defined but **not sent**
  until Week-8 adds human approval. Bounds: a per-target request budget, a token budget, dedup, and
  a kill-switch that pauses a target after repeated transport failures.

## Alternatives Considered

1. **Pure-LLM payload generation each iteration.** Rejected: cost, non-reproducibility, no
   regression guard. The LLM's value is ranking/mutation, not generating a boundary-value corpus.
2. **LLM decides interesting-ness.** Rejected: makes findings a model opinion; a 5xx is a fact.
3. **Send state-changing payloads now (behind a flag).** Rejected: Week 8 owns the human-approval
   gate for state change; doing it earlier removes the boundary that makes the ACL meaningful.

## Consequences

Positive:

- Reproducible, cheap, testable fuzzing; findings are code-detected facts, not LLM claims.
- Safe by construction: the engine inherits `agent-recon`'s read-only ACL; it cannot change state.

Tradeoffs:

- Read-only fuzzing cannot exercise state-changing bugs this cycle (by design; Week 8).
- The payload corpus needs curation; the LLM compensates by prioritizing and mutating.

## Follow-Up

- Week 8: send the reserved state-changing payloads only through the HITL approval gate.
- Raw malformed payloads and target responses are target-derived and stay out of git (gitignored
  output), consistent with the redaction posture.
