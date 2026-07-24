# 0014 The Week-6 syndicate is a LangGraph supervisor over the existing agents; observability is a redaction-gated loopback Phoenix plane

Date: 2026-07-24

## Status

Accepted (PR1 of 2 — supervisor + observability; the Exploit(sim) agent is PR2)

## Context

Week 6 is the "Multi-Agent Pentest Syndicate": a Supervisor coordinating Recon, Fuzz, and Exploit,
with observability tracing the agent-to-agent flow. Decision 0012 named Week 6 as the LangGraph
trigger. Four facts checked against the running system shaped how it is built (a red-team of the
first plan draft — 2 Critical, 8 High — forced most of these):

- **The provenance contract is enforced SERVER-SIDE at the LiteLLM gateway**
  (`sentinel_guardrail.py`), not by the client. So the durable invariant is not "use the right
  client object" but "no `agent/` code reaches a model except through the gateway." LangGraph
  orchestrates control flow; it must not become a second, unlabelled model door.
- **The flow is linear** (Recon → Fuzz → Exploit). LangGraph earns its keep only for the durable
  checkpoint + `interrupt()` HITL that Week 8 needs — inert in Week 6, so they must be *tested* now,
  not merely present, or they rot before Week 8.
- **A durable checkpoint and a trace plane are new places target-derived text can leak to disk.**
  The existing egress redactor (`egress_redaction.py`) deliberately *preserves* attack/target
  payloads so findings stay legible — so it is the wrong tool here; the syndicate needs the opposite
  guarantee (strip target-raw + secrets) as a distinct control.
- **Langfuse already traces + redacts every LLM call.** A second plane is justified only for what
  Langfuse does not give: the graph/agent-to-agent flow. And auto-instrumentation sees nothing,
  because the agent's model door is a raw `requests` call, not a LangChain client.

## Decision

**The syndicate is a hand-rolled LangGraph `StateGraph` over the existing Recon and Fuzz pipelines,
model access stays at the gateway via `agent/llm.py`, and agent-flow observability is a self-hosted,
loopback-bound Phoenix plane fed by manual OTel spans behind a redaction gate.**

- **Framework:** hand-rolled `StateGraph` (not `create_supervisor()`) — explicit linear flow, less
  magic to audit. Durable `SqliteSaver` checkpoint; an `interrupt()` seam gated on a
  `pending_state_change` flag (inert in Week 6, exercised by a test) reserved for the Week-8 HITL
  exploit branch. Model config is threaded through state, not ambient env.
- **Model door:** nodes call the existing provenance-labelled `agent/llm.py`; no LangChain chat
  model is adopted. A model-egress contract test (`tests/agent-model-egress-contract-test.sh`) fails
  if any `agent/` module imports a direct LLM SDK, references a router base, or enables
  LangChain/LangSmith telemetry (`langsmith` is a transitive dep and must stay air-gapped-off).
- **Disk/trace redaction is a hard gate, distinct from egress redaction:** everything the checkpoint
  persists and every span attribute runs through a secret-AND-target-raw scrub
  (`trace.redact_persisted`); raw fuzz payloads/response text never reach disk (only signal *kinds*
  and counts do). Tests assert no secret and no target-raw pattern reaches the checkpoint DB or a
  span, each with a non-vacuous negative control.
- **Observability tool:** Arize Phoenix, self-hosted as a loopback-bound, digest-pinned container
  (not LangSmith — its self-host is enterprise-only and cannot be air-gapped). Phoenix traces the
  graph flow via manual OTel spans; per-LLM-call bodies stay on the existing Langfuse plane. Tracing
  fails open (a down Phoenix never blocks a pentest); the redaction guarantee holds regardless.
- **Recon→Fuzz is a real producer→consumer link:** Fuzz consumes the Recon map to scope targets to
  the map's endpoints (params resolved from the cited baseline) and to prioritize injection-class
  payloads by the map's CWEs. At the current per-target budget this changes send *order*, not
  coverage — stated honestly rather than overclaimed.

Full record, invariants (I1–I8), and the red-team/audit history:
`docs/plans/active/2026-07-24-no-issue-week6-multi-agent-syndicate.md`. Deferred to their charter
weeks: the Exploit(sim) agent (PR2), the Week-8 HITL `interrupt()` consumer, Week-9 PII redaction,
and full `--require-hashes` integrity pinning of the Python lock.
