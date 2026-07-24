# 0012 The Recon agent is a thin, provenance-bound pipeline; LangGraph is deferred

Date: 2026-07-24

## Status

Accepted

## Context

Week 4 builds the "Recon & Analysis" agent: it reads the SAST/DAST lake and the threat-intel
RAG, reaches the target only through the Kong `agent-recon` identity, and emits a structured
Attack Surface Map. Research recommended LangGraph now (for a clean Week-6 multi-agent upgrade),
Pydantic-validated structured output, and provenance-labelled integration.

Two facts checked against the running system shaped the decision:

- **The gateway is fail-closed on the provenance contract.** A chat request without a
  `metadata.sentinel_provenance` declaration is refused ("cannot distinguish operator
  instructions from untrusted content") — verified live. So the agent's model access is not a
  plain OpenAI call; it must speak the frozen D↔E contract (guardrail-hook-contract.md, decision
  0006), labelling every message `operator` or `target-derived`.
- **The Week-4 pipeline is essentially linear.** Query lake → pre-aggregate → retrieve RAG per
  CWE → one bounded, provenance-labelled LLM call → validate the Attack Surface Map. There is no
  branching, looping, checkpointing, or human interrupt in Week 4. LangGraph's distinctive value
  (durable checkpoints, `interrupt()` for HITL, a supervisor graph) is a Week-5/6 need.

## Decision

**Week 4 ships a thin, provenance-bound pipeline over the existing LiteLLM gateway, not a
framework. LangGraph is deferred to Week 6, when the multi-agent supervisor and the HITL
interrupt actually arrive — the trigger, recorded so the deferral is a decision.**

Because the durable assets are framework-agnostic, deferring costs little rework:

- **The Attack Surface Map is a frozen Pydantic contract** (`agent/schema.py`), `extra="forbid"`,
  enums drawn from the *real* vocabularies (attack-surface `auth_class`/`state_change`, DefectDojo
  severities) so an out-of-vocabulary value signals a hallucination. Aggregate counts are
  **computed by code, not the model**, with a `consistency_errors()` self-check — a fabricated
  count is caught, not trusted. This contract is what Week-5 consumes; it does not depend on the
  orchestrator.
- **Model access is the provenance-aware client** (`agent/llm.py`): every message MUST carry a
  trust label, so the agent physically cannot send a lake finding, a RAG chunk, or a target
  response to the model without marking it `target-derived`. This is the concrete Week-4 form of
  the data-vs-instructions boundary; the gateway spotlights the marked spans.
- **Structured output is prompt-guided JSON + strict Pydantic validation** (fail-closed, with a
  bounded repair retry), NOT a hard dependency on a backend's structured-output mode — the router
  behind LiteLLM is not guaranteed to support `json_schema` response formats, and portability is
  worth more than one fewer validation step.
- **Context is retrieve-then-reason** with hard token budgets (retrieve top-k findings per
  endpoint and RAG context per CWE; never dump the whole lake), per the research.

Verified live already: the provenance-labelled call round-trips the gateway; the schema rejects a
hallucinated field, an out-of-vocabulary enum, and a fabricated aggregate; the client refuses an
unlabelled message. `tests/recon-agent-test.sh` = 6/0.

## Alternatives Considered

1. **LangGraph now (research's primary).** Deferred, not rejected: its value is Week-5/6
   (checkpointing, HITL `interrupt()`, supervisor). Adopting it for a linear pipeline is
   speculative dependency against this repo's YAGNI/low-lock-in ethos (cf. torch avoided in Week
   3). The tools + schema + provenance client are framework-agnostic, so the Week-6 adoption
   reuses them and replaces only a small orchestration loop.
2. **Backend structured-outputs (`json_schema` response_format).** Rejected as a hard dependency:
   the router's support is unverified; prompt-guided JSON + Pydantic validation is portable.
3. **PydanticAI.** Weaker multi-agent path and Logfire coupling; no advantage over a thin loop for
   a single linear agent.

## Consequences

Positive:

- The injection boundary is enforced in code (unlabelled message → refused), not merely intended.
- The Attack Surface Map's trustworthy parts (counts) are code-derived and self-checked.
- Minimal new dependencies; the Week-6 framework decision is made with a concrete supervisor need.

Tradeoffs:

- A thin loop must implement retry/observability that a framework would provide; kept small and
  tested. Langfuse tracing is wired at the gateway/client layer rather than via framework hooks.
- When LangGraph lands (Week 6), the orchestration loop is rewritten (small) around the same tools.

## Follow-Up

- Week 6: adopt LangGraph for the multi-agent supervisor + HITL `interrupt()`, reusing the schema,
  the provenance client, and the tools unchanged.
- Freeze the Attack Surface Map schema version as the Recon↔Exploit interface contract before the
  Week-5 exploit stream consumes it.
