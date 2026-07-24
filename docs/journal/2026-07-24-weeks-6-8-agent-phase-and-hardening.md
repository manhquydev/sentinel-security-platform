# 2026-07-24 — Weeks 6–8: the AI-attack phase and its hardening (shipped to main)

Built and merged Weeks 6–8 in one long session, each through the full gated pipeline
(scout → research → advise → red-team → validate → implement → code-review → STRIDE audit → fix),
then shipped to `main` via PR #10 (merge `495a853`, post-merge `security-scan` green).

## What shipped

- **Week 6 — multi-agent syndicate** (`40066e4`, `864a9df`; decision 0014): a hand-rolled LangGraph
  supervisor over Recon → map-guided Fuzz → Exploit(sim), redacted checkpoint, tested `interrupt()`
  seam, loopback Phoenix. Model access stays at the gateway (contract-tested).
- **Week 7 — IPI defense** (`52fab70`, `56cba74`; decision 0015): structural output-integrity at the
  one real surface (a scanner `title` → recon `_analyze`), plus a reproducible self-hosted
  adaptive-attacker eval and the FP-on-security-content differentiator.
- **Week 8 — HITL gate** (`b879a9b`; decision 0016): a fail-closed approval gate over a *simulated*
  action, with out-of-process Ed25519 approval the agent can't self-mint. Real execution deferred.

## Lessons worth keeping

- **The red-team repeatedly caught fundamentally-flawed scope *before code*, three weeks running.**
  Week 6: the observability plane didn't compose with our raw-`requests` client + duplicated Langfuse.
  Week 7: "build a guardrail classifier" — but there was no rogue-execution surface to gate, so the
  real work was output-integrity + measurement. Week 8: "approve and execute the real payload" rested
  on five broken axes (no runnable payload exists — it's scrubbed by design; approvable GET endpoints
  are disjoint from the only write route; the loopback approval was self-forgeable; Kong OSS has no
  OPA plugin; reversibility was illusory). Each time the honest answer was a re-scope, not a patch.
  **When the maximal option depends on a capability the code doesn't have, the plan gate is where you
  find out — cheaply.**
- **Verify, don't trust — every layer.** Stale library versions in a research report (`langgraph
  0.0.37` vs real `1.2.9`; NeMo/OPA "just works" air-gapped — both false on this stack) were caught by
  resolver/doc checks. A "green" build hid a real target-raw checkpoint leak behind a vacuous test.
  Subagent "all green" claims were re-run independently; one implementer stalled mid-run and its
  unverified partial work was recovered by running the tests it never reached and isolating the one
  real defect from two test artifacts.
- **Structure over detection is the durable control** (decision 0006's thesis, re-proven): the code
  can't-be-altered facts (Week 7) and the agent-can't-sign split (Week 8) hold even when a detector is
  bypassed; detectors are *measured*, never trusted as the gate.
- **A LangGraph gotcha worth remembering:** `Command(resume={})` is a vacuously-satisfied empty
  resume-map — the node is skipped, so a "no token" refusal must be enforced by a wrapper that detects
  "still interrupted after resume," not by the node alone.

## Deferred (named, not forgotten)

- Week-7 LlamaFirewall air-gapped sidecar (needs an HF-license acceptance + sidecar infra).
- Week-8 real state-changing execution (needs explicit decisions per 0016: a payload artifact
  reversing E3/0013, write topology + app-session, recreate-based reversibility, OPA-or-fallback).
- Week 9+ (PII redaction; eval pipeline; vLLM/FinOps; PRD) — fresh units.
