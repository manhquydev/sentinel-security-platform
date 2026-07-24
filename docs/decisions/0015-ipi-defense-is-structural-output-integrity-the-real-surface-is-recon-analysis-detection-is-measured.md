# 0015 IPI defense is structural output-integrity; the real surface is recon-analysis; detection is measured defense-in-depth

Date: 2026-07-24

## Status

Accepted (Week-7 PR1 shipped — the guard + measurement; PR2 the LlamaFirewall sidecar detector and
PR3 the adaptive eval extend it)

## Context

Week 7 is "Advanced Guardrails & Indirect Prompt-Injection Defense" — the charter suggests a
guardrail framework (e.g. NeMo) to sanitize target data. A four-lens red-team of the first plan
(unanimous NOT CLEAN) established, with code evidence, three facts that reshaped the work:

- **There is no rogue-execution surface to defend.** The syndicate is already read-only (GET-only
  gateway), the exploit agent is import-contained (no target client) with an immutable HITL verdict,
  and there is no LLM-driven routing. A "capability gate" + a before/after ASR measured against a
  state-changing action would pass *vacuously* — the action can't happen. That gate is only
  meaningful as forward enforcement for Week-8's future execution surface.
- **The one genuine indirect-injection surface is recon-analysis.** An attacker-controlled scanner
  finding `title` flows verbatim into `recon._analyze`; a hijacked `analysis` (a fabricated or
  downplayed narrative) reaches the human analyst. Exploit `_narrate` input is code-derived; fuzz
  `_guide` runs after probes. So the real threat is **output/decision integrity**, not execution.
- **Detection cannot be the control.** Decision 0006 already recorded that classifier detection is
  bypassable (>90% ASR under adaptive attack) and that false positives on security content are
  "arguably more decisive." A guardrail framework is not the primary answer.

## Decision

**Week-7 IPI defense is a structural output-integrity guarantee, with detection as measured
defense-in-depth, targeted at the recon-analysis surface — not a classifier gate over a phantom
action surface.**

- **The structural control is that the map's FACTS are code-computed and authoritative.**
  `severity_counts`/`cwe_summary`/findings are derived by code from scanner output (decision 0012),
  never from the LLM — so a hijacked `analysis` narrative **cannot alter them**; it can only
  contradict them. `agent/guard.py::analysis_integrity_errors` cross-checks the narrative against
  those facts and `quarantine()` in-band-flags a contradicted analysis; the authoritative counts are
  always shown alongside. `spotlight_findings` datamarks the untrusted title so an embedded
  imperative reads as data. This holds even when every detector is bypassed.
- **Detectors are measured, never a silent gate (0006).** `detect_injection` (PR1, in-repo heuristic)
  and the LlamaFirewall sidecar (PR2) flag suspected injection for measurement + SOC visibility; they
  never drop/rewrite input on their own. The repo's differentiator is the **false-positive rate on
  real security content**, measured explicitly (`evaluation/ipi-guard/`).
- **The framework runs air-gapped as a sidecar (PR2).** NeMo is ruled out (hard conflict with the
  Week-6 `langchain-core`); LlamaFirewall runs as its own loopback service (own venv), AlignmentCheck
  pointed at the local LiteLLM gateway, PromptGuard pre-fetched offline — no external egress, no
  shared-venv conflict (avoids regressing Weeks 3 & 6). Gated on a user-accepted HF license.
- **The Trap is an isolated fixture, never the pinned lake** (the recon account cannot delete a
  DefectDojo finding and `verify-lake.sh` is read-only — planting in the production lake is
  irreversible). Measurement of a live hijack is stochastic and small-sample; the guard's catch is
  proven deterministically (a stubbed hijack), and a credible adaptive ASR is PR3's job.
- **No live state-changing action surface is built (0013 preserved).** The Week-8-ready capability
  gate is measured against a *simulated* action; a real execution surface + HITL gate remain Week 8.

Full record + red-team/validate history:
`docs/plans/active/2026-07-24-no-issue-week7-guardrails-ipi-defense.md`.
