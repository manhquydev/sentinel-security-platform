# 0020 The inherited LLM-SAST-triage verifier is measured unsafe (both models refuse under correct provenance; drop real vulns when forced); the deterministic ethos holds. Default model → grok-4.5

Date: 2026-07-25

## Status

Accepted. The AI-SAST inherit-and-upgrade Phase-1 viability spike ran and **disproved** the naive
LLM-triage thesis on real FP-traps — a documented negative result, so **no verifier module ships** (the
plan's measure-first, fail-allowed design). The project's default agent LLM moved from `cx/gpt-5.6-sol`
to `grok-4.5`.

## Context

The inherit-and-upgrade plan (`docs/plans/active/2026-07-25-ai-sast-inherit-and-upgrade.md`) proposed a
clean-room guided-question verifier (inherit VulnHunterX's *method*, not its code) to reduce SAST false
positives, run through Sentinel's provenance gateway with a structural verdict-integrity gate, and
**measured** on a real FP-trap corpus. Built + tested offline (`agent/verifier/` + the fail-safe
integrity gate + `evaluation/sast-fp-discrimination/scorer.py`, `tests/ai-sast-verifier-test.sh` 5/0),
then run live: RealVuln (Apache-2.0, verified) bounded subset → **Bandit** (the high-FP Python engine) →
matched to ground truth (file+CWE+line±10) → verifier → scorer. 21 findings (8 real vulns, 13 FPs).

## Decision (the measured finding — two models × two provenance conditions)

| condition | `sast-sol` (cx/*) | `grok-4.5` |
|---|---|---|
| **target-derived** (security-correct) | refuse 15/15 → FP-reduction **0**, recall safe | refuse 15/15 → FP-reduction **0**, recall safe |
| **operator** (FORBIDDEN trust downgrade) | FP-red 0.62, precision **↓** 0.38→0.29, **drops 3/8 real vulns** | FP-red 0.62, precision ↑ 0.38→0.50, **still drops 3/8 real vulns** |

- **Under the security-correct provenance, BOTH model families refuse the grading role** (they return
  remediation/other, never a TP/FP verdict) — the provenance datamark blocks LLM triage of
  target-derived code **model-independently**. This independently reproduces the Week-10 judge finding
  (decision 0018) on the SAST surface.
- **Under the forbidden `operator` downgrade, both models grade but breach the hard recall floor** —
  they silently mark REAL vulnerabilities (SQLi, command-injection, hardcoded-credential) as false
  positives. grok-4.5 is a *better* grader (precision improves rather than collapses), but it is still
  **unsafe**: an LLM verifier that hides real vulns cannot hold the recall-critical decision.
- **Conclusion:** the naive "inherit VHX LLM-triage + harden it" thesis **fails the safety bar in every
  reachable configuration**. Per the plan's measure-first/fail-allowed design, **no verifier module
  ships**. The result is committed as a reproducible scorecard
  (`evaluation/sast-fp-discrimination/baseline-260725-{sast-sol,grok45}.json`), exactly as Week-10's
  judge was — a measured negative result, not an assertion.

**The honest upgrade direction (what to build instead).** The LLM must **not** make the drop decision.
The deterministic gate + structural filters decide keep/drop; the LLM is a **non-load-bearing
annotator** (confidence hint / human-facing rationale) that can never remove a finding. This is
Sentinel's measured-not-trusted ethos (0012/0015/0017/0018), now backed by data on the SAST surface.
VulnHunterX scores well because it optimises **F2** (tolerates recall loss) over **raw LiteLLM without
provenance**; Sentinel's stricter bar (no recall loss + provenance discipline) exposes the LLM verdict
as unsafe — the genuinely novel, honest contribution of this experiment.

**Default model → grok-4.5.** `cx/gpt-5.6-sol` is running low on quota, so the agents' default model
moves to `grok-4.5` (alias `sast-grok45` → `openai/gcli/grok-4.5` on the same router, added to the main
gateway; agent defaults repointed). grok is the stronger general model, but this switch does **not**
change the verifier conclusion (both models refuse under correct provenance). The frozen benchmark arms
`sast-sol`/`terra`/`gpt55` are left untouched — their committed scorecards are only reproducible through
those aliases (decision 0001).

## Consequences

- The verifier harness + the two-model spike are committed as a reproducible measurement + a documented
  negative result; **no module built** on the disproven thesis. The finding reinforces 0012/0015/0018 on
  a new surface and gives the AI-SAST inherit initiative an honest outcome: the path is a **broader
  deterministic SAST foundation + a non-load-bearing LLM annotator**, not LLM triage that can drop
  findings.
- Every agent LLM call now defaults to grok-4.5 through the provenance gateway; FinOps prices it (a
  labelled estimate); zero regressions (syndicate 30/0, hitl 9/0, verifier 5/0, finops 7/0).
- **Deferred (each an explicit decision first):** the deterministic-gate + LLM-annotator verifier
  (if pursued, it never drops a finding); broadening the deterministic foundation (OpenGrep/gosec/Bandit
  — a separate initiative); the full 66-repo RealVuln run (the bounded subset already gave a decisive
  signal); reconciling grok's cost estimate against a real invoice.
