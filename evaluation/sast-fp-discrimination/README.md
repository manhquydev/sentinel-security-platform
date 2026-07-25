# AI-SAST FP-discrimination eval (verifier viability spike)

Measures whether the clean-room guided-question verifier (`agent/verifier/`) reduces SAST false
positives on a **real FP-trap corpus** without dropping real vulnerabilities. Design + pre-registered
metric: `docs/ai-sast-verifier-design.md`. Named `sast-fp-discrimination` to avoid the existing
`evaluation/false-positive/` (which measures the *egress guardrail*, a different thing).

## Corpus — RealVuln (verified, `plans/reports/researcher-260725-1015-realvuln-corpus-scout.md`)

**kolega-ai/Real-Vuln-Benchmark, Apache-2.0** (primary-source verified — NOT MIT). 66 Python-web repos,
2,176 findings = **1,903 vulns + 279 explicit FP-traps** (`is_vulnerable:false`), 18 web CWE families.
Ground truth: `ground-truth/{repo-slug}/ground-truth.json` (per-finding `{file, cwe, line,
is_vulnerable}`). Matching mirrors the benchmark: **file + CWE + line ±10**, each ground-truth entry
claimed once. Rule-only SAST scores ~14% F3 → real FP headroom to measure.

**Never committed** (Apache-2.0 data): `fetch.sh` shallow-clones the pinned per-repo SHAs from RealVuln's
`benchmark-manifest.json` into `corpus/` (gitignored), fail-closed on SHA drift. Bounded by a committed
`spike-subset.txt`. NOTICE/attribution preserved if results are published.

## Pipeline

```
fetch.sh  → corpus/ (Semgrep-scannable Python source + ground-truth.json)
  → run Semgrep (the lake's engine) → findings {rule_id, cwe, file, line, code_slice}
  → match to ground truth (file+CWE+line±10, claim-once)   [matcher: to build in the live run]
  → agent/verifier deterministic gate → single-turn triage → verdict-integrity gate
  → scorer.py → gate-only vs gate+verifier, LLM-marginal FP-reduction, recall floor, F2
```

## Pre-registered metric (gameable-proofed — see the DESIGN)

Denominator = the **LLM-triaged residual** (gate auto-keeps never counted as the LLM's). Ablation =
**LLM-marginal-over-gate**. **Hard recall floor** `1−ε` over SAST-flagged true-positives — breaching it
FAILS the spike regardless of FP-reduction. Held-out split; fail-closed corpus (`loaded ≥ manifest`).
**Measure-first bar**: record the baseline once, set "proceed" just above the gate; a miss is an
accepted, documented **negative result** — no module gets built (like Week-10's judge).

## Status — RAN. Thesis DISPROVEN (decision 0020)

Built + tested offline (`tests/ai-sast-verifier-test.sh` 5/0), then run LIVE on a bounded RealVuln
subset (Bandit → match → verifier → score; 21 findings, 8 real vulns + 13 FPs) across two models × two
provenance conditions:

| condition | `sast-sol` | `grok-4.5` |
|---|---|---|
| target-derived (correct) | refuse 15/15, FP-red **0**, recall safe | refuse 15/15, FP-red **0**, recall safe |
| operator (forbidden downgrade) | FP-red 0.62, precision 0.38→0.29, **drops 3/8 real vulns** | FP-red 0.62, precision 0.38→0.50, **still drops 3/8 real vulns** |

**Both models refuse to grade target-derived code under correct provenance (FP-reduction 0); when forced
via the forbidden trust downgrade, both silently drop real vulnerabilities (recall floor fails).** So
**no verifier module ships** — the honest path is a broader deterministic SAST foundation + a
non-load-bearing LLM annotator that can never drop a finding. Committed scorecards:
`baseline-260725-{sast-sol,grok45}.json`, `captured/verdicts-{sast-sol,grok45}.json`. This is a measured
negative result (like Week-10's judge), not a failure to build.

### Follow-on: the SAFE direction — non-load-bearing annotator (`run_annotate.py`, `agent/verifier/annotate.py`)

Instead of dropping, the LLM RANKS findings by review-priority over their code-derived facts (rule/CWE/
severity — operator-safe, so grok answers **21/21**, no refusal) and **never drops one** — recall stays
1.0 by construction. Measured as AUC (does it rank real vulns above FP-traps?) vs a deterministic
severity ranking, on the same bounded RealVuln subset (`annotate-baseline-260725.json`):

- deterministic severity AUC = **0.42** (worse than random — Bandit over-rates its noisy classes)
- LLM annotator AUC = **0.61** (better than severity and than random; demotes the CWE-703/259 noise)

**Honest read: a WEAK POSITIVE, not proof.** The safe direction is reachable and safe and beats the
deterministic baseline here, but n=21 and the mean priorities barely separate (0.29 vs 0.28) — it needs
the full 66-repo corpus to confirm. Contrast the drop-verifier (decisive negative): the safe annotator
is the direction worth confirming at scale.

## Files

| File | What |
|---|---|
| `scorer.py` | finding-level gate-only vs gate+verifier metrics; LLM-marginal FP-reduction; recall floor; F2 |
| `fetch.sh` | fetch pinned RealVuln subset into `corpus/` (gitignored), fail-closed on SHA drift |
| `spike-subset.txt` | committed repo-name subset for the bounded viability spike |
| `agent/verifier/{verify,gate}.py`, `questions/*.json` | the clean-room verifier + deterministic gate + CWE question sets |
