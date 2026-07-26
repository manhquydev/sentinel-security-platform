# 0022 Multi-engine deterministic detection is the real recall lever (+44%, free); the remaining SAST ceiling is structural and needs DAST

Date: 2026-07-25

## Status

Accepted. Measured on the full RealVuln corpus. This closes the AI-SAST inherit-and-upgrade arc with
the positive engineering direction the evidence actually supports.

## Context

Decisions 0018/0020/0021 measured three attempts to add LLM value to the static phase; each time a
deterministic mechanism won or tied. That prompted the obvious question the ranking work could not
answer: **how much is there to rank in the first place?** Over the fetched RealVuln corpus (63 repos,
1790 real vulnerabilities), Bandit — the engine the earlier experiments used — finds **13.1%**. No
ranker can recover a vulnerability that was never detected, so detection, not triage, is the binding
constraint.

## Decision (measured, no LLM involved)

`evaluation/sast-fp-discrimination/run_multiengine.py` runs two deterministic engines over the same
corpus with the same RealVuln matching (file + CWE + line ±10, claim-once):

| Engine | Findings | TP | Recall | Precision |
|---|---|---|---|---|
| Bandit | 1764 | 234 | 0.131 | 0.133 |
| Semgrep (security-audit + owasp-top-ten + python) | 675 | 212 | 0.118 | **0.314** |
| **Union** | 2439 | **336** | **0.188** | 0.138 |

**Findings:**

> **CONFIRMED WITH AN INTERVAL (E15, 2026-07-26).** This decision originally published a bare
> micro-averaged point estimate — the same structure that turned 0021's headline into a tie. Re-audited
> under repo-grouped bootstrapping it **survives**: relative gain **+43.6%, 95% CI [+31.5%, +58.4%]**
> over 63 repos, median per-repo gain **+0.0357**, precision delta **+0.0051 [−0.0136, +0.0173]** (interval
> spans 0, so "no measurable precision cost" is right and "precision improves" would not be). The per-repo
> run reproduced the committed totals exactly.
>
> **Caveat the point estimate hid: 22 of 63 repos (35%) gain nothing** — the union equals Bandit alone
> there. The supported claim is therefore **portfolio-level**, not a per-application promise.
>
> **RE-CLUSTERED (E73, 2026-07-26).** The 63 repositories are **33 independent applications** — the 40
> LLM-generated ones are 10 specs × 4 generators, replicates sharing structure and seeded-defect
> placement. Under application clustering the headline **survives**: [+28.5%, +61.7%], lower bound still
> ~3× the preregistered +10% floor. The **median-per-repo claim does not**: its interval becomes
> [+0.0000, +0.0690], touching zero, so "the union helps the median application" is **downgraded to
> MARGINAL** — it was supported by counting four implementations of one spec as four pieces of evidence.
> (`pool_spec_clustered.py`, `spec-clustered-260726.json`.)

1. **Multi-engine union raises recall +44% relative (0.131 → 0.188) at NO precision cost** (0.133 →
   0.138, marginally better). This is a free, deterministic, reproducible win — the opposite of the LLM
   experiments, where the deterministic baseline kept winning.
2. **The engines are strongly complementary**, not redundant: of 336 union true-positives only ~110
   overlap; Bandit uniquely contributes ~124 (37%) and Semgrep ~102 (30%). So "add another engine" is
   an evidence-backed lever, not a guess — which justifies evaluating further engines from the
   landscape (OpenGrep, gosec, Brakeman, js-x-ray, mobsfscan) per language, each measured the same way.
3. **Engine quality varies enormously**: Semgrep achieves **2.4× Bandit's precision** (0.314 vs 0.133)
   with a third of the findings. Engine and ruleset selection matters more than any downstream ranking.
4. **The honest ceiling: 81% of real vulnerabilities remain undetected by BOTH engines.** The
   most-missed ground-truth classes are CWE-200 (information exposure), CWE-284/862/639 (access
   control, missing authorization, IDOR), CWE-20 (input validation) — classes that require
   application semantics and runtime behaviour, which pattern/AST-based SAST structurally cannot see.

**Consequence for the architecture.** SAST is a high-value but hard-capped layer: broaden it with more
deterministic engines (cheap, complementary, measured), and accept that the residual is not a SAST
tuning problem. The access-control/authz/IDOR classes are precisely what **runtime testing** reaches —
which is why Sentinel's DAST/agentic syndicate (Weeks 4–10, Nuclei/Kong/fuzzing) exists alongside the
lake. This is the project's founding thesis, now measured rather than assumed: **the AI stands on a
broad deterministic tool foundation (SAST ∪ DAST ∪ SCA), and the residual is closed by adding
detection capability, not by asking a model to imagine findings.**

## Consequences

- The recall lever is identified and quantified; adopting further engines is now an evidence-backed,
  per-language decision with a committed measurement harness to justify each one
  (`multiengine-baseline-260725.json`, reproducible offline with no gateway).
- Ranking work (0021) is correctly demoted to a triage-ordering concern over whatever detection
  produces — with the free deterministic CWE-prior as the default ranker.
- **Deferred (each an explicit decision first):** adding OpenGrep (LGPL, Semgrep-compatible, offline)
  and gosec/Brakeman/js-x-ray per target language, each measured on this harness before adoption;
  wiring the union + prior into the live scanner→lake path; quantifying how much of the missed 81% the
  existing DAST/syndicate layer actually recovers (the natural next measurement).
