# 0021 The non-load-bearing LLM SAST annotator is a confirmed safe upgrade (ranks, never drops; beats deterministic ranking at scale)

Date: 2026-07-25

## Status

Accepted **as amended 2026-07-25 by the self-red-team in §Amendment** — the original "LLM beats
deterministic ranking" headline was INCOMPLETE and is corrected below. Standing conclusions: the
LLM-triage-that-DROPS verifier is disproven (0020); the RANK-never-drop annotator is safe and beats the
scanner's own severity; but a **free supervised deterministic CWE-prior significantly beats the LLM**
where labels exist, so the LLM's value is narrowed to the **zero-shot / no-labels** case.

## Context

Decision 0020 measured that an LLM verifier which decides keep/drop is unsafe (refuses under correct
provenance; drops real vulns when forced). It named the safe alternative: a **non-load-bearing
annotator** that assigns a review-priority and never removes a finding — recall preserved by
construction. This decision records the measurement of that alternative.

## Decision (measured, full RealVuln corpus)

`agent/verifier/annotate.py` + `evaluation/sast-fp-discrimination/run_annotate.py`: for each SAST
finding the LLM outputs a 0..1 review-priority reasoning over the finding's **code-derived facts only**
(rule id, CWE, severity — **operator** provenance, like recon over lake findings), never the raw target
code. It **never drops a finding**. Because the priority depends only on those facts, annotation is
**memoized** — the whole corpus costs ~unique-tuple LLM calls.

Measured over the full corpus (63 RealVuln repos, **n=1764** = 234 real vulns + 1530 FP-traps; **37**
memoized LLM calls; conformance 1764/1764 — no refusals, because it reasons over facts not raw code):

| Ranker | AUC (real-vuln above FP-trap) | 95% CI |
|---|---|---|
| deterministic severity | 0.732 | [0.694, 0.770] |
| **LLM annotator** | **0.814** | **[0.780, 0.848]** |

The annotator's CI does **not overlap** the deterministic ranker's → significantly better (priority
mean 0.44 on real vulns vs 0.26 on FP-traps). **Recall = 1.0 throughout** — nothing is ever dropped.

**Conclusion.** The safe, provenance-clean, non-load-bearing annotator is a confirmed upgrade: it
surfaces real vulnerabilities ahead of false-positive traps for a human triager, significantly better
than the scanner's own severity, with zero recall risk — exactly where the drop-verifier failed. This
is the honest realisation of "inherit the good ideas (VHX guided-questions, Metis evidence-anchoring)
within Sentinel's measured-not-trusted ethos": the LLM assists the human's *order of work*, it never
makes the *keep/drop* call.

(Honest caveat: the earlier n=21 subset was unrepresentative — it made severity look anti-correlated;
at scale severity is informative and the LLM advantage is real and larger. The full-corpus numbers are
the committed result.)

## Amendment (2026-07-25) — self-red-team: a free deterministic CWE-prior beats the LLM where labels exist

Before building on the positive above, the obvious challenge was tested: is the LLM's advantage merely
"it knows CWE-703/259 are noisy classes" — something a trivial deterministic lookup could replicate for
free? **Yes.** A **CWE-class base-rate prior** (Laplace-smoothed `P(real|CWE)`, fit on a random dev half,
scored on the held-out half — no leakage) was compared on the same held-out data (n=882, 120 TP/762 FP):

| Ranker | AUC (held-out) | 95% CI |
|---|---|---|
| deterministic severity | 0.750 | [0.697, 0.803] |
| LLM annotator (zero-shot) | 0.818 | [0.770, 0.865] |
| **deterministic CWE-prior (supervised)** | **0.886** | **[0.847, 0.926]** |

Paired bootstrap (n=2000): **AUC(CWE-prior) − AUC(LLM) = +0.069, 95% CI [+0.045, +0.095]** — excludes 0,
so the deterministic prior **significantly beats the LLM**.

**Corrected conclusion (the honest, more useful one).** The LLM annotator is safe (recall 1.0) and does
beat the scanner's raw severity — but it is NOT the best ranker available. The decisive distinction is
**labels**:

- **Labels available →** use the free, offline, reproducible **CWE-prior**. It is significantly better
  and costs no LLM call. Adding an LLM here would be paying for a worse ranker.
- **No labels (new codebase / unseen rule classes / cold start) →** the prior cannot be fit, and the
  **zero-shot LLM annotator** is the better-than-severity fallback.

This is the measured-not-trusted ethos holding a THIRD time on this surface (after 0018's judge and
0020's drop-verifier): whenever a deterministic mechanism can be measured against the LLM, it wins or
ties — so the LLM belongs only where no deterministic mechanism exists. Both baselines are cheap to
compute, so the honest product shape is: **deterministic prior first, LLM annotator only as the
cold-start fallback.**

## Consequences

- A committed, reproducible, significant positive result (`annotate-baseline-260725.json`) — the AI-SAST
  inherit initiative ends with a measured *win* on the safe direction, not just a negative on the unsafe
  one. Additive under `agent/verifier/` + `evaluation/sast-fp-discrimination/`; no W1–11 change.
- `fetch.sh` hardened to skip an unreachable/placeholder upstream repo instead of aborting the corpus.
- **Deferred (each an explicit decision first):** wiring the annotator into the live scanner→lake path
  as a priority field (a real integration, not a spike); broadening the deterministic SAST foundation
  (OpenGrep/gosec/Bandit); confirming across more models than grok-4.5; a human-facing rationale string
  alongside the priority (the annotator already can, measured separately).
