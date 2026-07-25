# 0023 SAST detects the PRESENCE of bad patterns, not the ABSENCE of controls (9.5×); the residual structurally belongs to runtime/DAST

Date: 2026-07-25

## Status

Accepted. Measured on the full RealVuln corpus with two deterministic engines. This is the empirical
justification for pairing the SAST lake with the DAST/agentic layer — the project's founding
architecture, now supported by data rather than assumption.

## Context

Decision 0022 measured that Bandit ∪ Semgrep reach 18.8% recall and miss 81%, and asked where the
residual actually sits. An aggregate number cannot tell you whether the gap is a **tuning** problem
(add rules/engines) or a **structural** one (a different detection mode is required). `analyze_cwe_gap.py`
broke the corpus down per CWE class; `classify_gap.py` then bucketed each class by a property taken
from the **CWE definition itself**, independent of the results.

## CORRECTION (2026-07-25, independent instrument audit) — read before the table below

An audit found that `analyze_cwe_gap.py` attributed each detection to `min(cwes)` over
*primary ∪ acceptable* CWEs instead of the ground truth's own `primary_cwe`, **misattributing 61% of
vulnerabilities** (CWE-798 booked as 259, CWE-78 as 77, CWE-639 as 284, CWE-434 as 20…). The bug is
fixed (`run_spike.load_gt` now carries `primary`, attribution uses it) and everything was re-measured:

| claim | as published (buggy `min`) | **corrected (`primary_cwe`)** |
|---|---|---|
| CWE classes in corpus | 54 | **78** |
| presence bucket | 248/569 = 43.6% | **268/637 = 42.1%** |
| absence bucket | 39/847 = 4.6% | **35/513 = 6.8%** |
| **presence-vs-absence ratio** | 9.5× | **6.2×** |
| "absence is the LARGER half" | 847 vs 569 → yes | **513 vs 637 → NO, WITHDRAWN** |
| blind classes (union detects 0) | 547 vulns (31%) | **877 vulns (49%)** |
| largest single class | CWE-200 "237 vulns" | CWE-307 (134); CWE-200 is **54** |

**What is withdrawn:** the 9.5× magnitude, the specific per-class figures quoted below, and the claim
that the absence bucket is the larger half. A further **640 vulns (36%) are unclassified** (CWE-434,
532, 614, 601, 204, 915, 918, 1021, 209, 942…), and how they are bucketed can move the size comparison
either way — so bucket SIZE is not a settled result and is reported as unresolved.

**What survives, and is the load-bearing point:** SAST detects *presence* far better than *absence*
(**6.2×** corrected; the audit's sensitivity sweep found the ratio stayed ≥3.5× and **never inverted**
under any defensible alternative bucketing or attribution). The absence bucket is large (513–877 vulns
depending on classification) and its recall is 6.8%. **The architectural consequence is unchanged:
the residual is not a SAST tuning problem and belongs to runtime/DAST.**

Corrected per-class evidence (primary-CWE attribution): CWE-307 no auth-attempt limit **0%** (134
vulns), CWE-312 cleartext storage **0%** (63), CWE-639 IDOR **0%** (60), CWE-200 info exposure **0%**
(54), CWE-532 log exposure **0%** (54) — versus CWE-330 **97.5%** (40), CWE-78 **89%** (46), CWE-89
**71%** (42), CWE-798 **53%** (55).

## Decision (the measured law — figures below are the SUPERSEDED originals; see the correction above)

Two structurally different kinds of vulnerability, over 1790 real vulns / 54 CWE classes:

| Bucket | Classes | Real vulns | Detected | **Recall** |
|---|---|---|---|---|
| **presence** of a bad pattern (SQLi, weak crypto, hardcoded key, `os.system` on input) | 16 | 569 | 248 | **43.6%** |
| **absence** of a required control (no authz, no rate limit, IDOR, missing authn) | 12 | **847** | 39 | **4.6%** |
| other / unclassified | 26 | 374 | 49 | 13.1% |

**SAST detects PRESENCE 9.5× better than ABSENCE — and the absence bucket is the LARGER half of real
vulnerabilities (847 vs 569).**

Per-class evidence (union of both engines):

- **Sees it:** CWE-330 insufficient randomness 95%, CWE-327 broken crypto 94%, CWE-77 command
  injection 89%, CWE-89 SQLi 70% — all *a dangerous construct is written in the code*.
- **Blind:** CWE-284 improper access control **0%** (187 vulns), CWE-307 no limit on auth attempts
  **0%** (134), CWE-200 information exposure **0.8%** (237 — the single largest class) — all *a
  required control is missing*.
- 35 of 54 classes (547 vulns, 31%) are detected by **neither** engine.

**Why this is structural, not a rule gap.** A pattern/AST engine matches tokens that exist. An absent
control has no token to match: "this endpoint never checks ownership" and "this login has no attempt
limit" are properties of *what the code does not contain and how it behaves*. No amount of additional
SAST rules changes that — but the same property is trivially observable at **runtime**: you detect a
missing rate limit by hitting the endpoint repeatedly, and a missing authorization check by requesting
another user's object. That is exactly what the project's DAST/agentic layer does (Nuclei, the Kong
ACL boundary, the fuzzing + exploit syndicate, Weeks 2–10).

## Cross-validation on Sentinel's own lake (2026-07-25)

The law was re-tested on **independent data collected weeks earlier for an unrelated purpose** — the
project's own DefectDojo lake, different targets, different tools:

| scanner | type | target | CWE classes | bucket |
|---|---|---|---|---|
| Semgrep | SAST | WebGoat | 327 weak digest, 330 insecure random | 100% presence |
| Nuclei | DAST | Juice Shop | 693 **missing** security headers, 200 public Swagger | 100% absence |

**Zero class overlap.** The DAST findings are literally named *"HTTP Missing Security Headers"* — an
absent control, which has no code token to match — while the SAST findings are dangerous constructs
written in source. And **CWE-200, which SAST detected at 0.8% on RealVuln (237 vulns), is detected
natively by the DAST scanner here**: the class SAST is blind to is the class DAST sees.

Honest caveat: small n (11 SAST + 21 DAST findings) on different targets, so this corroborates the
*direction*, not the 9.5× magnitude. Its weight comes from independence — none of this data was
collected to test this hypothesis.

## Consequences

- **Investment guidance, quantified.** Adding SAST engines/rules pays off inside the *presence* bucket
  (and 0022 showed +44% relative recall for one extra engine, complementary at ~30% unique). It cannot
  address the *absence* bucket, which holds the majority of real vulnerabilities. Effort there belongs
  to runtime/DAST coverage, not to more static rules or to an LLM.
- **The architecture is validated.** SAST ∪ DAST ∪ SCA is not defence-in-depth decoration: the two
  families detect structurally different vulnerability classes, and each is near-blind to the other's.
  The AI layer sits on top of that union — which is the founding thesis, now measured.
- **Reproducible instruments committed:** `analyze_cwe_gap.py` (per-CWE detection),
  `classify_gap.py` (presence/absence buckets), data in `cwe-gap-260725.json` +
  `gap-classification-260725.json`. Offline, no LLM, no gateway.
- **Deferred (each an explicit decision first):** measure how much of the absence bucket Sentinel's own
  DAST/syndicate actually recovers on a runnable target (the direct next experiment, and the strongest
  possible validation of the syndicate); check whether some blind *presence*-type classes (CWE-321
  hardcoded crypto key, 312/256 cleartext storage — currently 0%) are a genuine rule gap that an added
  engine would close; test whether OpenGrep is complementary to Semgrep or largely redundant (it is a
  fork) before adopting it as a third engine.
