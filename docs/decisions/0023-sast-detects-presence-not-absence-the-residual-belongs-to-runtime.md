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

> **CORRECTED — the table above is the ORIGINAL, buggy attribution.** Hits were booked by `min(cwes)`
> over *primary ∪ acceptable* rather than the ground truth's `primary_cwe`, misfiling **61%** of
> vulnerabilities. The corrected figures are **presence 42.1% (268/637)**, **absence 6.8% (35/513)**,
> **78 classes**, and **877 (49%) blind**. See the correction table earlier in this decision.

**SAST detects PRESENCE 6.2× better than ABSENCE.** The direction is robust (≥3.5× under every
alternative bucketing tested, never inverted); the original 9.5× magnitude is superseded.

**WITHDRAWN: "the absence bucket is the larger half."** Under corrected attribution it is 513 vs 637 —
the reverse of the published claim — and 640 vulnerabilities (36%) remain unclassified, so relative
bucket size is **unresolved**, not merely smaller. No claim about which half is larger is supported.

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

---

## AMENDED 2026-07-26 (E56) — "SAST cannot see absence" was about the RULESETS, not about SAST

This decision's framing, and the language it exported to 0022, 0024 and 0027, treats the absence classes
as **structurally** beyond pattern analysis: an absent control writes no token, so there is nothing to
match. The supporting measurement is real — Bandit and Semgrep emit 33 distinct CWE classes across this
corpus and **not one is absence-class**.

That measurement supports a narrower claim than the one drawn from it. It shows **the shipped rulesets
contain no absence-class rule**. It does not show that such a rule cannot be written.

**One can be written, and it works.** About sixty lines that locate route declarations and report handlers
carrying no authentication or authorization marker, scored with this project's own matcher, reaches
**76 of 337 = 22.6% recall on CWE-306 and CWE-862**, against a shipped-engine baseline of **zero**.

**What survives unchanged.** The *presence/absence* distinction itself is sound and remains the most useful
frame this project has produced — the two families really do detect different things, and the engines
really are blind here. What is withdrawn is the word **structurally**, and with it any roadmap claim that
this territory can only be reached by an LLM.

**What the amendment costs the AI case.** 0027's opening argument is that the generative role occupies the
one place "a proposer cannot be beaten by the deterministic baseline, because the deterministic baseline is
approximately nothing". The baseline is not nothing; it was merely unwritten. The generative role's claim
now has to rest on what it does *better* than a rule — and E56 measured that too: the detector reaches 24%
recall at **6.7% precision**, because it cannot distinguish a deliberately public endpoint from a forgotten
check. That distinction is about intent, and it is the honest residual where the model has an advantage.

**What it does not license.** Composing them — detector for recall, model to filter its output — is the
verdict/gate role that 0018 and 0020 measured failing (a verifier that hid 3 of 8 real vulnerabilities) and
that DD1 forbids structurally. The obvious pipeline is closed by this project's own prior evidence.
