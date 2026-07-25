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

## Decision (the measured law)

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
