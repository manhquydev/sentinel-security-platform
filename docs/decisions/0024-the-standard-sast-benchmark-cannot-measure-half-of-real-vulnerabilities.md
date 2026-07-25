# 0024 The industry-standard SAST benchmark contains 0% absence-of-control cases — it cannot measure the larger half of real vulnerabilities

Date: 2026-07-25

## Status

Accepted. Self-verified against primary data (OWASP Benchmark's own `expectedresults` CSV, Juice
Shop's live `/api/Challenges`, and Sentinel's RealVuln measurement). Explains *why* the field
under-invests in the detection gap that decisions 0022/0023 measured.

## Context

Decision 0023 measured that SAST detects "presence of a bad pattern" 9.5× better than "absence of a
required control", and that absence is the **larger half** of real vulnerabilities. The obvious
follow-up question is why an entire industry would leave the larger half under-served. The answer is a
measurement artefact, and it is verifiable in one command.

## Decision (the measured contrast)

**OWASP Benchmark v1.2beta — the standard against which SAST tools are scored — verified from its own
`expectedresults-1.2beta.csv` (2740 test cases, 11 categories):**

```
sqli 504 · weakrand 493 · xss 455 · pathtraver 268 · cmdi 251 · crypto 246
hash 236 · trustbound 126 · securecookie 67 · ldapi 59 · xpathi 35
CWEs present: 22, 78, 79, 89, 90, 327, 328, 330, 501, 614, 643
CWE-284: 0   CWE-639: 0   CWE-862: 0   CWE-863: 0   CWE-306: 0   CWE-307: 0
```

**Every category is a presence-type class. There are zero access-control, authorization, IDOR,
missing-authentication, or rate-limit test cases.**

Compare the absence-class share across three independent sources:

| Source | What it is | Absence-class share |
|---|---|---|
| **OWASP Benchmark** | the benchmark tools optimise against | **0%** (0 / 2740) |
| **RealVuln** | real CVE-backed corpus (Sentinel's E5 measurement) | **47%** (847 / 1790) |
| **OWASP Juice Shop** | a real deliberately-vulnerable app, live `/api/Challenges` (113) | **26–53%** (strict: Broken Access Control 12 + Broken Authentication 9 + Broken Anti Automation 4 + Security Misconfiguration 4 = 29; broad adds Sensitive Data Exposure 16 + Improper Input Validation 12 + Security through Obscurity 3 = 60) |

**Conclusion: the benchmark's category list *is* the presence bucket, by construction.** A tool that
maximises its OWASP Benchmark score is optimising exactly the half of the vulnerability space that
static analysis can see — and is neither rewarded nor penalised for the half it cannot. What is not
measured is not built.

This also explains a pattern observed earlier in this project: AI-SAST efforts (including
VulnHunterX's F2-optimised leaderboard results) can post strong benchmark numbers while real-world
recall stays low, because both the tools and their benchmarks live inside the presence bucket.

## Consequences

- **Benchmark selection is a load-bearing decision, not a formality.** Sentinel's own AI-SAST
  benchmark (`benchmark/`, OWASP Benchmark Java) measures only presence-class detection; that is fine
  for what it was built for (choosing a SAST engine/model) but it must never be read as evidence of
  overall vulnerability-finding capability. The `evaluation/absence-detection/` probes and RealVuln
  measurements cover the other half and are reported separately.
- **The gap is an opportunity, not just a caveat.** Because no standard benchmark measures
  absence-of-control detection, there is no established leaderboard to beat — and Sentinel already has
  the infrastructure that the class requires (multi-identity Kong OAuth2, a HITL gate for state
  change, a runtime syndicate). Building and *measuring* absence detection is where differentiated
  value is, precisely because the field's metrics look away from it.
- **Honest caveats:** the Juice Shop category→absence mapping is a judgement call, so it is reported
  as a strict/broad range (26–53%) rather than a point estimate; Juice Shop's `/api/Challenges` carries
  `category`, `difficulty`, `tags` and `description` but **no CWE and no endpoint field**, so it is not
  machine-readable ground truth for scoring a scanner without hand-labelling.
- **Deferred (each an explicit decision first):** hand-label a bounded Juice Shop absence set
  (endpoint + CWE + precondition) to obtain a real recall denominator for the E8/E9 probers; evaluate
  AuthProbe (arXiv 2607.20574) for IDOR/BOLA ground truth; the IDOR probe itself needs two
  authenticated identities → decision 0016's HITL gate → user authorisation.
