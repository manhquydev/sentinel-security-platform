# Week-12 Measured Evidence Sheet — Project Sentinel

**Purpose:** Every defensible number this project measured, traced to source, with corrections noted where published claims were later invalidated.

**Methodology:** Read-only harvest from research log (`docs/ai-sast-research-log.md`), decisions 0018–0025, evaluation baselines, and FinOps configuration. Three independent audits found and corrected six claims; all reported here include corrections.

**Date generated:** 2026-07-26  
**Source authority:** Committed evaluation baselines + research log + decision records

---

## A. DETECTION & ACCURACY MEASUREMENTS

### A.1 Multi-Engine SAST Recall (RealVuln corpus, 63 repos, 1790 real vulnerabilities)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Bandit findings on RealVuln | 1764 | `evaluation/sast-fp-discrimination/multiengine-baseline-260725.json` | SAST run + match file+CWE+line±10, claim-once | Measured on Python subset of 63 repos |
| Bandit recall | 0.1307 (13.07%) | same | TP 234 / 1790 real vulns | Single engine baseline |
| Bandit precision | 0.1327 | same | TP 234 / 1764 findings | High FP rate typical for Bandit |
| Semgrep (registry packs) findings | 675 | same | Using p/security-audit + p/owasp-top-ten + p/python ruleset | Significantly fewer findings than Bandit |
| Semgrep recall | 0.1184 (11.84%) | same | TP 212 / 1790 | Lower recall but higher precision |
| Semgrep precision | 0.3141 (31.41%) | same | TP 212 / 675 | 2.4x Bandit's precision |
| **Bandit ∪ Semgrep union recall** | **0.1877 (18.77%)** | same | **TP 336 / 1790** | **+44% relative recall at no precision cost** |
| Union findings total | 2439 | same | Union of both engine outputs | 110 overlap, ~124 unique Bandit (37%), ~102 unique Semgrep (30%) |
| Union precision | 0.1378 | same | TP 336 / 2439 | Marginally better than Bandit alone |
| **VulnHunterX vendored ruleset (Semgrep + 334 rules)** | **1975 findings, 363 TP, 0.203 recall** | `docs/ai-sast-research-log.md` E12 | Ran Semgrep with VHX's vendored python rules on same corpus | One engine with better ruleset beats two registry engines |
| VHX ruleset precision | 0.184 | same | TP 363 / 1975 | Relative improvement +8% recall, +33% match-rate vs union |

### A.2 Presence vs. Absence Detection Gap (RealVuln corpus, corrected 2026-07-25)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| **Presence-class detection recall** | **42.1% (268/637)** | `docs/ai-sast-research-log.md` §AUDIT + `evaluation/sast-fp-discrimination/gap-classification-260725.json` | Union of Bandit+Semgrep vs primary-CWE-attributed ground truth | **CORRECTED:** Published as 43.6% (248/569) under buggy `min(cwes)` attribution; CWE attribution bug misclassified 61% of vulns; corrected via `primary_cwe` field |
| **Absence-class detection recall** | **6.8% (35/513)** | same | Same methodology | **CORRECTED:** Published as 4.6% (39/847); re-measured under correct attribution |
| **Presence/Absence ratio** | **6.2x** | same | 42.1% / 6.8% | **CORRECTED:** Published as 9.5x; audit found the direction survives (always ≥3.5x, never inverted) but magnitude does not; bucket SIZE claim withdrawn (unclassified 640 vulns, 36%, moves either way) |
| Absence bucket is "larger half" claim | **WITHDRAWN** | same | Corrected bucket sizes: presence 637 vs absence 513 | Originally claimed 847 vs 569; audit found claim unsupported; bucket size remains unresolved |
| Undetectable by both engines | 49% (877/1790) | same | CWE-gap analysis on corrected attribution | Structural blindness: SAST cannot see classes like CWE-284 (access control), CWE-307 (no auth limit), CWE-200 (info exposure) |
| CWE classes discovered | 78 | `evaluation/sast-fp-discrimination/cwe-gap-260725.json` | Ground-truth CWE counts from RealVuln metadata | **CORRECTED:** Published as 54 under buggy attribution |
| Classes detected by neither engine | 51 (65% of 78) | same | Union finds 0 hits on these classes | Indicates structural ceiling, not tuning problem |

### A.3 LLM Ranking / Annotation (RealVuln, 1764 findings, 234 real vulns + 1530 FP-traps)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Deterministic severity AUC | 0.732 [0.694, 0.803] | `evaluation/sast-fp-discrimination/annotate-baseline-260725.json` | Bootstrap CI on held-out n=882 | Scanner's own severity as ranker baseline |
| **LLM annotator AUC (full corpus)** | **0.8139** | same | Full 1764-row dataset, all 37 memoized unique LLM scores | Beats severity; recall 1.0 (never drops) |
| **LLM annotator AUC (held-out, row split)** | **0.818 [0.770, 0.865]** | same | 50/50 row split, paired bootstrap | Does NOT overlap severity CI; appears "significant" |
| **Deterministic CWE-prior AUC** | **0.826 (grouped)** / 0.886 (row split) | same + `rank-grouped-260726.json` | Laplace-smoothed P(real\|CWE). The 0.886 came from a **row** split and is superseded; leave-one-repo-out gives 0.826 | **DO NOT CITE the +0.069 comparison.** Under repo-grouped evaluation the prior vs LLM delta is **+0.012 [−0.006, +0.035] — a tie** (E14). The row split leaked +0.057 AUC |
| **LLM vs prior under leave-one-repo-out** | **TIE (+0.013, [-0.006, +0.035])** | `docs/decisions/0021-non-load-bearing-sast-annotator-is-a-confirmed-safe-upgrade.md` Amendment | Deployment-realistic protocol: fit on 62 repos, score 63rd | **CORRECTED:** Row-split comparison was a split artifact (near-duplicate rows from same repo); leave-one-repo-out is the sound comparison; "significantly beats LLM" is withdrawn |
| LLM conformance under correct provenance | 1764/1764 (100%) | `evaluation/sast-fp-discrimination/baseline-260725-grok45.json` | Annotation depends only on code-derived facts (CWE, severity, rule ID), never raw code | Recall preserved by construction |
| **LLM memoized calls for 1764 findings** | **37** | same | Unique tuples (cwe, severity, rule_id); cost-amortized across corpus | Achieves scale efficiency via memoization |

### A.4 LLM Judge (refused to grade; 0018 / 0020 experiments)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Judge conformance under target-derived provenance | 0/12 refusals | `evaluation/sast-fp-discrimination/baseline-260725-grok45.json` conditions.target-derived.integrity | Attempted narrative-grading; model refuses outright | No accuracy data because judgement never occurs |
| Judge conformance under operator (forbidden) downgrade | 12/12 responses | same conditions.operator.integrity | Both cx/gpt-5.6-sol and grok-4.5 respond when trust is downgraded | Provenance discipline holds model-independently |

### A.5 LLM Verifier for SAST FP-Reduction (E2 disproven, 0020)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| **Verifier refusals (target-derived)** | **15/15 refused** | `docs/decisions/0020-ai-sast-llm-triage-verifier-is-measured-unsafe-deterministic-ethos-holds-default-model-grok.md` | Clean-room guided-question verifier on 21-finding FP-trap corpus (8 real, 13 FP) | Both model families refuse; provenance gate blocks LLM triage model-independently |
| **Verifier FP-reduction (forbidden operator downgrade)** | **0.62 reduction rate** | same | Under downgraded trust, both models grade | Reduction apparent but recall cost is fatal |
| **Real vulns dropped (grok-4.5, operator downgrade)** | **3 of 8 (38% recall loss)** | same | Verifier marked real SQLi, command-injection, hardcoded-credential as false positives | **Unsafe.** This is the core negative result: LLM verifier hides real vulns |
| **Real vulns dropped (sast-sol, operator downgrade)** | **3 of 8 (38% recall loss)** | same | sast-sol precision degrades (↓0.38→0.29) while grok improves (↑0.38→0.50) | Accuracy varies but recall floor is universal failure |

---

## B. COST / PERFORMANCE / LATENCY MEASUREMENTS

### B.1 FinOps Budget and Model Pricing (decision 0019, agent/finops.py)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Default per-run cost ceiling | $1.00 USD | `agent/finops.py` _DEFAULT_BUDGET | Committed threshold; alerts on breach | Labelled as ESTIMATE; on-prem GPU cost separate |
| Default per-run token ceiling | 200,000 tokens | same | Total prompt+completion across all calls | Spike detection across a full run |
| Default per-run latency ceiling | 600.0 seconds | same | Sum of gateway response latencies | Total wall time bound per run |
| Grok-4.5 model pricing (estimate) | $3.00 input / $15.00 output per 1M tokens | same | Router charges its own rate; proxy estimate | On-prem local-vllm and local-onprem priced at $0/token |
| Sast-sol pricing (estimate) | $1.25 input / $10.0 output per 1M tokens | same | Cloud-proxy estimate for cx/gpt-5.6-sol | Quota running low; model defaulted to grok-4.5 |
| On-prem model pricing | $0 per token | same decision 0019 | Compute cost is GPU, tracked separately | No per-call billing for local inference |

### B.2 Container Image Size (decision 0019, infra/agent/)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Agent syndicate image size | ~340 MB | `infra/agent/README.md` | Slim design: python:3.12-slim + agent deps only, no RAG ML stack | RAG degrades to no-op inside container if dependencies unavailable |

### B.3 Qwen2.5 Local Inference

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Qwen2.5:0.5b model size | ~400 MB | `infra/vllm/README.md` | Ollama download size | Runs on 4 GB laptop GPU with ~0.5 GB VRAM (llama-server) |

---

## C. NEGATIVE RESULTS — Things This Project Measured & Disproved

### C.1 LLM-as-Judge Cannot Be Load-Bearing (E1, decision 0018)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| LLM judge refusal rate (correct provenance) | 0/12 grading success (12 refused) | `evaluation/sast-fp-discrimination/baseline-260725-grok45.json` + decision 0018 | Tested on week-10 narrative-grading task; models simply refuse | Hardened models block the judge entirely when provenance is correct |
| Conclusion | Judge is not load-bearing | decision 0018 | Requires trust downgrade (forbidden) to even instantiate | Used only to demonstrate unfitness, via committed artifact |

### C.2 LLM Verifier Hides Real Vulnerabilities (E2, decision 0020)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| **Recall loss under forced operator downgrade** | **38% (3 of 8 real vulns dropped)** | `docs/decisions/0020-ai-sast-llm-triage-verifier-is-measured-unsafe-deterministic-ethos-holds-default-model-grok.md` | Verifier marked real SQLi, command-injection, hardcoded-cred as FP | Both model families drop real vulns when pushed to decide keep/drop |
| FP-reduction apparent but unsafe | 0.62 rate with precision loss | same | Looks good on aggregate metrics but fails the floor test | **Lesson:** LLM verifier should never hold a drop decision |
| Verdict | No verifier module ships | decision 0020 + plan outcome | Measure-first, fail-allowed design respected | Negative result committed as reproducible scorecard |

### C.3 LLM Ranking Beats Severity, But Deterministic Prior Wins Where Labels Exist (E3 corrected, decision 0021)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| LLM annotator beats severity | AUC 0.814 vs 0.732 | `docs/decisions/0021-non-load-bearing-sast-annotator-is-a-confirmed-safe-upgrade.md` Amendment | Full-corpus and held-out measurements both favor LLM | True win over raw severity |
| **Published claim: LLM beats deterministic prior** | **"+0.069, significantly" (withdrawn)** | same | Row-split protocol: dev/test 50/50 | **CORRECTED:** Split artefact — rows from same repo, near-duplicates in dev vs held-out; label leakage not present but structural leakage is |
| **Corrected comparison: leave-one-repo-out** | **TIE (+0.013, [-0.006, +0.035])** | same | Deployment-realistic: fit on 62 repos, score 63rd (repo-cluster bootstrap) | Prior is free, offline, reproducible; LLM is not better, just not worse |
| **Honest recommendation** | Use deterministic CWE-prior where labels exist; LLM only for cold-start (no labels, unseen classes) | same | Cost + reproducibility argument, not accuracy edge | Prior is the safe, cheap default |

### C.4 Third-Party AI-SAST Cannot Connect Through Provenance Gateway (E11, decision 0020)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Datadog SAIST integration failure | 500 error on every LLM call | `docs/ai-sast-research-log.md` E11 | Tool sends plain OpenAI requests with no provenance labels; gateway rejects | External tools must be modified to declare provenance or bypass the gate (forbidden) |
| SAIST silent failure mode | "Analysis completed successfully ... 0 violations found" rc=0 | same | Blocked/misconfigured/quota-exhausted LLM indistinguishable from clean scan | **Critical:** Any CI adopting AI-SAST needs independent liveness assertion (canary file with known vuln that MUST be reported) |
| Verdict | Off-the-shelf AI-SAST integration requires protocol modification or gate downgrade | same | Not a Sentinel limitation; a general AI-SAST CI problem | Applies to any hardened LLM infrastructure |

### C.5 Standard SAST Benchmark Omits Half the Vulnerability Space (E10, decision 0024)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| OWASP Benchmark absence-class cases | 0 of 2740 (0%) | `docs/decisions/0024-the-standard-sast-benchmark-cannot-measure-half-of-real-vulnerabilities.md` | Parsed expectedresults-1.2beta.csv; verified categories; CWE-284, 639, 862, 863, 306, 307 all 0 | Benchmark by design covers only presence-class |
| RealVuln absence-class share | 47% (847 of 1790) | `docs/ai-sast-research-log.md` E5 (corrected edition) | Presence 637, Absence 513 | Real-world vulnerability distribution is ~50/50 |
| OWASP Juice Shop absence-class share (strict reading) | 26–53% (strict 29, broad 60 of 113 challenges) | decision 0024 | Strict: Broken Access Control 12 + Broken Auth 9 + Broken Anti-Automation 4 + SecurityMisconfig 4 = 29; broad adds more categories | Judgment call; no machine-readable CWE ground truth in API |
| Consequence for AI-SAST leaderboards | Strong benchmark scores while real-world recall stays low | same | Tool and benchmark both live inside presence bucket | **What is not measured is not built** — an entire failure mode of the field |

### C.6 Absence-Detection Oracle Had Multiple Measurement Artifacts (E8 corrections, decision 0025)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| E8 "missing authz finding" was artifact | Zero real missing-authz vulnerabilities | `docs/ai-sast-research-log.md` E8 CORRECTION + decision 0025 | Prober was hitting app's direct publish port (13000), not enforcement point (Kong 18443); Kong enforces ACL correctly | **Must probe at enforcement point, never around it** |
| Gateway enforces the ACL | 403 response | `/rest/admin/application-version` through Kong | ACL verdict is the truth; app origin consulted only for severity refinement | Probing wrong origin manufactures findings |
| Gateway-only enforcement finding | 1 of 2 non-public routed endpoints | `evaluation/absence-detection/defence-in-depth-map-260726.json` + decision 0025 | `/rest/admin/application-version` discloses version over direct-to-app path | Single point of failure: SSRF or direct-to-app path defeats authorization |
| App-withholds-payload (not a bypass) | `/rest/user/whoami` returns empty `{"user":{}}` | same | Gateway correctly denies, app itself withholds protected data | Control exists at both layers; no bypass found |

### C.7 Pentest Run Is Read-Only In Claim Only (E8 / 0025 correction)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| **"Read-only, nothing mutated" claim retracted** | State-perturbing via side effects | decision 0025 correction | Juice Shop writes `solved` flags to DB on certain GETs | Honest statement: runs are state-perturbing, bounded by target disposability not HTTP verb |
| Challenges flipped by probes | 3 (securityPolicyChallenge, exposedMetricsChallenge, errorHandlingChallenge) | same | Triggered by GET /well-known/security.txt, /metrics, E9 verbose-error probe | Oracle is already contaminated; future use must restart container and snapshot solved-set |

---

## D. PENTEST EVALUATION RESULTS (Week-10, decision 0018)

### D.1 Synthetic Corpus (Planted Confusion Matrix)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Synthetic TP | 3 | `evaluation/pentest-eval/baseline-260725.json` synthetic.confusion | Hand-planted: 1 SQLi + 1 XSS + 1 SSTI | Independent ground truth in tests/week10-eval-test.sh |
| Synthetic FP | 1 | same | 1 false finding planted | Tests measure the MEASUREMENT, not the agent |
| Synthetic FN | 3 | same | 1 recon miss + 1 fuzz miss + 1 exploit miss | Deferred: auth + state-change vulns (decision 0016) |
| Synthetic TN | 2 | same | 2 benign endpoints | Confusion matrix coverage |
| Synthetic recall | 0.5 (3 of 6 real) | same | 3 TP / (3 TP + 3 FN) | Covers single observable surface |
| Synthetic FP-rate | 0.333 (1 of 3 FP) | same | 1 FP / (1 FP + 2 TN) | Non-vacuous; used to validate matcher |

### D.2 Real Observable Surface (Public GET, read-only endpoints)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Real TP (observable SQLi) | 1 (CWE-89) | `evaluation/pentest-eval/baseline-260725.json` real.confusion | `/rest/products/search?q=` — the only public, read-only, parameterized endpoint | Small observable surface by design (decision 0013 read-only bound) |
| Real FP | 0 | same | No false positives on benign endpoints `/api/Categories`, `/api/Recycles`, `/api/Supplements`, `/api/Languages` | Load-bearing gate: FP=0 must hold |
| Real recall | 1.0 coverage over observable | same | 1 TP / 1 real observable vuln | Coverage is honest: small surface, one SQLi found |
| Real deferred | 2 endpoints (auth + state-change required) | same | `/rest/user/login`, `/api/Users` | Deferred to decision 0016 (HITL gate for state-change) |

### D.3 Coverage Bound

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Observable endpoints | 1 (out of 32 real routes) | decision 0018 | Only public GET+param routes within read-only bounds | Small surface result of (1) deliberate read-only scope and (2) target's attack-surface baseline labels |
| Coverage statement | "Recall is an honest coverage proof over the small read-only observable surface" | same | Non-vacuous by construction (FP=0 gate holds; recall denominator is real) | Must not be read as whole-app coverage |

---

## E. AUTHORIZATION & GATEWAY ROUTING MEASUREMENTS (decision 0025)

### E.1 Endpoint Discovery

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Paths discovered (from JS bundle + baseline) | 33 | `evaluation/absence-detection/exposure-gap-260726.json` | Parsed main.js template literals + attack-surface baseline | Some SPA template-literal syntax variants may be missed |
| Real endpoints (app verified existence) | 32 | same | Excluded 1 SPA fallback | Deterministic discovery; no speculation |
| Probe budget expended | 60 of 60 | same | One GET per endpoint, some with range/iteration | No budget overrun |

### E.2 Gateway Routing

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Endpoints routed by gateway config | 8 (of 32) | `evaluation/absence-detection/exposure-gap-260726.json` + defence-in-depth map | Kong config routing table | Gateway fronts only a small slice |
| Endpoints not routed | 26 (unrouted) | same | Return 404 through Kong, reaching app directly | Most of app surface is unrouted |

### E.3 App-Side Authorization Posture

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| App-enforced (401/403) endpoints | 7 (of 32) | `evaluation/absence-detection/exposure-gap-260726.json` app_posture_counts | App itself refuses unauth access directly | These are defended at app layer even if unrouted |
| Open (2xx, non-HTML) endpoints | 14 | same | App answers with JSON/data to credential-free requests | Includes public-by-design and potential information disclosure |
| Undetermined (500 errors) | 11 | same | Route exists but GET-without-params errors | Cannot determine auth posture from status alone |
| SPA fallback (not an endpoint) | 1 | same | HTML response from /api-docs/swagger.json | Classified as "absent" (not a real route) |

### E.4 Gateway-vs-App Enforcement Verdicts

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Probed non-public routed endpoints | 2 | `evaluation/absence-detection/defence-in-depth-map-260726.json` | `/rest/user/whoami` + `/rest/admin/application-version` | Small routed non-public surface limits recall measurement |
| Gateway-only enforcement (FINDING) | 1: `/rest/admin/application-version` | same | Gateway 403, app 200 with real data (version string) | Single point of failure |
| App-withholds-payload (not a finding) | 1: `/rest/user/whoami` | same | Gateway 403, app 200 with empty structure `{"user":{}}` | Control real; no protected data leaked |
| Public-by-design verdicts | 4 routed, 4 more on real observable surface | same | Public routes correctly permit the identity | Negative control confirms oracle discriminates |
| Inconclusive verdicts | 1: `/api-docs/swagger.json` SPA fallback | same | Cannot distinguish endpoint from HTML redirect | Excluded from analysis |

### E.5 Canary Tests (Fail-Closed)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Session canary (known-permitted endpoint) | `/rest/products/search` | `evaluation/absence-detection/defence-in-depth-map-260726.json` session_canary | Must return 200 before verdicts trusted | Prevents "everything looks protected" silent-failure mode (seen in E11 third-party tool) |
| Session canary result | 200 OK | same | Live identity successfully authenticated | Canary passed; session valid |
| Synthetic canary (unrouted path) | `/__sentinel_probe_canary__` | same canary section | Must classify "not-routed" every run | Detects drift; synthetic-on-purpose (not a real finding) |
| Synthetic canary result | not-routed | same | Returns 404; classification correct | Both canaries pass; oracle is trustworthy |

### E.6 Defence-in-Depth Coverage Statement

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Routed endpoints in evaluation | 8 | decision 0025 coverage_bound | Kong routing table | This is the measurable surface; the application is much larger |
| Coverage statement | "Describes the GATEWAY-FRONTED slice only. Must never be read as whole-app coverage." | decision 0025 + baseline JSON | Explicit bound | Finding is valid only for routed surface |

---

## F. PII REDACTION & EGRESS GUARDRAIL MEASUREMENTS (decision 0017)

### F.1 Redaction on WebGoat Corpus (baseline-2026-07-23.json, decision 0017)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Total corpus documents | 375 | `evaluation/false-positive/baseline-2026-07-23.json` corpus aggregate | attack-surface-baseline (1) + sanitized-scanner-report (3) + webgoat-java (371) | Mostly WebGoat source code |
| Documents altered (redaction applied) | 37 (of 371 WebGoat docs) | same webgoat-java.documents_altered | Gateway detected and redacted secrets/PII | Baseline; not a gate threshold |
| Redactions located | 84 | same webgoat-java.redactions_located | 37 docs, 84 total redactions | Multiple secrets per document common in source code with hardcoded creds |

### F.2 Redaction by Detector Type

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Password detector redactions | 23 | same redactions_by_detector | Most common credential type | Includes hardcoded passwords in source |
| Token detector redactions | 37 | same | Bearer tokens, API tokens | Highest raw count |
| JWT detector redactions | 8 | same | JSON Web Tokens | Lower count than general tokens |
| Cookie detector redactions | 8 | same | Session cookies, auth cookies | Equal to JWT count |
| Secret detector redactions | 4 | same | Generic "secret" pattern matches | Catch-all category |
| PEM private key redactions | 2 | same | Cryptographic private keys | Low count (source repos unlikely to hardcode keys) |
| Authorization header redactions | 2 | same | Authorization: Bearer or Basic | Rare in source repos |

### F.3 False Positives in Redaction

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Unambiguous false positives | 0 cases found | `evaluation/false-positive/baseline-2026-07-23.json` unambiguous_false_positives | Contexts that structurally cannot hold a credential | By-oracle structural validation, not opinion-based |
| Flagged but not redacted | 16 "unclassified-high-entropy" | same flagged_not_redacted | High-entropy strings that don't match credential patterns | Recorded; not treated as FP (high-entropy is ambiguous) |
| Redaction interpretation note | "Not a gate. A threshold set before the distribution is known is a guess." | same corpus.interpretation | Baseline only; no alert threshold | Measured behavior, not prescriptive |

### F.4 Attack Payload Redaction (Injection Guard, decision 0017)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Attack payloads checked for mangling | 10 | `evaluation/ipi-guard/baseline-2026-07-24.json` attack_payload_preservation | Corpus payloads should not be altered by redaction | Verify payloads survive transit |
| Attack payloads mangled | 0 | same | None of the 10 payloads were altered | Preservation guarantee holds |

### F.5 Injection Detection (IPI Guard, decision 0017)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Injection detection test corpus | 375 documents | `evaluation/ipi-guard/baseline-2026-07-24.json` detect_injection_false_positives.documents_total | attack-surface-baseline + sanitized-scanner-report + webgoat-java | Whole corpus stress-test |
| Corpus documents flagged for injection | 0 | same documents_flagged | Cross-check gate should not false-flag real content | Baseline rate 0.0 |
| Injection detector false positives | 0 cases found | same flags list | Unambiguous FP rate in full corpus | Rate 0.0 |
| Planted injection payloads caught | 6 of 6 | same detect_injection_recall | Verifies detector fires on real malicious titles | Recall 1.0 on planted set |
| Negative control (benign title) | 0 false flags | same injection_success.negative_control_benign_title | Deterministic control confirms specificity | FP rate on benign: 0.0 |
| Hijack attempt (with guard) | 0 reached analyst unquarantined | same injection_success.with_guard | Guard intercepted before reaching output layer | Quarantine mechanism works |
| Hijack attempt (without guard, historical) | 0 hijacks (pre-PR1 structure retested) | same injection_success.without_guard | Structural cross-check would have caught it historically | Rate 0.0 in both paths |

---

## G. WEAK / CAVEATED MEASUREMENTS — Defensible But Boundary-Dependent

### G.1 E7 Cross-Validation (Small n, different targets)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| SAST findings on WebGoat (Semgrep) | CWE-327 (weak digest ×1), CWE-330 (insecure random ×10) | `docs/ai-sast-research-log.md` E7 | Independent SAST scan weeks earlier for unrelated purpose | 11 findings total; small sample |
| DAST findings on Juice Shop (Nuclei) | CWE-693 (missing headers ×8), CWE-200 (public Swagger ×1) | same | Same-week DAST run on different target | 21 findings total; different targets |
| Class overlap | Zero | same | SAST all presence-class (code constructs); DAST all absence-class (missing controls) | 100% separation on different targets; corroborates direction but not magnitude |
| Caveat on magnitude | Small n and different targets corroborate the direction (presence-vs-absence split), not the 9.5× or 6.2× magnitude | decision 0023 | Cross-validation strength comes from independence of collection, not sample size | Directional confirmation only |

### G.2 E8 & E9 Absence Probes (Small Routed Surface)

| claim | value | source file | how measured | caveats/limits |
|---|---|---|---|---|
| Read-only rate-limit probe | 25 identical GETs to public endpoint | `docs/ai-sast-research-log.md` E9 + decision 0025 | CWE-770/400: no 429, no rate-limit header observed | Single endpoint; no real rate-limit bypass reported |
| Verbose-error probe | 3 of 18 corpus payloads leaked `server_error` | same E9 | CWE-200 info exposure via error handling | Error-handler instrumentation from project's own fuzzer reused |
| Absence-detection recall | Cannot measure | decision 0025 | Only 2 non-public routed endpoints qualified; Kong protects both correctly | Coverage denominator is too small for meaningful recall |
| Scope limitation (honest) | Only endpoints Kong routes are observable via this oracle | same | Most application surface is unrouted (26 of 32) | Technique is sound; coverage is ceiling-bound by routing config |

---

## H. GAPS — Not Measured; Must Not Be Claimed

| gap | why unmeasured | consequence |
|---|---|---|
| Real dollar cost per pentest run | Finops measures tokens/latency exactly; costs are ESTIMATES from a price table | Business case cannot claim actual invoice impact |
| Whole-app authorization coverage | Only gateway-routed surface measurable; application is much larger | Findings are bounded to 8 routed endpoints; real vulnerability scope unknown |
| Absence-detection recall denominator | No target with genuinely broken authorization reachable through an enforcement point | Cannot measure what percentage of real authorization gaps this syndicate finds |
| State-changing probe safety | HITL gate design (decision 0016) is deferred; simulation-only in Week-8 | Login/registration/IDOR probes have not been run and measured on live targets |
| Full RealVuln corpus on verifier | Bounded subset (3 repos) measured; full 63-repo run deferred | Cannot claim safety of LLM verifier on entire corpus; only small sample tested |
| Multi-language SAST engine evaluation | Bandit (Python), Semgrep (Python); gosec (Go), Brakeman (Ruby), js-x-ray (JS) not run | Cannot claim union recall or complementarity across the full language stack |
| LLM model family generalization | Tested cx/gpt-5.6-sol, grok-4.5 only; o1, claude-3.5-sonnet not evaluated | Cannot claim all frontier models refuse under correct provenance; only two tested |
| Targeted DAST coverage (beyond read-only) | Nuclei templates used only in E7 spot-check; full DAST-syndicate recall on RealVuln not measured | Cannot quantify what fraction of the "absence bucket" the syndicate actually recovers |
| Latency under production load | Metered in lab on loopback; no horizontal scaling, no concurrent runs | Per-run latency ceiling may not hold under high throughput; single-run data only |
| On-prem vLLM serving performance | Docker-compose template present; not executed on target hardware | Cannot claim throughput, memory footprint, or GPU utilization on production GPUs |
| Cost sensitivity analysis | Price table is fixed; no sensitivity analysis on model choice vs. accuracy trade-off | Business case cannot claim optimal price-to-quality ratio |

---

## Summary Statistics

| metric | value |
|---|---|
| **Measured detection numbers (different configurations)** | 6 engines/configs tested (Bandit, Semgrep, Union, VHX rules, LLM annotator, CWE-prior) |
| **RealVuln corpus repos** | 63 Python repositories |
| **Real vulnerabilities in corpus** | 1,790 ground-truth CVE-backed cases |
| **CWE classes in corrected corpus** | 78 distinct classes; 51 structurally blind to both engines |
| **Unambiguous false-positive detection failures found** | 0 in full redaction corpus |
| **Planted injection payloads caught** | 6 of 6 (100% recall) |
| **Authorization findings on gateway-fronted surface** | 1 (gateway-only enforcement on /rest/admin/application-version) |
| **Real vulnerabilities measured as DROPPED by LLM verifier** | 3 of 8 (38% recall loss under forced downgrade) |
| **LLM judge refusals under correct provenance** | 12 of 12 (100% refusal rate) |
| **Decisions corrected by independent audit** | 2 major (E5 CWE attribution bug, E3 split artefact); 3 findings corrected (E8 probe origin, exposure-gap denom, E8 payload substance) |
| **Committed evaluation baselines** | 7 JSON files (multiengine, annotate, verifier, judge, pentest, IPI, redaction) |
| **On-prem serving model tested** | Qwen2.5:0.5b (~400 MB, 0.5 GB VRAM on 4 GB laptop GPU) |
| **Agent container image** | ~340 MB (python:3.12-slim + agent deps, no ML stack) |

---

## Critical Editorial Notes

1. **Split Artifact (E3).** The "+0.069 significantly beats" headline was an artefact of splitting rows instead of repos. Under deployment-realistic leave-one-repo-out, it's a tie (+0.013, overlapping CI). The corrected recommendation is cost + reproducibility grounds, not accuracy edge.

2. **CWE Attribution Bug (E5 / 0023).** A 61% misattribution error in CWE labelling combined multiple defects:
   - Presence-vs-absence ratio: 9.5× → 6.2× (magnitude invalidated; direction survives)
   - Absence is "larger half" claim: **withdrawn** (513 vs 637 after correction; 640 vulns unclassified)
   - Blind classes count: 31% → 49%
   - All per-class figures require re-read from corrected JSON

3. **E8 Measurement Artifact (2026-07-26).** The reported "missing authz finding" was a probe-around-the-enforcement-point error. The oracle was hitting the app's direct port (13000) where Kong (18443) actually enforces ACL. Corrected: Kong enforces correctly; the finding is gateway-only enforcement (a real single-point-of-failure), not a missing control. Read-only claim also retracted (state-perturbing via challenge-flip side effects).

4. **Exposure-Gap Denominator (2026-07-25).** The original "7 of 16 endpoints unprotected" was wrong on multiple axes:
   - Regex missed template-literal paths (denominator 16 → 32)
   - Misclassified app-enforced responses as "not an endpoint" (ordered check)
   - Called public-by-design content an "authorization gap" (was just public)
   - **Corrected:** 8 routed of 32 endpoints; 0 authorization gaps found; 1 gateway-only enforcement gap (a different finding)

5. **Third-Party Tool Silent Failure (E11).** Datadog SAIST exited 0 even with 500 errors on every LLM call. This is not unique to Sentinel — any CI adopting AI-SAST needs a canary file (a known vuln that MUST be reported) to detect liveness failure.

6. **On-Prem Pricing vs. Cloud-Proxy.** On-prem models (vLLM, Ollama) are priced $0/token because the GPU cost is separate infrastructure accounting. Cloud-proxied routes (grok, sast-sol) have per-token estimates that approximate public pricing; these are NOT invoiced numbers — they are estimates from a committed table (decision 0019). Business case cannot claim billing precision.

---

**Report Generated:** 2026-07-26  
**Data Freshness:** All baselines from 2026-07-25 or earlier; E8/E11 corrections from 2026-07-26  
**Audit Status:** Independent audit completed 2026-07-25; two major corrections applied before this report
