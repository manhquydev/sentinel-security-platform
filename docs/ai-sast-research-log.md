# AI-for-Security research log (lab notebook)

Durable record of the experiments run on the question: **where does AI genuinely add value to security
tooling, and where do deterministic tools win?** Every entry lists the hypothesis, the method, the
measured data, and the conclusion — including the ones that disproved a hypothesis (especially those).

Guiding thesis under test: *security AI must stand on real tools (SAST/DAST/SCA), not invent findings.*
Corpus: **RealVuln** (kolega-ai/Real-Vuln-Benchmark, Apache-2.0, verified) — 63 fetched Python-web
repos, **1790 real vulnerabilities + FP-traps**, ground truth `{file, cwe, line, is_vulnerable}`,
matched file + CWE + line ±10, claim-once. Data fetched at eval time, never committed.
Harness: `evaluation/sast-fp-discrimination/` (all scripts reproducible offline unless marked LIVE).

---

## E1 — LLM-as-judge for evaluation verdicts (Week-10) → **NEGATIVE**

- **Hypothesis:** an LLM can judge whether the pentest agents' findings are correct.
- **Method:** narrow narrative judge vs a human gold set, under two provenance conditions.
- **Data:** under the security-correct `target-derived` label the hardened models **refuse to grade
  (0/12 conformance)**; only a forbidden trust downgrade to `operator` made them answer (12/12).
- **Conclusion:** the LLM judge cannot be safely instantiated; a **deterministic oracle** holds the
  verdict. → decision **0018**.

## E2 — LLM triage that DROPS false positives (VulnHunterX-style) → **NEGATIVE (unsafe)**

- **Hypothesis:** inheriting VHX's guided-question verifier reduces SAST false positives safely.
- **Method:** clean-room verifier (method inherited, no VHX code — LGPL), fail-safe integrity gate,
  LIVE on RealVuln via Bandit → match → verify → score. Two models × two provenance conditions.
- **Data:**

  | condition | `sast-sol` | `grok-4.5` |
  |---|---|---|
  | target-derived (correct) | refuse 15/15, FP-reduction **0** | refuse 15/15, FP-reduction **0** |
  | operator (forbidden downgrade) | FP-red 0.62, precision ↓0.38→0.29, **drops 3/8 real vulns** | FP-red 0.62, precision ↑0.50, **still drops 3/8 real vulns** |

- **Conclusion:** unreachable under correct provenance; **hides real vulnerabilities** when forced. No
  module shipped. → decision **0020**.

## E3 — LLM as a non-load-bearing RANKER (never drops) → **POSITIVE, then CORRECTED**

- **Hypothesis:** if the LLM only orders the triage queue (recall preserved by construction), it adds
  value.
- **Method:** `annotate.py` scores each finding 0..1 over **code-derived facts only** (rule/CWE/
  severity → `operator` provenance, so no refusal); AUC vs deterministic rankers; memoised (annotation
  depends only on those facts) → **37 LLM calls for 1764 findings**; conformance 1764/1764.
- **Data (held-out n=882):**

  | ranker | AUC | needs labels? | cost |
  |---|---|---|---|
  | scanner severity | 0.750 | no | free |
  | LLM annotator (zero-shot) | 0.818 | no | LLM calls |
  | **deterministic CWE-prior** | **0.886** | **yes** | **free** |

  Paired bootstrap **prior − LLM = +0.069 [+0.045, +0.095]** (excludes 0 → significant).
- **Conclusion:** the LLM beats *severity* but a free supervised **CWE-class prior beats the LLM**.
  Use the prior where labels exist; the zero-shot LLM only for cold start. → decision **0021** +
  its self-red-team amendment. Reproduce: `rank_baselines.py`.

## E4 — Multi-engine deterministic detection → **POSITIVE (the real lever)**

- **Hypothesis:** ranking cannot recover an undetected vulnerability; detection is the binding
  constraint.
- **Method:** `run_multiengine.py` — Bandit and Semgrep (security-audit + owasp-top-ten + python) over
  the same corpus, same matching, no LLM.
- **Data:**

  | engine | findings | TP | recall | precision |
  |---|---|---|---|---|
  | Bandit | 1764 | 234 | 0.131 | 0.133 |
  | Semgrep | 675 | 212 | 0.118 | **0.314** |
  | **union** | 2439 | **336** | **0.188** | 0.138 |

  Union = **+44% relative recall at no precision cost**; engines strongly complementary (of 336 union
  TPs only ~110 overlap → Bandit ~37% unique, Semgrep ~30% unique); Semgrep has **2.4× Bandit's
  precision** with a third of the findings.
- **Conclusion:** adding a deterministic engine is the one clean, free win measured so far. Engine and
  ruleset choice dominates any downstream ranking. → decision **0022**.

## E5 — Per-CWE detection gap → **CONFIRMED, and it yielded a general law**

- **Hypothesis:** the missed 81% is not spread evenly — it concentrates in classes pattern/AST SAST
  structurally cannot see, meaning the residual belongs to **runtime/DAST**, not to more SAST rules.
- **Method:** `analyze_cwe_gap.py` (per-CWE totals vs per-engine detections) then `classify_gap.py`,
  which buckets each class by a property taken from the **CWE definition**, independent of results.
- **Data (1790 real vulns, 54 classes):**

  | bucket | classes | real | detected | recall |
  |---|---|---|---|---|
  | **presence** of a bad pattern | 16 | 569 | 248 | **43.6%** |
  | **absence** of a required control | 12 | **847** | 39 | **4.6%** |
  | other | 26 | 374 | 49 | 13.1% |

  Per class: sees CWE-330 (95%), 327 (94%), 77 (89%), 89 (70%); blind on CWE-284 access control **0%**
  (187 vulns), CWE-307 no auth-attempt limit **0%** (134), CWE-200 info exposure **0.8%** (237 — the
  largest class). 35/54 classes (547 vulns, 31%) detected by neither engine.
- **Conclusion — the law:** **SAST detects the PRESENCE of a dangerous construct 9.5× better than the
  ABSENCE of a required control, and the absence bucket is the larger half of real vulnerabilities.**
  An absent control has no token to match; it is observable only in behaviour — i.e. at **runtime**.
  This is the empirical justification for the SAST ∪ DAST architecture. → decision **0023**.

## E7 — Cross-validation of the law on Sentinel's OWN lake → **CONFIRMED, zero overlap**

- **Hypothesis:** if the presence/absence law (E5) is structural rather than an artefact of the RealVuln
  corpus, then Sentinel's own SAST and DAST scanners should detect **disjoint** CWE classes, split along
  exactly that axis.
- **Method:** read the project's DefectDojo lake directly (`agent/lake.py`) and compare the CWE classes
  reported by the SAST scanner vs the DAST scanner. Independent targets, independent tools, data
  collected weeks earlier for an unrelated purpose — i.e. not tuned for this question.
- **Data:**

  | scanner | type | target | CWE classes found | bucket |
  |---|---|---|---|---|
  | Semgrep | SAST | WebGoat | **327** weak digest (×1), **330** insecure random (×10) | 100% presence |
  | Nuclei | DAST | Juice Shop | **693** missing security headers (×8), **200** public Swagger (×1) | 100% absence |

  **Overlap: zero classes.** The DAST findings are literally named *"HTTP **Missing** Security Headers"* —
  an absent control, which has no code token to match; the SAST findings are dangerous constructs
  present in source (`new Random()`, a weak digest call).
- **Cross-validation strength:** CWE-200 scored **0.8%** under SAST on the RealVuln corpus (237 vulns) —
  and here the DAST scanner detects it natively. The class SAST is blind to is the class DAST sees.
- **Caveat (honest):** small n (11 SAST + 21 DAST findings) and different targets, so this corroborates
  the *direction* rather than re-measuring the 9.5× magnitude. Its value is independence: nothing about
  this data was collected to test this hypothesis.
- **Conclusion:** the law reproduces on independent data with independent tools. → strengthens **0023**.

---

## Standing conclusions (what the data supports so far)

1. **Every time a deterministic mechanism could be measured against the LLM, the deterministic
   mechanism won or tied** (E1 oracle > judge; E2 unsafe; E3 prior > annotator). The LLM's proven niche
   is the **cold-start / no-labels** case, and only where it cannot remove information.
2. **The single clean win came from adding a real tool, not more AI** (E4: +44% recall, free).
3. **An LLM must never hold a decision that can remove a finding** — E2 showed it silently hides real
   vulnerabilities, which no ranking gain can offset.
4. **Provenance discipline is a hard constraint on LLM use**: hardened models refuse to reason over
   `target-derived` content, so any design that needs them to must either downgrade trust (forbidden)
   or restructure the input to code-derived facts (E3's approach).

## Open questions

- How much of the SAST-blind residual does Sentinel's own DAST/agentic layer actually recover? (the
  natural next experiment; it is the architectural justification of the whole syndicate)
- Is OpenGrep complementary to Semgrep or largely redundant (it is a Semgrep fork)? Worth measuring
  before adopting it as a third engine.
- Do gosec/Brakeman/js-x-ray show the same ~30% unique-contribution pattern in their languages?

## E8 — Runtime differential prober for the ABSENCE bucket → **WORKS (detects what SAST+Nuclei both missed)**

- **Hypothesis:** absence-of-control vulns (CWE-306/284/862), which SAST detects at 4.6% and Nuclei's
  stateless templates cannot reach at all, are detectable by a **differential runtime oracle**.
- **Method:** `evaluation/absence-detection/probe_missing_authz.py`. The attack-surface baseline already
  labels each endpoint's `auth_class`; request every **non-public, read-only, GET** endpoint with **no
  credentials**. Oracle: `401/403` = control present; `2xx` = control ABSENT (response size recorded as
  *impact*, never as the verdict). A committed set of expected-protected endpoints is probed identically
  as the **negative control**. Safety: GET only, read-only paths only, loopback fail-closed, no
  credentials, no account creation, nothing mutated — inside decision 0013's read-only bound, no HITL.
- **Data (Juice Shop, 5 endpoints, 1 request each):**

  | endpoint | label | no-credential response | verdict |
  |---|---|---|---|
  | `/rest/admin/application-version` | administrative | 200, 20B | **FINDING** — admin data unauthenticated |
  | `/rest/user/whoami` | authenticated | 200, 11B | **FINDING** — control absent (minimal impact) |
  | `/rest/basket/1`, `/api/Cards`, `/api/Addresss` | expected-protected | **401** | ok — negative control |

  **Negative controls 3/3 correctly protected → the oracle discriminates**, it does not rubber-stamp.
- **Comparison:** on this same target, Nuclei (DAST) reported missing-headers + Swagger and **zero**
  missing-authz; SAST reported none. The prober found what both missed — the predicted gap.
- **Instrument-design lesson (recorded honestly):** the first version used response SIZE as the verdict
  and wrongly downgraded `{"version":"20.1.1"}` from an *administrative* endpoint to "no data". Size
  measures **impact**; the missing control is the finding. Fixed, and the negative control was added
  after the first run had none (templated paths had been filtered out).
- **Conclusion:** the differential oracle closes a class that neither SAST nor template-DAST reaches.
  Scope caveat: only 2 baseline endpoints qualified — the corpus of labelled non-public endpoints is the
  limiting factor, not the technique.
