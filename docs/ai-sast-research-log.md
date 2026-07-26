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

## Ledger — what still stands

Navigation aid, not authority: **the entries below are authoritative**, and where one contradicts this
table the entry wins. Statuses for E1–E13 come from the meta-analysis in
`docs/plans/reports/2026-07-26-sentinel-implicit-protocol-meta-analysis.md`; E14–E18 were run and
audited on 2026-07-26.

| # | question | status |
|---|---|---|
| E1 | LLM as judge of findings | **STANDS (negative)** — refuses under correct provenance, 0/12 |
| E2 | LLM verifier drops false positives | **STANDS (negative)** — hides 3 of 8 real vulns; unsafe |
| E3 | LLM annotator beats a CWE prior | **CORRECTED ×2** — "+0.069 significant" → tie → **per-application +0.095 [+0.063,+0.128], prior wins** (E14) |
| E4 | non-load-bearing annotator is safe | STANDS |
| E5 | presence vs absence detection gap | **CORRECTED** — 9.5× → **6.2×**; "absence is the larger half" **WITHDRAWN** (61% CWE misattribution) |
| E6 | (no entry; exists only as the target of E12's correction) | — |
| E7 | cross-validation on our own lake | STANDS, **direction only** (small n) |
| E8 | runtime missing-authz prober | **WITHDRAWN** — probed *around* Kong; found zero real vulnerabilities |
| E9 | rate-limit / verbose-error probes | findings STAND; the "read-only" safety claim **RETRACTED** |
| E10 | does the standard benchmark cover absence? | **STANDS** — 0 of 2740 cases |
| E11 | third-party AI-SAST through our gateway | **STANDS** — cannot connect; exits 0 while every call 500s |
| E12 | VulnHunterX vendored ruleset | STANDS |
| E13 | marginal cost/yield of the LLM layer | **STANDS** — +$0.05, +35s, **zero extra findings** |
| — | exposure-gap measurement | **WITHDRAWN** — "7 of 16 unprotected" → 32 real routes, **zero** authorization gaps |
| E14 | re-audit of E3 under a grouped split | **STANDS as corrected** — and exposed that the retraction had never reached the code |
| E15 | re-audit of 0022's "+44%" | **STANDS** — +43.6% [+31.5%,+58.4%]; survived Stage-8 review byte-identically; precision clause qualified |
| E16a | can models emit machine-readable findings? | **STANDS (negative)** — 5 models × 3 formats × prefill = zero conformance, while correctly finding planted defects |
| E16b | generative role, first look | **INCONCLUSIVE** by preregistration (p = 0.065) |
| E17 | generative role, powered replication | **STANDS as corrected** — 10/60 vs 1/40 (p = 0.024) → **9/60 vs 0/40 (p = 0.0078)** after the classifier fixes; framing corrected (the deterministic zero is *structural*, so it is capability addition, not a horse race) |
| E21 | is low sensitivity an artefact of non-answers? | **STANDS (negative)** — 53% of non-answers resolve but 9/10 resolve to *clean*; sensitivity 0.167 -> 0.183. ~19% is **real** |
| E20 | file role or missing control? | **INCONCLUSIVE (withdrawn)** — reused arm A′ against a freshly measured arm C under a 36%-unstable instrument |
| E44 | is the positive control trustworthy? | **STANDS (instrument)** — **no**: the canary fired on 4/5 identical reads, so the single-reading gate blocked ~1 legitimate run in 5. Now read n times, pass on >=1; dead harness still scores 0/n and is still refused |
| E43 | lottery, or per-file signal? | **STANDS — a MIXTURE, neither** — pooled over 3 runs, 16 files: ever 0.291 vs never 0.021, **+0.271 [+0.104, +0.437] (excludes 0)**; best file **0.667 (excludes 1.0)**; 7 of 8 never-reported files at exactly 0. Most files ~0, a few at 0.33-0.67 — the 0.113 rate describes almost no individual file. Predicts E42 |
| E42 | does the class-asymmetry estimate replicate? | **STANDS (aggregate) / FAILS (per-file)** — rates reproduce exactly (6/53, 1/53, +0.094) on 52/53 byte-different responses, but the detected files **overlap in 0 of 6**. A reproducible RATE, not per-file detection |
| E41 | is CWE-307's invisibility competition for the answer? | **STANDS (negative)** — uncontested 1/16 = 0.062 vs contested 1/53, p = 0.41; **no recovery**, and the uncontested files are *smaller* (84 vs 189 median lines), so the confound favoured recovery. Large salience effect ruled out |
| E40 | can targeted per-class prompting recover CWE-307? | **ABANDONED at the canary gate (twice)** — the targeted prompt reported the rate limit absent on code that has one; 4 canary readings across 2 formats, never discriminating. No corpus calls spent. Question stays open |
| E39 | is the class narrowing real on corpus code? | **STANDS as an ESTIMATE (not a test)** — ownership/authn 6/53 vs rate-limit 1/53, difference **+0.094 [+0.000, +0.189]**; direction matches E34 but the interval includes zero. **1 of 53 files with a real CWE-307 defect had it named** |
| E38 | do the stored verdicts still match the prose? | **STANDS (instrument)** — **no**: 11 rows across 7 artefacts had drifted (echoed source inside code fences, scored before code-stripping existed). Reconciled; it cut **both ways**. Also: the CWE-306 vocabulary was dead (0/440), and CWE-200's is not specific enough for class attribution |
| E37 | is the capability class-uniform or concentrated? | **CANCELLED at power gate, then SUPERSEDED by E42** — reinstated at k=3, 94.6% power, 159 calls, once the correlation was measured here instead of imported from E31. Original text: — 43.3% paired, 53.7% at k=3 under measured churn; only a falsified independence assumption reaches 80% |
| E36 | replicate the mess control | **STANDS** — messy 2/80 vs absence 14/59, p = 0.000120; messy vs clean p = 0.44 (indistinguishable). Artefact no longer stale |
| E35 | replicate the headline | **STANDS** — fresh run 14/59 vs 0/40, p = 0.000350 (E17 re-scored: 9/60 vs 0/40). Specificity 0/40 in **both**. Artefact no longer stale |
| E34 | authored-unseen, powered | **STANDS** — 7/12 vs 0-1/12, p = 0.0136. **Class-specific**: ownership+authn 6/6, rate-limit/mass-assignment/error-leak/re-auth 0/4 |
| E33 | clean 2-level mutation comparison | **CANCELLED at power gate** — 32% power even using all 117 eligible files |
| E32 | structural familiarity | **INCONCLUSIVE (leaning against)** — anonymised+reordered 8/41 vs 11/41, −0.073 [−0.195,+0.049]; transfer bound does **not** narrow |
| E31 | per-file propensity | **STANDS** — mixture confirmed: 10/12 stable at 0. Most instability is clean<->non-answer; **flag churn ~1 in 12**; controls theta=0.000 across 18 calls |
| E30 | propagating noise into intervals | **WITHDRAWN (model error)** — treated a disagreement rate as a flip probability; falsified by E28's measured 0.026 drift |
| E29 | how unstable is the instrument, really? | **STANDS** — pooled **15/38 = 40%** verdict flips, 95% CI [21%,63%]; **0/38 identical prose**. Replaces the bare "36%" |
| E28 | does the conclusion replicate? | **STANDS** — 7/40 vs 1/42, diff **+0.151** against E24's **+0.177** — agreement to within **0.026** — p = 0.0241; individual verdicts churn, the difference does not |
| E27 | how much did the classifier under-count? | **STANDS** — narrow (~1 file in 53 on this corpus); and E23/E24 found **non-re-analysable** (responses truncated at 400 chars) |
| E26 | sensitivity on authored unseen code | **STANDS (demonstration)** — 3/4 planted defects found, 0/4 false claims on controls; classifier under-counted 2/4, so published sensitivity is a **floor** |
| E25 | transfer to unseen code | **STANDS (bounded)** — 0 flags on 25 files of our own code (written days before): **specificity transfers**; sensitivity untested, no ground truth |
| E24 | file role, valid design | **STANDS (live result only)** — 9/40 vs 2/42, p = 0.020. **Not re-verifiable**: stored responses truncated at 400 chars (E27), so a re-score under-counts to 6/40 |
| E23 | memorisation, valid design | **STANDS (live result only; not re-verifiable — see E27)** — anonymised 14/53 vs original 11/53, diff +0.057 [−0.038,+0.151]: no collapse, so surface memorisation is not the driver; equivalence NOT established |
| E22 | is the instrument deterministic? | **STANDS** — **no**: 36% verdict flips, 0/14 identical prose at temperature 0 |
| E19 | capability or memorisation? | **INCONCLUSIVE (withdrawn)** — the paired design assumed a deterministic instrument; E22 measured 36% verdict flips, which alone explains the null |
| E18 | is it detection, or reaction to messy code? | **STANDS** — **detection**: defective code with no absent control draws flags at 3/80, indistinguishable from clean (p = 0.59); vs absence arm p = 0.010 |

**The pattern worth reading this table for:** of the corrections above, **every quantified one that
touched a published claim moved it against this lab's own headline**.

That sentence used to end "none ever found an understatement", and E38 retired the absolute. The
artefact reconciliation found drift in both directions: one stored verdict had inflated the E35 headline,
and another had left the E34 artefact *more* pessimistic than the figure the log had already published.
The published claims still only ever moved the unflattering way — but a summary line that can only come
out flattering to the people writing it is worth distrusting, and the honest version is narrower than the
one that read better.

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

## E9 — Read-only probes for two more ABSENCE classes → **2 findings, and an instrument lesson**

- **Hypothesis:** more of the absence bucket is reachable with strictly read-only, credential-free
  probes — no state change, so no HITL gate needed (decision 0016 stays respected).
- **Method:** `evaluation/absence-detection/probe_missing_limits.py`.
  * **CWE-770/400 no rate limit** — bounded burst of identical GETs to a public read-only endpoint;
    any throttling signal (429 / `Retry-After` / rate-limit header) = control present.
  * **CWE-200 verbose-error info exposure** — malformed GET values; a `stack_trace`/`server_error`
    signal = the generic-error-handling control is absent.
- **Data (Juice Shop, read-only, nothing mutated):**

  | class | endpoint | result |
  |---|---|---|
  | CWE-770/400 no rate limit | `/.well-known/security.txt` | **FINDING** — 25 identical requests, no 429, no rate-limit header |
  | CWE-200 verbose error | `/rest/products/search` | **FINDING** — 3/18 corpus payloads leaked `server_error` |

- **Instrument lesson (the important part):** v1 used **five hand-invented payloads** and reported
  "handled generically" on `/rest/products/search` — while the project's OWN fuzzer had already
  recorded `stack_trace` on that exact endpoint. The instrument was weaker than the tool sitting next
  to it. Fixed by **reusing `agent/fuzz_payloads.CORPUS` + `agent/fuzz_signals.detect`** instead of
  reinventing them; the finding then appeared. *The project's own "inherit, don't rebuild" rule applies
  to its internal tooling too* — and a disagreement between two instruments is a bug signal, not noise.
- **Conclusion:** the read-only absence surface is larger than E8 alone suggested (missing rate limits
  and verbose errors are both detectable with zero credentials and zero state change). The remaining
  big class — **IDOR / broken object-level authz (CWE-639/862)** — needs TWO authenticated identities,
  i.e. login/registration = state change → decision 0016's HITL gate. That is a user decision, not
  something to slip past the boundary.

## E10 — Why the field under-invests in absence detection → **the benchmark cannot see it (0%)**

- **Hypothesis:** if absence-of-control is the larger half of real vulnerabilities (E5) yet tools
  under-serve it, the cause may be a *measurement* artefact — the benchmarks tools optimise against may
  not contain the class at all.
- **Method:** verified from PRIMARY data, not from the literature. Parsed OWASP Benchmark's own
  `expectedresults-1.2beta.csv` (2740 cases) for its category/CWE list; queried the live Juice Shop
  `/api/Challenges` (113 challenges) for its category distribution and available fields.
- **Data:**

  OWASP Benchmark v1.2beta — complete category list:
  `sqli 504 · weakrand 493 · xss 455 · pathtraver 268 · cmdi 251 · crypto 246 · hash 236 ·
  trustbound 126 · securecookie 67 · ldapi 59 · xpathi 35`; CWEs 22/78/79/89/90/327/328/330/501/614/643.
  **CWE-284: 0 · 639: 0 · 862: 0 · 863: 0 · 306: 0 · 307: 0** — every case is presence-class.

  | source | what it is | absence-class share |
  |---|---|---|
  | OWASP Benchmark | the benchmark tools optimise against | **0%** (0/2740) |
  | RealVuln | real CVE-backed corpus (E5) | **47%** (847/1790) |
  | Juice Shop | real vulnerable app, live API | **26–53%** (29–60 of 113) |

- **Conclusion:** the standard SAST benchmark's category list **is** the presence bucket by
  construction, so a tool maximising its benchmark score is optimising exactly the half static analysis
  can see, and is neither rewarded nor penalised for the half it cannot. **What is not measured is not
  built.** It also explains how AI-SAST efforts can post strong leaderboard numbers (e.g. F2-optimised
  results) while real-world recall stays low — tools *and* their benchmarks both live in the presence
  bucket. → decision **0024**.
- **Side finding:** Juice Shop's `/api/Challenges` exposes `category/difficulty/tags/description` but
  **no CWE and no endpoint**, so it is not machine-readable ground truth for scoring a scanner without
  hand-labelling — which is why the E8/E9 probers still have no recall denominator.

## AUDIT (2026-07-25) — an independent review invalidated two published conclusions; both corrected

An independent audit re-executed the whole measurement stack (both engines over all 63 repos) and
reproduced every published number exactly *before* challenging it. It found two real defects:

1. **CWE attribution bug (affects E5/0023, and 0022's narrative).** Hits were attributed by
   `min(cwes)` over *primary ∪ acceptable* instead of the ground truth's `primary_cwe` —
   **61% of vulnerabilities were booked under the wrong class**. Corrected:

   | | published (buggy) | corrected |
   |---|---|---|
   | classes | 54 | **78** |
   | presence | 43.6% (248/569) | **42.1% (268/637)** |
   | absence | 4.6% (39/847) | **6.8% (35/513)** |
   | ratio | 9.5× | **6.2×** |
   | "absence is larger half" | yes | **NO — withdrawn** |
   | blind | 547 (31%) | **877 (49%)** |

   The **direction survives** (ratio ≥3.5× under every alternative bucketing tested, never inverted);
   the magnitude and the size claim do not. 640 vulns (36%) remain unclassified, so bucket size is
   explicitly unresolved.

2. **E3/0021's "+0.069, significantly beats the LLM" is a split artefact.** Rows come from 63 repos /
   16 CWE classes / 37 unique memoised scores, so held-out rows are near-duplicates of dev rows. Under
   **leave-one-repo-out + repo-cluster bootstrap: +0.013 [−0.006, +0.035] — a TIE.** Restated: prefer
   the deterministic prior on **cost and reproducibility**, not on an accuracy edge.

3. **E8's oracle had a real false-positive mode.** A path that does not exist returns `200 + index.html`
   on this SPA and was classified `control-absent`. Added a nonexistent-path negative control, an
   HTML-fallback guard, `allow_redirects=False`, and a baseline-`confidence` gate (hypothesis-labelled
   endpoints now report `label-unverified`, so `/rest/user/whoami` is no longer claimed as a finding).
   Negative controls 4/4; one defensible finding remains (`/rest/admin/application-version`).

4. **A hardcoded claim in output.** `classify_gap.py` printed "the absence bucket is the LARGER half"
   unconditionally — it survived into a run where it was false (513 vs 637). Now derived from the data.

**What held up under attack:** 0022's recall numbers reproduced exactly and survived order,
engine-order, null-CWE and canonical-semantics challenges (union 336 either way; overlap 110/124/102
verified); the bootstrap is correctly paired; the dev/held-out split has no *label* leakage; and E8's
earlier self-caught bugs were already recorded rather than hidden.

**Lesson for the lab:** every published number needs an adversarial re-run by someone who did not write
the instrument. Two of my conclusions were wrong in ways I could not see from inside.

## E11 — Running Datadog SAIST (AI-native SAST) through Sentinel's gateway → **two hard findings**

- **Motivation:** an honest audit of this lab showed only 2 of ~19 surveyed tools had actually been
  EXECUTED (Bandit, Semgrep); the rest was research. Datadog SAIST was already vendored in-repo
  (`benchmark/tools/datadog-saist`, a 60 MB prebuilt Go binary) and had never been run.
- **Method:** ran the real binary on a corpus repo, pointing `-openai-base-url` at Sentinel's own
  provenance-hardened gateway. SAIST validates `-detection-model` against a fixed vocabulary and sends
  that name verbatim, so a documented adapter alias (`openai-gpt5-mini` → grok-4.5) was added to the
  gateway config. Flags: `-local-prompts -skip-indexing` (no Datadog API/JWT dependency).
- **Finding 1 — the hardened gateway REJECTS off-the-shelf AI-SAST.** Every LLM call returned:
  `500 "request carries no sentinel_provenance declaration; the gateway cannot distinguish operator
  instructions from target-derived data, so the request fails closed"`. SAIST sends plain OpenAI
  requests with no provenance labels, because no external tool speaks Sentinel's contract. This is the
  **third** independent time provenance discipline has blocked LLM-SAST integration (E1 judge refused,
  E2 verifier refused, E11 tool cannot even connect) — and the first where the blocker is the
  *protocol*, not the model. Any external LLM-security tool must either be modified to declare
  provenance or bypass the control that makes the gateway a security boundary.
- **Finding 2 — SAIST fails SILENTLY (the more serious one).** With every LLM call failing it still
  printed `Analysis completed successfully … 0 violations found across 3 files using 12 rules` and
  **exited 0**. A blocked/misconfigured/quota-exhausted LLM is therefore indistinguishable from a
  genuinely clean scan. This is precisely the failure mode this project journaled in
  `2026-07-23-checks-that-passed-because-they-checked-nothing.md` — here observed in a third-party
  AI-native SAST product, not in our own code. Any CI adopting an AI-SAST tool needs an independent
  liveness assertion (e.g. a canary file with a known vulnerability that MUST be reported), or a green
  build proves nothing.
- **Status:** SAIST executed end-to-end (rc=0, SARIF written) but produced 0 findings because its LLM
  stage never completed. A provenance-declaring run would require patching SAIST's request builder —
  deferred as an explicit decision (it is a fork of a third-party Apache-2.0 tool).

## E12 — Cloning VulnHunterX for real (it had only ever been web-researched)

- **Motivation:** the honest audit showed VHX — the *primary inheritance source* and the user's own
  project — had never been cloned. Every claim about it came from web research.
- **Clean-room boundary kept:** structure, config and DATA were inspected; the verification engine's
  source and prompt templates were deliberately **not** read, so `agent/verifier/`'s clean-room
  provenance (built from the published method description) stays intact.
- **Structural claims VERIFIED:** `src/vuln_hunter_x/{codeql,semgrep,opengrep,questions,context,fuzz,
  llm,sarif,reporting}`; `benchmarks/{datasets.yaml,adapters,approaches,metrics}` with the 3-arm design
  (`raw_sast.py` / `vulnhunterx.py` / `ablation.py`) exactly as researched; 921 yaml/json under `config/`.
- **NEW — VHX also evaluates on RealVuln** (`datasets.yaml`), the same corpus this lab measured on, so
  the Bandit/Semgrep baselines here are directly comparable to VHX's published numbers.
- **NEW — VHX vendors 881 OpenGrep rule files across 9 languages** (`config/opengrep-rules`, python
  alone: 334), pinned to upstream `opengrep/opengrep-rules@f1d2b56`, imported 2026-06-14, explicitly so
  the engine runs **offline without contacting `registry.semgrep.dev`**.

### Correction to E6's "OpenGrep is not viable" conclusion

The earlier research agent concluded *"official ruleset archived Nov 2025 → not viable, skip"*.
Verified via the GitHub API: `opengrep/opengrep-rules` **is** archived (`archived=true`, last push
2025-11-28) — so the *maintenance* objection stands. But "unusable" was too strong: an archived repo is
still cloneable, and **VHX demonstrates a working offline vendored-snapshot approach**. Honest synthesis:
**frozen ≠ unusable**; adopting it is a maintenance decision, not a feasibility one.

### LICENSING — four conflicting signals in VulnHunterX (actionable for its owner)

| Signal | Says |
|---|---|
| `README.md` badge + text | "MIT — see LICENSE" |
| `LICENSE` file (actual) | **LGPL-2.1** |
| `pyproject.toml` classifier | "License :: OSI Approved :: MIT License" |
| `config/opengrep-rules/LICENSE` | **Commons Clause** — grants no right to **Sell** |

The README's *"MIT — see LICENSE"* is self-contradicting (LICENSE is LGPL-2.1), and the vendored rules
add a **Commons Clause** restriction that propagates to anything shipping them: no product or service
whose value derives substantially from that software may be sold. For a research/education capstone
this is fine; for any commercialisation path it is a blocker that should be resolved deliberately.
This is why Sentinel inherited the *method* clean-room rather than the code (decision 0020).

### E12 result — **VHX's vendored RULESET beats the two-engine union (the real inheritable asset)**

Ran Semgrep (already installed) with VHX's 334 vendored **python** rules over the same 63-repo corpus,
same matcher, same claim-once ground truth — measurement only, nothing vendored into Sentinel:

| configuration | findings | TP | recall | GT-match rate |
|---|---|---|---|---|
| Bandit alone | 1764 | 234 | 0.131 | 0.133 |
| Semgrep registry packs | 675 | 212 | 0.118 | 0.314 |
| Bandit ∪ Semgrep (2 engines, E4) | 2439 | 336 | 0.188 | 0.138 |
| **Semgrep + VHX vendored rules (1 engine)** | **1975** | **363** | **0.203** | **0.184** |

**One engine with a better ruleset beats two engines with registry packs** — +8% relative recall and
+33% relative match-rate over the union, at lower operational cost (one tool, offline, no registry).

**This reframes the whole inherit-from-VulnHunterX question.** Across the arc, VHX's *LLM triage* was
disproven (E2: refuses under correct provenance; drops real vulns when forced). Its genuinely valuable
contribution turns out to be the unglamorous part: **a curated, pinned, offline ruleset**. The lesson
matches every other result in this lab — the wins come from better deterministic tooling, not from
adding model reasoning.

*Caveat (per the instrument audit):* "GT-match rate" is `tp/findings` against a curated ground truth,
not true precision — an unmatched finding is not necessarily a false positive. Recall is the sound
comparison; both are computed identically across rows so the ranking is fair. Rules were used
in-place from a scratch clone (Commons Clause forbids *selling*, not measuring); adopting them into
Sentinel would need an explicit licence decision.

## Exposure-gap measurement (gateway routing coverage vs. app-side enforcement) — **INVALIDATES-THE-CLAIM**

- **Hypothesis:** Kong routes only 8 endpoints; the application exposes far more. Measuring both what the
  gateway knows about and what the app defends will show how much surface area sits with no enforcement
  control in front of it.
- **Method:** `evaluation/absence-detection/measure_exposure_gap.py`. Deterministically discover paths from
  the Angular client bundle (`/main.js`) and attack-surface baseline; probe both the gateway and the app
  origin as the live agent identity. Classify endpoints on two independent axes: **(1) routing** — does the
  gateway's config route this path? (status != 404); **(2) app posture** — what does the app itself do
  when reached directly (401/403 vs 2xx vs 500 vs SPA fallback)?
- **Published claim:** "**EXPOSURE GAP: 7 of 16 real endpoints have NO control in front of them.**"
  Breakdown: unprotected 7 · routed 6 · app-enforced 2 · not-an-endpoint 12 · inconclusive 1.
- **Three defects (found by code review + re-execution):**
  * **Ordering bias in branch logic.** Original script checked "is the response HTML?" before checking
    "is the status 401/403". This app renders 401 as `text/html`, so app-enforced endpoints were
    silently miscounted as "not an endpoint". This under-counted app-side controls (2 reported; actual 7).
  * **Regex misses Angular template-literal paths.** Pattern matched only quote-delimited literals
    (`"…"`, `'…'`), missing paths like `${host}/rest/languages` (backtick and template syntax). The
    denominator of 16 was an artifact of the regex, not the true application surface.
  * **Unauthorized claim on the "unprotected" label.** Original framing: "7 endpoints have NO control in
    front of them" = an authorization finding. Code review read all 7 response bodies (scope: unrouted +
    openly answering): every one is public-by-design content (product catalogue, delivery tiers, CAPTCHA,
    security-question text, photo wall, CTF hints). **Zero authorization gaps were found.** The measurable
    property is gateway routing coverage, not protection.
- **Data (re-measured with corrected instrument):**
  Deterministically discovered 33 paths; 32 are real routes (one SPA fallback discarded).

  | | count |
  |---|---|
  | real endpoints (app proved they exist) | **32** |
  | traverse gateway (`routed=true`) | 6 |
  | app-enforced (return 401/403 directly) | **7** |
  | open (answer 2xx, non-HTML) | 14 |
  | undetermined (HTTP 500 — route exists but GET-without-params errors) | 11 |
  | absent (404 or SPA fallback) | 1 |
  | **crossing: unrouted AND openly answering** | **8** |

  No authorization gaps. Routed-vs-unrouted crossing: 8 routes accept connections directly without
  traversing the gateway — a statement about **gateway coverage** (no logging, ACL, rate-limiting applies),
  explicitly NOT an authorization finding.

- **Conclusion (corrected):** The instrument defects combined to produce both a false denominator (16
  vs. 32) and a mislabeled bucket (public content claimed as unprotected auth gaps). The corrected
  measurement shows: **zero authorization gaps found; the measurable property is gateway routing coverage
  (6 of 32 real routes traverse it), not protection.** Decision 0025 captures the posture of the 6 routed
  non-public endpoints (1 gateway-only-enforcement + 1 app-withholds-payload + rest in scope). This
  measurement captures the coverage bound and proves the application does enforce authorization itself on
  7 of the 26 unrouted endpoints.

## CORRECTION to E8 (2026-07-26) — **the "missing authz finding" was a measurement artefact**

A red-team of the follow-on plan tested the same endpoint against two origins and found:

```
http://127.0.0.1:13000/rest/admin/application-version   -> 200   (app, direct publish)
https://127.0.0.1:18443/rest/admin/application-version  -> 401   (Kong, the enforcement point)
```

**Kong enforces the ACL. The prober was hitting the app's direct publish port and therefore probing
AROUND this project's own authorization layer** (decision 0010: "authorization enforcement is Kong
ACL"). E8's reported finding was not a vulnerability — it was the wrong origin.

**Corrected result: E8 found ZERO real missing-authz vulnerabilities.**

Fixed: the oracle now judges at the **enforcement point** and uses the app origin only to refine
severity —
`gateway 401/403` → control present; `gateway 401/403 + app 2xx` → **gateway-only-enforcement**
(informational: no defence in depth, a direct-to-app bypass would work, but the control exists);
`gateway 2xx` → the real finding. If the gateway is unreachable the run **errors** rather than judging
from the app origin, so this class of mistake cannot silently recur.

**Newly visible limitation (honest):** Kong only routes a narrow configured set, so most baseline
endpoints return 404 through it — the enforcement-point oracle can only judge endpoints the gateway
actually knows about. That bounds the technique far more tightly than E8 implied.

**Lessons.** (1) *Probe at the enforcement point, never around it* — a prober that bypasses the control
under test manufactures findings. (2) The negative controls did not catch this: they were all
"expected-protected" endpoints, and none tested whether the prober was even talking to the layer that
enforces. A control-plane sanity check belongs in every runtime oracle. (3) Three of this lab's
strongest claims have now been corrected by adversarial review (0021's significance, 0023's magnitude,
and now E8's finding) — the pattern is consistent: **self-review does not catch the errors that matter.**

## E13 — the marginal cost and marginal yield of the LLM layer, measured on a live run (2026-07-26)

- **Hypothesis:** enabling the LLM layer on the Supervisor syndicate finds vulnerabilities the
  deterministic path misses, and the added cost is worth that yield.
- **Method:** the same target through the same gateway, run twice per configuration via
  `agent/supervisor.py`: once with `--no-llm` (deterministic floor) and three times with
  `--model sast-grok45` (LLM enabled). FinOps accounting (`agent/finops.py`) reports cost, tokens,
  latency and errors per run; findings and exploit proposals are read from the run result. No mocks —
  real gateway, real model, real target.
- **Data:**

  | run | LLM | calls | tokens | cost (est) | latency | findings | proposals |
  |---|---|---|---|---|---|---|---|
  | deterministic floor | off | 0 | 0 | $0.0000 | ~0s | 11 | 5 |
  | llm-1 | grok-4.5 | 3 | 6971 | $0.0498 | 36.2s | 11 | 5 |
  | llm-2 | grok-4.5 | 3 | 6862 | $0.0481 | 34.4s | 11 | 5 |
  | llm-3 | grok-4.5 | 3 | 7023 | $0.0506 | 33.8s | 11 | 5 |

  LLM cost is stable at **$0.048–$0.051 per run** (~7k tokens, ~35s, 0 errors across all three).
- **Conclusion:** on this target the LLM layer produced the **same 11 findings and 5 exploit proposals**
  as the $0 deterministic path, for **+$0.05 and +35s per run**. Marginal yield: zero. This is the same
  result the whole research programme keeps reaching (E7, 0020, 0021, 0022) — every clean win came from
  adding deterministic tooling, never from adding a model. The honest business-case framing is therefore
  not "AI finds more"; it is "AI narrates and triages at a bounded, measured cost, on top of a
  deterministic engine that does the finding." The single-target scope is a hard limit: this measures
  marginal yield on one app the models have memorised, not on a client's private code, where the LLM's
  contribution is untested (and, per the cancelled Phase 3, not answerable on this target).

## E14 — PREREGISTRATION (written before measuring, per `docs/research-protocol.md` Stage 2)

Registered 2026-07-26 01:35 +07. **Nothing below was measured before this text was committed.**

- **Why this experiment (Stage 1).** Decision 0021's "+0.069, deterministic prior WINS" was withdrawn in
  prose and amended to a tie (+0.013 [−0.006, +0.035]) under leave-one-repo-out. But on 2026-07-26 the
  committed instrument `rank_baselines.py` still printed
  `+0.069 95%CI=[+0.045,+0.095] -> deterministic prior WINS`. The repo's reproducibility artifact
  contradicts the repo's own published correction. Either the withdrawal or the instrument is wrong, and
  the business case depends on knowing which.
- **Hypothesis (falsifiable).** The +0.069 is a **leakage artifact of splitting by row**. Under a split
  grouped by repository, the deterministic CWE prior does **not** reliably beat the LLM annotator: the
  95% CI of ΔAUC will **include 0**.
- **Falsifying result.** If the grouped 95% CI **excludes 0 in favour of the prior**, the hypothesis is
  wrong, 0021's original claim stands, and the withdrawal must itself be retracted.
- **Primary outcome.** ΔAUC = AUC(cwe_prior) − AUC(llm), evaluated **leave-one-repo-out**, with a 95% CI
  **bootstrapped over repositories** (the grouping unit), 2000 resamples, seed fixed.
- **Secondary (exploratory, labelled as such).** The row-split ΔAUC recomputed on identical data, to
  quantify the leakage gap directly.
- **Method.** The committed baseline `annotate-baseline-260725.json` records **no repo field** — the
  grouping unit was discarded when it was written, which is why no grouped analysis was ever
  reproducible from it. Repo labels are reconstructed deterministically: `run_annotate.py` appends one
  row per Bandit finding in strict `sorted(os.listdir(REPOS))` order and drops nothing (`recall: 1.0`),
  so replaying Bandit per repo yields per-repo offsets into the row list.
- **Validity check (abort condition).** The reconstruction is accepted **only if** the replay produces
  exactly 1764 rows AND the `(cwe, severity)` sequence matches the committed rows position-for-position.
  If it does not match, the run is **aborted and reported as failed** — no analysis proceeds on an
  unverified join.
- **Power / limits stated in advance.** n = 1764 findings (234 TP / 1530 FP) across ~63 repos. The
  bootstrap is over repos, so the effective n is the **repo count, not the row count** — intervals will
  be materially wider than the row-split ones, which is the entire point.
- **Note on what the scores are.** The LLM annotation is memoized on `(rule_id, cwe, severity)`, so both
  the LLM score and the CWE prior are functions of code-derived facts, not of the repo. The leakage
  under test is therefore specifically in **fitting the prior** on rows sharing a repo with the held-out
  rows.

## E14 — RESULT: the withdrawal was right, and the correction had never reached the code

Run 2026-07-26 against the preregistration above. **Hypothesis confirmed. Abort condition did not fire.**

- **Reconstruction validity:** the replay reproduced **1764 rows across 61 repos** and matched the
  committed `(cwe, severity)` sequence position-for-position, so the row→repo join is verified, not
  assumed.
- **PRIMARY (leave-one-repo-out, bootstrap over 61 repos):**
  AUC(cwe_prior) = 0.826, AUC(llm) = 0.814 →
  **ΔAUC = +0.012, 95% CI [−0.006, +0.035] — a TIE.** The CI includes 0, so the hypothesis that the
  original result was a leakage artefact stands.
- **EXPLORATORY (row split, the withdrawn method, identical data):** +0.069.
- **The leakage was worth +0.057 AUC.** That is the measured price of splitting by row instead of by
  repository — the prior learns a repo's answer key and is then graded on that same repo.

This independently reproduces decision 0021's corrected value (+0.013 [−0.006, +0.035]) — and does so
**from committed artefacts for the first time**.

### Two defects this experiment exposed

1. **The correction had never reached the instrument.** `rank_baselines.py` kept its row-level
   `random.shuffle` split and, on 2026-07-26, still printed
   `+0.069 95%CI=[+0.045,+0.095] -> deterministic prior WINS` — the exact claim 0021 withdrew. For a
   day the repo's reproducibility artefact contradicted the repo's own published correction, and
   anyone re-running it would have reproduced the retracted claim with a confident verdict.
2. **The grouping unit had been discarded.** `annotate-baseline-260725.json` records no repo field, so
   the corrected leave-one-repo-out number was **not reproducible from committed data at all** — it
   existed only as prose. E14 recovers the labels deterministically and now commits the grouped result.

**Root cause of both:** the runtime stack has DD1–DD10 pinning every correction with a negative
control; the SAST measurement stack had **zero test coverage**, so nothing held its corrections in
place. Fixed: `tests/sast-measurement-test.sh` (SM1–SM6, 7/0) now pins the grouped split, the abort-on-
unverified-join, the retraction label, the interval-driven verdict, the measured leakage gap, and a
repo-wide check that no superseded figure survives in the measurement stack.

**Propagated (correction-propagation law, `docs/research-protocol.md` §4):** the decisions index
carried both retracted figures as live findings; 0023's headline contradicted its own correction table;
0024's title rested on the withdrawn "larger half". All four corrected in this commit.

**What this does NOT show.** The tie is between a *supervised* prior (needs labels) and a *zero-shot*
LLM. On cost and reproducibility the prior remains preferable; on accuracy there is no measured
difference. And this is a ranking task — a role the architecture already forbids the LLM to hold as a
gate, so it adds no evidence about the unmeasured generative role (protocol §8, open question 1).

## E15 — PREREGISTRATION (written before measuring, per `docs/research-protocol.md` Stage 2)

Registered 2026-07-26 01:45 +07. **Nothing below was measured before this text was committed.**

- **Why (Stage 1).** Decision 0022's "**union recall +44% relative, at no precision cost**" is the
  load-bearing *positive* claim in the Week-12 business case (pillar 1: cheap continuous detection). It
  has the same structure as the claim E14 just demolished: a **bare micro-averaged point estimate,
  pooled over all rows, with no interval and no grouping**. If it is fragile, the business case must be
  restated *before* it is presented, not after.

- **Stage 5 check changes the hypothesis.** Asking the protocol's mandated question — *what would this
  instrument print if my hypothesis were false?* — exposes that the obvious test is a **tautology**:
  union recall is **monotonically ≥** single-engine recall, because taking the union of two finding sets
  can only add matches, never remove them. "Is the gain > 0" therefore **cannot** come out negative and
  is not a hypothesis at all. Testing it would be measurement theatre. The honest questions are about
  **magnitude, stability and cost**:

- **H1 (magnitude).** The +44% relative gain is **not** driven by a small number of outlier repositories:
  bootstrapped over repositories, the 95% CI on the relative gain **excludes +10%** (i.e. the gain is
  robustly more than marginal).
  *Falsified if* the lower bound falls below +10%, which would make "+44%" an artefact of pooling.

- **H2 (breadth).** The **median repository** shows a positive absolute recall gain, i.e. the benefit is
  broad rather than concentrated.
  *Falsified if* the median per-repo gain is 0 — which would mean most repos get nothing and a few
  carry the headline.

- **H3 (the "no precision cost" clause).** Published precision moved 0.1327 → 0.1378. The claim is that
  adding an engine costs no precision. *Falsified if* the repo-bootstrapped CI on the precision delta
  excludes 0 **in the negative direction**. Note in advance: a *positive* point estimate here is
  **not** evidence of improvement unless its CI also excludes 0 — the same error E14 punished.

- **Primary outcomes.** (a) relative recall gain (union vs bandit) with 95% CI bootstrapped over
  **repositories**; (b) median per-repo absolute recall gain; (c) precision delta with repo-bootstrapped
  CI.
- **Secondary (exploratory).** Per-engine unique contribution; how many repos gain nothing.
- **Power / limits stated in advance.** 63 repos, 1790 real vulnerabilities. Bootstrap is over repos, so
  effective n is the **repo count**. Repos contribute very unequally (some hold many vulns, some few), so
  intervals are expected to be wide — that is the honest picture, not a defect.
- **Corpus caveat, recorded now, not after.** RealVuln's repos are `vc-*-seeded-v2-*` with
  `llm_generated_corpus: true` — an **LLM-seeded** corpus, not organic CVEs. Whatever this measures, it
  measures on synthetic-seeded code; that bound travels with the number (protocol §5).
- **Abort condition.** If the re-run's pooled totals do not reproduce the committed baseline
  (63 repos, 1790 real vulns, bandit tp=234, semgrep tp=212, union tp=336), the environment has drifted;
  report the drift and do **not** silently publish different numbers under the old claim's name.

## E15 — RESULT: decision 0022's "+44%" SURVIVES the grouped re-audit, with one caveat it had hidden

Run 2026-07-26 against the preregistration above. **All three hypotheses hold. Abort condition did not
fire** — the per-repo run reproduced the committed baseline exactly (63 repos, 1790 real vulns,
bandit tp=234, semgrep tp=212, union tp=336), so no environment drift.

| hypothesis | result | verdict |
|---|---|---|
| **H1 magnitude** — gain not driven by outlier repos | relative recall gain **+43.6%**, 95% CI **[+31.5%, +58.4%]** (bootstrap over 63 repos) | **HOLDS** — lower bound far above the preregistered +10% |
| **H2 breadth** — median repo benefits | median per-repo absolute recall gain **+0.0357** | **HOLDS** |
| **H3 no precision cost** | precision delta **+0.0051**, 95% CI **[−0.0136, +0.0173]** | **HOLDS** — CI includes 0, so no measurable cost |

**This is the first load-bearing claim to survive a grouped re-audit.** It matters that the protocol
does not only demolish: applied to 0021 it confirmed a retraction, applied to 0022 it confirms the
claim and now attaches an interval it never had. "+44%" was a fair summary of +43.6%.

**The caveat the point estimate hid: 22 of 63 repos (35%) gain nothing at all.** The union equals
Bandit alone on those. So the honest statement is *corpus-level*: adding a second engine raises recall
by ~44% relative **across a portfolio**, but for **any individual application it may add exactly
nothing**. A per-app promise was never supported by this measurement; only the portfolio-level one is.
This is precisely the nuance micro-averaging erases, and it is now published with the claim.

**H3 stated carefully.** The precision delta is positive (+0.0051) but its interval spans 0, so the
correct reading is "**no measurable precision cost**", *not* "precision improves". Reading a positive
point estimate as improvement is the exact error that produced the retracted +0.069 — the instrument
prints this warning next to the number so it cannot be misread later.

**Bound that travels with the number.** RealVuln's repos are `vc-*-seeded-v2-*` with
`llm_generated_corpus: true` — an **LLM-seeded** corpus, not organic CVEs. This measures multi-engine
complementarity on synthetic-seeded Python. Generalisation to organic code is untested.

## E16 — PREREGISTRATION: the FIRST measurement of the LLM in a GENERATIVE role

Registered 2026-07-26 01:55 +07. **Nothing below was measured before this text was committed.**

- **Why (Stage 1).** This lab's headline is that every measured AI-vs-deterministic comparison ended
  with AI losing, tying, or being unanswerable. A meta-analysis of our own 13 experiments found that
  claim is **structurally incomplete**: every role we ever measured (judge, verifier, ranker) is a
  **verdict/gate role the architecture forbids the LLM to hold anyway**. The **generative** role —
  *propose candidates, let deterministic code dispose* — has **zero measurements**, because Phase 3 was
  cancelled at the red-team gate. Until it is measured, "AI loses" is an overclaim, and the Week-12
  business case rests on it.
- **The opening.** Decisions 0022–0024 measured that SAST is ~0% recall on **absence-of-control**
  classes: CWE-307 (no auth-attempt limit), CWE-639 (IDOR), CWE-200 (info exposure), CWE-862/306
  (missing authz/authn). The corpus holds **357 such vulnerabilities across 185 distinct files**. This
  is the one place where a generative proposer cannot be beaten by the deterministic baseline, because
  **the deterministic baseline is approximately zero there**. Any correct proposal is a net gain.
- **Hypothesis (falsifiable).** Given source code, an LLM proposing `(line, CWE)` candidates achieves
  **recall > 0.15 on absence-class vulnerabilities**, at a precision distinguishable from indiscriminate
  flagging — i.e. materially better than the deterministic engines' ~0% on the same files.
- **Falsifying result.** Recall ≈ 0, **or** a flag rate on clean negative-control files statistically
  indistinguishable from the flag rate on vulnerable files. The latter would mean the model flags
  everything and its "recall" is an artefact of guessing, not detection.
- **Primary outcomes.** (a) recall over absence-class ground truth using the **existing deterministic
  matcher** (`run_spike.match`: file + CWE + line±10, claim-once); (b) precision; (c) the flag rate on
  negative-control files.
- **Controls (Stage 4).**
  - **Negative-control files** — files with **zero** ground-truth vulnerabilities, sampled from the same
    repos and mixed in indistinguishably. Without these, recall alone is uninterpretable.
  - **Deterministic control arm** — Bandit + Semgrep on the identical file set, so the comparison is on
    the same inputs, not against a remembered number.
  - **Fail-closed** — a model call that errors or returns unparseable output is recorded as a
    **non-answer**, never silently dropped and never counted as a correct abstention.
- **No LLM in the verdict path.** The model emits candidate strings only. Scoring is done entirely by
  the committed deterministic matcher. The model never sees ground truth and cannot mark its own work.
- **Contamination — stated in advance, not after (protocol §5).** RealVuln is **public** and its repos
  are `vc-*-seeded-v2-*` with `llm_generated_corpus: true`, i.e. **LLM-seeded**. A positive result here
  therefore measures **capability and memorisation together and inseparably**, and must be reported that
  way. This experiment can establish a **ceiling**, never transfer to a client's private code.
- **Power / limits.** Bounded sample (tens of files, not 185) for cost and time. This is explicitly a
  **first look**, powered to detect a large effect only; a near-zero or near-total result is
  interpretable, a marginal one is not, and will be reported as inconclusive rather than spun.
- **Abort condition.** If the deterministic control arm finds a *non-trivial* number of absence-class
  vulns on these files, the premise ("deterministic baseline ≈ 0 here") is wrong and the experiment is
  reframed before any LLM comparison is published.

## E14 — REVISED after independent adversarial review (protocol Stage 8)

The Stage-8 reviewer reproduced every E14 number exactly, then broke the conclusion. **The review was
right, and it was right about my work, not someone else's.** Report:
`docs/plans/reports/2026-07-26-e14-adversarial-review.md`.

### What was wrong: E14 fixed the split and inherited the micro-averaging

E14 corrected 0021's row-level split — but then pooled every scored row into **one** ranking and took a
single AUC, which is exactly the micro-averaging the protocol names as the *other* half of the scar. I
verified the reviewer's measurement independently: **only 1.9%** (6,862 of 358,020) of the TP/FP pairs
that pooled AUC ranks are **within-repository**. 98% of the "result" was answering *"is repo A's true
positive scored above repo B's false positive?"* — a question that only matters if every client's
findings land in one shared queue.

**Both estimands, same data, same LOSO scores:**

| estimand | question it answers | prior | LLM | delta | 95% CI | verdict |
|---|---|---|---|---|---|---|
| **MACRO (per application)** — **PRIMARY** | rank findings *within* one app | 0.820 | 0.725 | **+0.095** | **[+0.063, +0.128]** | **prior WINS** |
| micro (pooled) — secondary | one global cross-client queue | 0.826 | 0.814 | +0.012 | [−0.006, +0.035] | tie |

**Why macro is primary:** the stated user is a pentest team working **one client application at a
time** (Week-12 §1). Nobody triages client A's SQL injection against client B's false positive in a
single queue. The deployment-realistic ranking is *within* an application. Choosing the estimand is a
product decision, so it is stated in the open rather than buried in a pooling step.

### The corrected story — three revisions deep

1. **Published:** +0.069, "prior WINS" — **invalid method** (row split leaks repo identity).
2. **E14:** tie — **valid method, wrong estimand** (pooled, 98% cross-repo pairs).
3. **Now:** **+0.095 [+0.063, +0.128], prior WINS on the per-application estimand**, and a tie on the
   pooled one.

So 0021's *original direction* was right — **for the wrong reason and with the wrong magnitude**. That
is not vindication of the original work: a row-split result that happens to point the same way as a
correct analysis is still an invalid result. But the honest conclusion today is that **where labels
exist, the free deterministic prior does beat the LLM annotator at per-application triage.**

### Two further corrections from the same review

- **The "+0.057 leakage" was ~2.5× overstated.** It subtracted a 61-fold grouped run from a 50/50 row
  split, confounding **grouping** with **training-set size** (882 vs ~1735 rows) and evaluation set. At
  matched fold count and train size, with only grouping differing: **+0.022**. The instrument now
  computes it this way (`matched_grouping_effect`).
- **The bootstrap understates both intervals.** It resamples pre-computed LOSO scores without refitting
  the prior per resample. A fully nested procedure widens the pooled interval to roughly [−0.015,
  +0.056] — still spanning 0, so the *micro* tie survives. Recorded as a stated caveat in the artefact
  rather than silently left in.

### Test-quality defects the review found in my own guards

- **SM4 was tautological** — it recomputed `lo <= 0 <= hi` and asserted it equalled `verdict`, which the
  code *defines* as that expression. It could not fail. Replaced with empirical assertions: both
  estimands must be published, the primary must be the per-application one, macro must exclude 0, micro
  must span 0, and the artefact must not be older than the instrument (a freshness check that did not
  exist).
- **SM6's guard was file-wide** — it exempted any file whose text contained the word "ties", which a
  docstring in `rank_baselines.py` did. Now line-scoped: a win verdict must be interval-guarded **on its
  own line**, or explicitly marked as a historical/retracted quotation.

**Lesson for the protocol.** Stage 8 caught what Stages 1–7 could not, including in an experiment
written specifically to demonstrate the protocol. Fixing a known flaw (the split) does not immunise an
analysis against the *neighbouring* flaw (the estimand). And a test written by the same person who
wrote the instrument can be vacuous in exactly the way the instrument is wrong.

## E16a — RESULT: capability is present; machine-readable conformance is absent (5 models, 3 formats)

Measured 2026-07-26 while building E16's instrument. Reported separately because it is a finding in its
own right, and because it **forced a redesign** of the experiment that produced it.

**Method.** A synthetic canary file with two blatant, textbook absence-of-control defects (an
`/api/account/<id>` endpoint with no authentication and no ownership check; an `/api/login` with no rate
limit or lockout) was sent through the provenance gateway with the source labelled `target-derived`, as
the contract requires. Three output formats were requested, and one assistant-prefill trick tried:

| output format requested | result |
|---|---|
| `FINDING: line=<n> cwe=<n>` | never emitted |
| JSON array `[{"line":…,"cwe":…}]`, "no prose, no code" | never emitted |
| "reply must BEGIN with exactly one word: YES or NO" | never emitted |
| assistant-prefill with `[` to force JSON continuation | ignored |

| model alias | behaviour | found the planted defects? |
|---|---|---|
| `sast-grok45` | emits a remediation patch | **yes** (IDOR + brute force) |
| `sast-sol` | emits prose findings | **yes** |
| `sast-terra` | emits prose findings | **yes** |
| `sast-gpt55` | asks what is wanted ("Send goal: review, fix patch, tests…") | n/a — did not engage |
| `openai-gpt5-mini` | prose + remediation patch | **yes** |

**Finding: 5 model aliases × 3 output formats × 1 prefill = zero format compliance, while every model
that engaged identified both planted defects correctly.** The models are not refusing on provenance
grounds — the earlier prediction — and they are not incapable. They will not be told what shape to
answer in.

**This is decision 0018's non-conformance, now confirmed in the generative role.** 0018 measured that
SAST-tuned models emit prose instead of a verdict tag when asked to *judge*. The same holds when asked
to *propose*. It generalises across the whole model shelf available to this project.

**Instrument-validity note (the important part).** The very first E16 smoke run reported
`RECALL=0.000`. That was **not** a result: the harness had truncated a file mid-function, the model
replied *"File truncated mid-`serialize_dispute`. What needed?"*, and the parser scored the
clarification as a non-answer. Published unexamined, it would have become "the generative role fails" —
a false negative caused entirely by my own harness. What caught it was asking the protocol's Stage-5
question (*what would this instrument print if the hypothesis were false?* — the answer was "0.000,
same as if it were true") and then adding the positive control the protocol mandates and I had omitted.
**A canary is not paperwork; it is the difference between a finding and an artefact.**

**Scope bound.** This is measured through *this* deployment: five aliases on the configured router. Our
own gateway injects no style directive (verified in `infra/litellm/config.yaml` — only redaction and
spotlighting callbacks at `pre_call`), so the terseness originates upstream. The honest claim is about
this model shelf, **not** about LLMs in general.

**Consequence for the architecture.** A structured "AI proposes, tools dispose" pipeline cannot be
built on these models by asking for structure. The disposal layer must consume the models' **native
output** — which is what E16 does: the model answers in prose, and a deterministic classifier over
absence-of-control vocabulary decides. No model is ever consulted about its own output.

## E16b — RESULT: the generative role points positive, but this sample cannot establish it

Run 2026-07-26, 24 vulnerable files + 16 clean controls, `sast-grok45`, positive control passed.

| | flagged | n | rate |
|---|---|---|---|
| files containing an absence-class vulnerability | 5 | 24 | **0.208** |
| clean control files (no ground-truth vulnerability) | **0** | 16 | **0.000** |

Non-answers (model asked a question or returned a refactor instead of a review): **4/24** vulnerable,
**8/16** clean.

| analysis | separation | 95% CI (bootstrap) | Fisher exact, one-sided |
|---|---|---|---|
| **ITT** (non-answer = not flagged; no post-selection) | **+0.208** | [+0.042, +0.375] | **p = 0.065** |
| engaged-only (conditions on the model answering) | +0.250 | [+0.100, +0.450] | p = 0.158 |

### Verdict: INCONCLUSIVE — as preregistered, not as an afterthought

The preregistration committed in advance that "a near-zero or near-total result is interpretable, a
**marginal one is not, and will be reported as inconclusive rather than spun**." This is marginal, so
that is the verdict.

The bootstrap CI excludes 0, but **it should not be trusted here**: the clean arm has a **zero cell**
(0/16), so every bootstrap resample of that arm returns 0 and the interval reduces to the vulnerable
arm's spread — it cannot represent the uncertainty in a 0/16 estimate. Fisher's exact test is the
appropriate instrument for these counts, and it gives **p = 0.065**: not significant at 0.05. Reporting
the bootstrap interval as the headline would have been exactly the "positive point estimate read as a
win" error that produced the retracted +0.069.

The engaged-only analysis is reported but is **the weaker one**, because the non-answer rate differs
sharply by arm (17% vulnerable vs 50% clean), so conditioning on engagement is post-selection on a
variable correlated with the outcome.

### What is nevertheless worth recording

1. **Specificity was perfect: 0 of 16 clean files drew a false absence-class claim.** The model never
   invented a missing control where ground truth says there is none. That is the failure mode the
   negative controls existed to catch, and it did not occur.
2. **Sensitivity is low: ~21% of vulnerable files flagged.** Even taken at face value this is a weak
   detector, not a replacement for anything.
3. **The direction is positive** — the first AI role in this lab's history to point that way rather than
   losing outright. But direction is not a result.

### Bounds that travel with this number

- **File-level, not line-level.** Line-level structured output was unobtainable (E16a), so per-line
  precision is unmeasured.
- **Contamination.** RealVuln is public and its repos are `llm_generated_corpus: true`. A positive
  result mixes capability with memorisation inseparably and **cannot** be claimed to transfer to a
  client's private code.
- **Single model, single run, n=40.**

### Consequence for the lab's headline claim

The Week-12 claim "every measured AI-vs-deterministic comparison ended badly for AI" remains true **for
gate roles**, which is where it was measured. For the generative role the honest status is now
**"unresolved, direction positive, underpowered"** — not a win, and no longer an untested blank.

## E17 — PREREGISTRATION: powered confirmatory replication of E16b (written before measuring)

Registered 2026-07-26 02:50 +07. **Nothing below was measured before this text was committed.**

- **Why.** E16b was underpowered (Fisher p = 0.065) and is therefore recorded as inconclusive. An
  underpowered result must be either powered up or abandoned — not quoted. This is the powered version.
- **Status of E16b.** Treated as **exploratory**. It supplied the effect-size estimate used to size this
  run and **its files are excluded from this one**, so E17 is an independent replication on a disjoint
  sample rather than an extension of the same data.
- **Sample size, fixed in advance by simulation, not by looking at results.** Assuming p(flag |
  vulnerable) = 0.21 and a conservative p(flag | clean) = 0.03, one-sided Fisher at α = 0.05:
  n = 60 vulnerable + 40 clean gives **83% power** (40/25 gives 59%; 80/50 gives 92%). **60 + 40 is the
  committed sample.**
- **Hypothesis.** The model flags absence-class vulnerable files at a higher rate than clean control
  files. **Primary test: one-sided Fisher exact on the ITT table** (a non-answer counts as *not
  flagged*, so nothing is post-selected). **α = 0.05.**
- **Falsifying result.** p ≥ 0.05, or a clean-file flag rate that rises to meet the vulnerable rate.
- **Committed in advance, to foreclose optional stopping:** the run happens **once**, at the stated
  size, and the outcome is published **whatever it is**. The sample will not be extended if the result
  lands just above 0.05, and it will not be truncated if it lands below.
- **Secondary (exploratory, labelled):** engaged-only rates; per-CWE breakdown; non-answer rates by arm.
- **Instrument frozen.** The prompt, the prose classifier and the positive control are **unchanged**
  from E16b and are not to be touched during this run. The classifier was audited against synthetic
  cases before E16b was read; touching it now, after seeing E16b's numbers, would be tuning on results.
- **Bounds unchanged and restated:** file-level only (E16a); one model; and RealVuln is public and
  `llm_generated_corpus: true`, so any positive mixes capability with memorisation and does not
  transfer to private code.

## E17 — RESULT: the preregistered replication REJECTS the null (p = 0.024)

Run 2026-07-26 exactly as preregistered: 60 vulnerable + 40 clean files, **disjoint** from E16b's
sample, instrument frozen, positive control passed, one run only.

| | flagged | n | rate |
|---|---|---|---|
| files containing an absence-class vulnerability | 10 | 60 | **0.167** |
| clean control files | **1** | 40 | **0.025** |

| analysis | separation | one-sided Fisher | verdict |
|---|---|---|---|
| **ITT — the preregistered primary** (non-answer = not flagged) | **+0.142** | **p = 0.0237** | **null REJECTED at α = 0.05** |
| engaged-only (secondary, exploratory) | +0.218 | p = 0.0112 | agrees |

Non-answers: 20/60 vulnerable (33%), 9/40 clean (23%).

**This is the first statistically significant result in this project's history in which the LLM arm
wins.** It is preregistered, powered in advance by simulation (83%), replicated on a sample disjoint
from the exploratory run, gated by a positive control, scored by a deterministic classifier audited
before any data was seen, and tested by the statistic named before the data existed. Both the primary
and secondary analyses agree in direction and significance.

### What it does and does not mean

**Does:** in the **generative role** — propose candidates, let deterministic code dispose — an LLM
carries **real signal about absence-of-control vulnerabilities**, the class where pattern SAST is
measured at ~0–6.8% recall (0022–0024). It is not flagging indiscriminately: **only 1 of 40 clean files
drew a false absence-class claim**.

**Does not:**
- **It is a weak detector.** 16.7% of vulnerable files flagged. Six in seven are missed.
- **It is file-level.** Line-level structured output was unobtainable from any of five models (E16a), so
  per-line precision is unmeasured and no one should imagine a ranked line list.
- **It is contaminated by construction.** RealVuln is public and its repos carry
  `llm_generated_corpus: true`. This measures capability and memorisation **inseparably**, and
  therefore **cannot** be claimed to transfer to a client's private code. Establishing transfer needs a
  target the model cannot have seen — which this lab does not currently have.
- **One model, one corpus, one language.**
- **A third of answers are non-answers**, which is a usability fact, not a detection fact.

### Consequence: the lab's headline claim is now formally narrowed

Before tonight: *"every measured AI-vs-deterministic comparison ended with AI losing, tying, or being
unanswerable."* That was true of every role ever measured — and every role ever measured was a
**verdict/gate** role the architecture forbids the LLM to hold anyway.

After E14/E15/E16/E17 the honest statement is two-part:

1. **In gate roles — judging, verifying, ranking — the deterministic method wins or ties.** Repeatedly,
   and now with the estimand argued in the open (0021: prior wins +0.095 per application).
2. **In the generative role, on the class deterministic tooling structurally cannot see, the LLM adds
   measurable signal** — significant, small, specificity-strong, and bounded by contamination.

That is a materially different and more useful claim than "AI loses", and it is the first time this
project has been able to say where AI *does* belong on evidence rather than on architecture alone.

### E17 — SELF-AUDIT, same day: the mechanism is NOT established

Before publishing E17 anywhere, its stored prose was checked against ground truth to answer a question
the preregistration did not ask: when the model flagged a vulnerable file, **did it name the class the
ground truth actually records for that file?**

**Of the 10 flagged vulnerable files, 6 named the ground-truth class and 4 flagged the file for
something else entirely** — a `pickle.loads` RCE, an undefined `encrypt`, a broken session cookie, an
email-existence leak. Real problems, in files that do contain an absence-class vulnerability, but **not
that vulnerability**.

| criterion | rate (vulnerable vs clean) | one-sided Fisher |
|---|---|---|
| **file flagged at all — the PREREGISTERED primary** | 10/60 = 0.167 vs 1/40 = 0.025 | **p = 0.024, significant** |
| **model named the ground-truth class** (post-hoc, exploratory) | 6/60 = 0.100 vs 1/40 = 0.025 | **p = 0.149, NOT significant** |

**Both are reported, and neither is discarded.** The preregistered test was committed before the data
existed and stands as the primary; a post-hoc criterion that happens to fail does not get to retract it,
or preregistration would mean nothing. But an exploratory analysis that **undercuts** the primary must be
reported with equal prominence, or the reporting is selective — which is the same sin as p-hacking
wearing better clothes.

**What this forces the conclusion to become:**

- **Established:** the model flags files containing absence-class vulnerabilities **more often than clean
  control files**, significantly, with strong specificity (1 of 40 clean files).
- **NOT established:** that it is detecting *the absence-of-control vulnerability itself*. The effect is
  consistent with the model reacting to files that are **generally messier** — and 4 of 10 flags
  demonstrably did exactly that.

The earlier sentence "the LLM carries real signal **about absence-of-control vulnerabilities**" is
therefore **too strong and is withdrawn**. The supported claim is narrower: *it discriminates files that
contain them from files that do not; the mechanism is unresolved.*

Resolving it needs a design this experiment did not have: either line-level attribution (blocked by
E16a — no model would emit structure), or a control arm of files that are **messy but contain no
absence-class vulnerability**, which would separate "reacts to mess" from "detects absent controls".
That is the next experiment, not a footnote to this one.

### E17 — the preregistered DETERMINISTIC CONTROL ARM, and what it restores

The preregistration promised a deterministic control arm — "Bandit + Semgrep on the identical file set"
— and the pivot to prose classification had **dropped it**. That omission was caught while writing up
the result, and the arm was run before publishing anything.

**Bandit + Semgrep flag an absence-class CWE in 0 of the 60 vulnerable files.** Not approximately zero.
Zero. The premise decisions 0022–0024 established holds exactly on this sample.

| comparison, identical 60 vulnerable files | rate | one-sided Fisher |
|---|---|---|
| LLM flagged the file at all vs deterministic | 10/60 = 0.167 **vs 0/60** | **p = 0.00065** |
| **LLM named the ground-truth class** vs deterministic | 6/60 = 0.100 **vs 0/60** | **p = 0.0137** |

**This is the comparison the preregistration actually specified, and it changes the reading of the
self-audit above.**

The self-audit withdrew the mechanism claim because, under the strict class-attribution criterion, the
LLM-vs-**clean-files** comparison was not significant (p = 0.149). But clean files are the wrong
comparator for the mechanism question: they differ from vulnerable files in *many* ways, so "the model
reacts to messier files" survives as a confound.

The deterministic control arm removes that confound **by design** — both arms see the **same 60 files**.
File messiness, size, style and repo are all held fixed; only the detector changes. On that comparison
the LLM beats the deterministic engines **even when required to name the ground-truth class**
(6/60 vs 0/60, p = 0.0137).

**Corrected conclusion — narrower than the first draft, broader than the withdrawal:**

- **Established:** on absence-of-control classes, the LLM identifies vulnerabilities that Bandit and
  Semgrep together identify **not once in 60 files**, and does so naming the correct class in 6 of them.
  This is the first measured capability in this project that deterministic tooling cannot supply at all.
- **Still not established:** that it does so *reliably*. 6 of 60 is a 10% class-attributed hit rate.
  Four of ten flags named a different issue than ground truth, and a third of all calls were
  non-answers.
- **Unchanged:** contamination. RealVuln is public and `llm_generated_corpus: true`, so capability and
  memorisation remain inseparable and transfer to private code is unproven.

**Process note.** A claim was withdrawn on one analysis, then partially restored by a control arm that
the preregistration had required and the implementation had silently dropped. Both movements are in the
record, in order. The lesson is not that the withdrawal was wrong — it is that **a comparison is only
as good as its comparator**, and the preregistration had named the right one before the data existed.

### E15 — adversarial review (Stage 8): the +43.6% survives; the precision clause is qualified

Report: `docs/plans/reports/2026-07-26-e15-adversarial-review.md`. The reviewer re-ran the instrument
over all 63 repos and reproduced the artefact **byte-identically** except its timestamp.

**Attacks that failed to break H1** (each with the reviewer's numbers):
- **Matching order.** Reversing the union concatenation to `semgrep + bandit` gives union_tp = **336**,
  identical; **0 of 63** repos are order-sensitive, despite **1,245** ground-truth pairs sitting within
  ±10 lines in the same file. The claim-once matcher is order-stable here.
- **CWE wildcard** in `match()` (a finding with `cwe is None` can match any in-file entry): only 3 of 675
  Semgrep findings and **0 of 1764** Bandit findings. Excluding them moves the gain 0.4359 → 0.4316.
- **Denominator.** `real` cancels exactly — `336/234 − 1 = 0.4359`. H1 is denominator-free by construction.
- **Micro vs macro estimand** — the attack that overturned E14. Macro per-application gain is
  **+40.7% [+26.7%, +59.2%]**. Here the two estimands **agree**; they did not for E14.
- **The 22/63 zero-gain caveat verified**, with the honest mechanism: 17 are genuine redundancy, 3 found
  nothing matching, 2 found nothing. **0** are artefacts of a small vulnerability denominator.

**H3 "no measurable precision cost" survives only as the conservative reading — two qualifications:**

1. **The union's findings denominator is a raw concatenation**, so a vulnerability caught by both engines
   counts as 2 findings for 1 true positive. Deduplicating on `(file, cwe, line)` removes 185 duplicates,
   loses **no** true positives, and moves the delta to **+0.0164, CI [+0.0014, +0.0274]** — an interval
   that **excludes 0**, flipping the instrument into its own "precision measurably IMPROVES" branch. The
   direction is favourable, but the verdict is **not robust to a defensible denominator choice**, so
   "no measurable cost" is the claim that should be made and "improves" must not be.
2. **The clause holds against Bandit only.** Against **Semgrep alone** (precision 0.314) the union is
   **−0.176**. Any statement about precision must name its baseline; the Week-12 report now does.

**Guard-rail defects the review found in my own tests** (protocol §10: review the tests, not the result):
- **The abort condition was blind to the drift most able to falsify H3.** `EXPECTED` pinned true
  positives but not **findings counts**, yet precision is `tp/findings`. A ruleset update adding findings
  that match no ground truth leaves every TP untouched, passes the abort, and moves H3 — *downward*,
  because it enlarges the union denominator. Fixed: all eight totals are pinned.
- **SM7's `lo > 0` was vacuous.** A union only adds matches, so `union_tp ≥ bandit_tp` per repo and no
  resample can be negative (the reviewer measured 0 of 2000; minimum +0.234). The preregistration had
  committed to **+10%** as the threshold that could actually fail; the test now asserts that.
  (`plo <= 0 <= phi` is *not* vacuous — the dedup variant fails it.)
- **SM7 had no freshness check.** Added; it caught the stale artefact immediately on the next run.

**This is the second vacuous assertion found in tests I wrote**, after SM4. Both were written by the
author of the code they guard, and both failed in the direction that flattered the result.

## E18 — PREREGISTRATION: is it detection, or reaction to messy code? (written before measuring)

Registered 2026-07-26 03:25 +07. **Nothing below was measured before this text was committed.**

- **Why (Stage 1).** E17 established that the model flags files containing absence-of-control
  vulnerabilities more than clean files, and beats a deterministic arm that scores 0/60. Decision 0027
  records the mechanism as **unresolved**: the effect is equally consistent with the model reacting to
  code that is **generally messier**, and 4 of 10 flags demonstrably named a different issue than ground
  truth. This experiment is the control arm that separates the two, and it is the one 0027 specified.
- **The discriminating control.** Arm B = files whose ground truth records **real vulnerabilities, but
  exclusively of PRESENCE classes** (CWE-79 XSS, 798 hardcoded credentials, 312 cleartext storage, 321
  hardcoded key, 434 unrestricted upload…). 249 such files exist. They are **objectively defective code**
  — as messy as arm A — while containing **none** of the class under test. Clean files could not
  separate these hypotheses; these files can.
- **Hypothesis.** The model's absence-class flagging is **class-specific**, not mess-driven: it flags
  arm A (absence-class vulnerable) at a higher rate than arm B (messy, no absence-class vulnerability).
- **Falsifying result.** Arm B's absence-class flag rate is statistically indistinguishable from arm A's
  → the effect is reaction to mess, and decision 0027's central claim must be narrowed again.
- **Primary test.** One-sided Fisher exact, α = 0.05, on ITT counts (non-answer = not flagged).
  **Arm A is E17's already-measured 10/60** — the instrument is deterministic (temperature 0) and
  **frozen**, so re-running it would only consume budget. **Arm B: n = 80, sampled fresh.**
- **Power, stated honestly in advance.** By simulation: if arm B truly flags at 0.03 → **84% power**; at
  0.05 → 69%; at **0.08 → only 41%**. So this run is powered to detect a **large** specificity gap and is
  **underpowered for a moderate one**. Committed in advance: if the result lands in the middle it is
  reported **inconclusive**, exactly as E16b was, and not spun either way.
- **What makes the classifier fair here.** It counts **only absence-of-control vocabulary** and
  deliberately excludes presence-class terms. So if the model looks at an arm-B file and correctly says
  "XSS on line 5", that scores **clean** — which is the correct behaviour, not a miss. Arm B therefore
  tests exactly what it should: does the model *manufacture* absence-class language when shown defective
  code that has no absent control?
- **Instrument frozen.** Prompt, classifier and positive control unchanged from E16b/E17.
- **Bounds unchanged:** file-level; one model; public LLM-seeded corpus, so contamination applies to both
  arms equally (which is a reason this *internal* comparison is more trustworthy than any absolute rate).

### E17 — framing correction: the deterministic zero is STRUCTURAL, so it is not a horse race

A Stage-5 check on my own headline comparison, run after publishing it: **can these engines emit an
absence-class CWE at all?**

Across 12 corpus repositories Bandit + Semgrep emit **33 distinct CWE classes** — CWE-703, 259, 79, 327,
502, 78, 89, 400, 330 and others. **Not one is absence-class.** The 0/60 is therefore **not a sampling
outcome**; it is the configured rulesets having **no rule for this class in the first place**, which is
precisely what decisions 0022–0024 measured and named "structurally blind".

**Consequence for how E17 must be stated.** Fisher's exact test assumes two arms that could each have
scored. Quoting "6/60 vs 0/60, p = 0.0137" implies a **contest between two detectors**, and it is not
one: the deterministic arm cannot produce a positive under any sample. The p-value is arithmetically
valid but rhetorically inflated, and reporting it as a head-to-head win would be the kind of framing
this lab keeps having to retract.

**The honest claim is a capability statement, not a superiority statement:**

> The deterministic layer has **no rule that can express** an absent control. The LLM, given the same
> file, names the ground-truth absence class in **6 of 60 files (10%)**. This is **capability addition
> where the deterministic layer has none**, not a better score on a shared task.

That is a *cleaner* finding than the horse-race framing, and it is the one decision 0027 should rest on.
The genuinely two-sided comparison in this experiment remains **E17's preregistered primary** — vulnerable
files vs clean control files, 10/60 vs 1/40, **p = 0.024** — where both arms could have scored and the
model discriminates. *(Superseded: the classifier fixes recorded further down this log — "access control
looks properly implemented" being scored as a finding, quoted code supplying the absence word — moved
this to **9/60 vs 0/40, p = 0.0078**. The corrected pair is what decision 0027 cites. Both are kept
because the direction of the correction matters: fixing the instrument moved the number in the arm that
suited us, and a reader should be able to see that.)* E18 (running) tests whether that discrimination is class-specific or mess-driven.

**Retained without change:** the ~10% hit rate, the file-level granularity, the 33% non-answer rate, and
the contamination bound. None of those depend on this framing.

## E18 — RESULT: the effect is CLASS-SPECIFIC, not a reaction to messy code (p = 0.010)

Run 2026-07-26 exactly as preregistered: arm B = 80 files with real ground-truth vulnerabilities of
**presence classes only** (XSS, hardcoded credentials, cleartext storage, insecure cookie, unrestricted
upload…) and **no** absent control. Instrument frozen, positive control passed, arm A reused from E17
(deterministic, temperature 0).

| arm | what the files contain | absence-class flag rate |
|---|---|---|
| **A** (E17) | an absence-of-control vulnerability | **10/60 = 0.167** |
| **B** (new) | real vulnerabilities, but **none** absence-class | **3/80 = 0.037** |
| clean controls (E17) | no ground-truth vulnerability at all | 1/40 = 0.025 |

| comparison | separation | one-sided Fisher |
|---|---|---|
| **A vs B — the preregistered primary** | **+0.129**, 95% CI [+0.029, +0.237] | **p = 0.0103 → null REJECTED** |
| **B vs clean** — is defective code enough on its own? | +0.012 | **p = 0.59 → no difference** |

**The second row is the one that settles it.** Arm B files are objectively defective — every one carries
a real, ground-truth-confirmed vulnerability — yet the model produces absence-of-control language about
them at **the same rate as it does for files with nothing wrong at all**. Mess does not trigger it. The
presence of an actual missing control does.

**Decision 0027's central open question is therefore resolved in favour of detection.** The rival
explanation — "the model just reacts to code that looks bad" — predicts arm B ≈ arm A. Measured, arm B ≈
**clean files** instead, and differs from arm A at p = 0.010.

### What this does not settle

- **Residual confound worth naming:** absence-of-control vulnerabilities live disproportionately in
  request handlers and endpoint code, while XSS and hardcoded credentials live in templates, models and
  utilities. So arm A and arm B may differ in **file role** as well as in vulnerability class, and part
  of the discrimination could be "this is an endpoint" rather than "this endpoint lacks a control".
  Separating those needs endpoint-handler files that are correctly protected as a third arm — the next
  control, not a footnote to this one.
- **Sensitivity is unchanged and low:** 16.7% of files with an absent control are flagged.
- **File-level, one model, and the corpus is public + LLM-seeded** — capability and memorisation remain
  inseparable, so transfer to private code is still unproven.

### The three-arm picture, which is the honest summary

| files | flag rate |
|---|---|
| absence-class vulnerability present | **0.167** |
| defective code, no absent control | 0.037 |
| nothing wrong | 0.025 |

The model discriminates the **class**, not the **defectiveness**. That is a materially stronger statement
than E17 could make on its own, and it is the first mechanism claim this lab has been able to support
rather than withdraw.

## E19 — PREREGISTRATION: capability or memorisation? (written before measuring)

Registered 2026-07-26 04:00 +07. **Nothing below was measured before this text was committed.**

- **Why (Stage 1).** Every generative-role result (E16b, E17, E18) rests on RealVuln, which is **public**
  and `llm_generated_corpus: true`. Decision 0027 therefore carries a bound it cannot currently discharge:
  capability and **memorisation** are inseparable, so nothing may be promised for a client's private code.
  This is the single largest limit on the most important finding this lab has produced. It is testable.
- **Method — semantics-preserving mutation, the standard contamination mitigation.** The **same** files
  are re-presented with every surface cue a memoriser keys on replaced, and the semantics untouched:
  user-defined function/class/argument/local names → `fn_N`/`Cls_N`/`v_N`; route literals → same shape,
  generic segments; the filename shown in the prompt → `module.py`. **Unchanged:** control flow, calls,
  decorators, imports, framework APIs, and the *absence* of any authorization/ownership/rate-limit check
  — nothing is added or removed, so the ground truth is preserved by construction.
- **Instrument validation, done before preregistering.** 53 of 60 arm-A files mutate with **structure and
  imports provably preserved** (AST node-type profile identical **and** every import byte-identical). A
  validation run caught the mutator renaming a module path — `from django.core.paginator import Paginator`
  → `django.core.v_21` — which the node-count check could not see; imports are now protected and asserted
  separately. The 7 files that fail to mutate are excluded, not forced.
- **Design: PAIRED.** The comparison is the **same 53 files**, original vs mutated. The original verdicts
  are already measured (E17, frozen instrument, temperature 0): **10/53 = 0.189** flagged. Only the
  mutated arm is new. Pairing removes file-to-file variation entirely.
- **Hypothesis.** Detection is **reasoning**, not recall: the flag rate **survives** mutation.
- **Primary test.** **McNemar exact, one-sided**, on the 53 discordant/concordant pairs, α = 0.05, testing
  whether mutation **reduces** detection. A significant drop ⇒ memorisation contributes materially, and
  decision 0027 must be narrowed hard.
- **Honest statement about a null result, made in advance.** Failing to detect a drop is **not** proof of
  equivalence. If no significant drop is found, the reportable claim is bounded by the **confidence
  interval on the paired difference**: only if that interval excludes a large drop is this evidence
  against pure memorisation. If the interval is wide, the verdict is **inconclusive**, exactly as E16b
  was, and decision 0027's contamination bound stays in force unchanged.
- **Instrument frozen.** Prompt, prose classifier and positive control unchanged from E16b/E17/E18.
- **Residual limits acknowledged in advance.** Mutation removes *surface* identity, not *structural*
  identity: a model could still recognise a distinctive control-flow shape. So this test can **weaken**
  the memorisation explanation but cannot fully eliminate it; only a genuinely unseen target can, and the
  lab does not have one.

### E19 — confound identified DURING the run, before any result was read

The mutation changes **two** things at once, and only one of them is memorisation:

1. **identity** — identifiers and route literals (the memorisation cue this experiment targets);
2. **filename** — the prompt shows `module.py` instead of e.g. `accounts/views.py`.

A filename like `views.py` or `routes/transaction_routes.py` is not only identity; it is **semantic
context**. It tells a reviewer this file handles requests, which is exactly where absent controls live.
Stripping it removes a legitimate reasoning cue, not just a recall cue.

**Consequence, stated before the numbers are known — the two branches are not symmetric:**

- **If the mutated rate HOLDS:** the confound does not weaken the conclusion. Both an identity cue *and*
  a semantic cue were removed and detection survived anyway, which is *stronger* evidence for reasoning
  than the experiment was designed to produce.
- **If the mutated rate DROPS:** the result is **ambiguous** between "memorisation was doing the work"
  and "the filename was doing the work", and a third condition is required to separate them — the
  **original, unmutated code shown under a generic filename**. That control is specified now so it
  cannot be improvised later to suit whichever answer arrives.

Recorded at 04:15 +07, while the run was still in flight and no output had been read.

## E19 — RESULT: detection survives full surface anonymisation (paired difference exactly 0.000)

Run 2026-07-26. Positive control passed. 53 paired files, same instrument, temperature 0.

| condition | flagged |
|---|---|
| original source, real filename (E17) | **10/53 = 0.189** |
| identifiers + routes + filename anonymised | **10/53 = 0.189** |

| statistic | value |
|---|---|
| paired difference (mutated − original) | **+0.0000** |
| 95% CI (bootstrap over the 53 pairs) | **[−0.094, +0.094]** |
| discordant pairs | **3 lost, 3 gained** |
| McNemar exact, one-sided | **p = 0.656 — no significant drop** |

### Read against the preregistered rule, not against hope

The preregistration stated in advance that a null result is **not** proof of equivalence and that the
claim would be **bounded by the interval**. Applying that rule:

- **Excludes a 10-point drop** (a >50% relative collapse of a 0.189 base rate). **Pure surface
  memorisation is ruled out**: had the model been recalling these files, replacing every identifier,
  route literal and the filename should have destroyed most detections. It moved the rate **not at all**.
- **Does not exclude a 5-point drop** (~26% relative). A *moderate* memorisation contribution remains
  possible and is **not** claimed to be absent.

### The flip pattern is the qualitative evidence

Mutation **lost 3** detections and **gained 3** — on **different files** (`bad_mvc.py`, `auth.py`, `auth.py`
lost; `main.py`, `partner_console.py`, `patient_operations.py` gained). Recall-driven detection predicts
something else entirely: the memorised files should have gone dark, systematically, with nothing
appearing to replace them. An even trade across different files is what a **noisy detector operating on
semantics** looks like — it also shows detection sits near a decision threshold, which is consistent with
the low 19% sensitivity.

### The confound named before the result now works in our favour

E19 stripped the **filename** as well as the identifiers, and a name like `views.py` is semantic context,
not just identity. The pre-recorded branch analysis said: *if the rate holds, the confound strengthens
the conclusion.* It held. Detection survived the removal of an identity cue **and** a legitimate
reasoning cue simultaneously. **The filename-only control (`run_filename_control.py`, built before this
result was read) is therefore not required** — it was specified for the drop branch, which did not occur.
It stays in the repo, unrun, as the record of a control prepared before the answer was known.

### What is now established, and what is still not

- **Established:** the generative-role effect is **not surface memorisation**. It survives complete
  anonymisation of identifiers, route literals and filename with the paired difference at exactly zero.
- **Not established — and explicitly preregistered as beyond this design:** *structural* memorisation.
  Mutation changes names, not shapes; a model could still recognise a distinctive control-flow topology.
  Only a genuinely unseen target settles that, and this lab does not have one.
- **Unchanged:** 19% sensitivity, file-level granularity, one model, one language.

**Consequence for decision 0027.** Its contamination bound was "capability and memorisation are
inseparable". That is now too strong: they have been **partially separated**, and the surface-recall
explanation is excluded. The bound narrows to *structural* familiarity and to the absence of a
genuinely unseen target — a materially smaller claim than the one the decision shipped with.

## E20 — PREREGISTRATION: file ROLE or missing CONTROL? (written before measuring)

Registered 2026-07-26 04:25 +07. **Nothing below was measured before this text was committed.**

- **Why (Stage 1).** E18 showed the effect is class-specific rather than a reaction to messy code, and
  named the one confound it could not remove: **absence-of-control vulnerabilities live
  disproportionately in request handlers**, while XSS and hardcoded credentials live in templates, models
  and utilities. So arm A and arm B differed in **file role** as well as in vulnerability class, and part
  of the discrimination could be the model recognising "this is an endpoint" rather than "this endpoint
  lacks a control". This is the control that separates them, and decision 0027 already specified it.
- **Design — hold FILE ROLE fixed, vary only the control.** Both arms are **endpoint-handler files**
  (`views.py`, `routes/*.py`, `/api/*`, `handlers.py`, `controllers/*`, `urls.py`, `endpoints.py`,
  `resources.py`):
  - **Arm A′** — handler files **with** an absence-class vulnerability. Already measured in E17 with the
    frozen instrument: **7/28 = 0.250**.
  - **Arm C** — handler files **without** any absence-class vulnerability: **all 42** that exist in the
    corpus (27 carry some other real vulnerability, 15 carry none). Not sampled — this is the whole
    population, so there is no sampling choice to get wrong.
- **Hypothesis.** The model responds to the **missing control**, not the file role: arm A′ is flagged at a
  higher rate than arm C.
- **Falsifying result.** Arm C's rate is statistically indistinguishable from arm A′ ⇒ the model is
  reacting to *endpoint-ness*, and **decision 0027's mechanism claim must be narrowed to "recognises
  request-handling code"**, which would be a far weaker and much less useful finding.
- **Primary test.** One-sided Fisher exact, α = 0.05, on ITT counts (non-answer = not flagged).
- **Power, stated in advance and not flattering.** With n_C = 42 against arm A′ at 0.250: **87%** power if
  arm C truly flags at 0.02, **71%** at 0.05, **42%** at 0.10. Powered for a large gap only. **Committed:
  a mid-range result is reported inconclusive**, as E16b was.
- **Instrument frozen.** Prompt, prose classifier, positive control and the transport-failure-vs-negative
  canary rule are unchanged from E16b/E17/E18/E19.
- **Known limits carried forward:** file-level granularity, one model, and arm A′ is reused rather than
  re-run (deterministic instrument, temperature 0), which is stated rather than hidden.

### E20 — arm C composition, verified before the result

Checked while the run was in flight, so the arm's validity is on record independently of what it
returns: the 42 files are **28 `views.py`, 10 `routes/*`, 3 `api/*`, 1 `handlers.py` — and zero
`urls.py`**. That matters because Django's `urls.py` is routing *configuration*, not handler logic, and
would rarely contain an authorization check whether or not one was required. Had arm C been dominated by
config files it would have been a weaker comparator wearing the right filename. It is not: both arms are
genuine request-handling code.

**Limit that applies to arm C and is worth stating with it:** RealVuln's ground truth is not exhaustive,
so a handler here could genuinely lack an authorization check that the corpus simply never labelled. If
that happens, the model flagging it is a **true** positive being scored as a false one — which biases
**against** the hypothesis. A positive result is therefore safe from this; a null result would be
partially explainable by it.

## E20 — RESULT: the missing CONTROL drives it, not the file role — but the test is fragile

Run 2026-07-26. Positive control passed. Both arms are endpoint-handler files; only the presence of an
absent control differs.

| arm | files | flagged |
|---|---|---|
| **A′** handlers **with** an absence-class vulnerability (E17, same instrument) | 28 | **7 = 0.250** |
| **C** handlers **without** one (whole population, not a sample) | 42 | **3 = 0.071** |

One-sided Fisher exact: **p = 0.0418 → null rejected at the preregistered α = 0.05.** Non-answers 14/42
(33%), in line with every other arm.

### The fragility, stated before anything is concluded from it

| arm C | rate | p | verdict |
|---|---|---|---|
| 2/42 | 0.048 | 0.018 | significant |
| **3/42 (observed)** | **0.071** | **0.042** | **significant** |
| 4/42 | 0.095 | 0.081 | **not** significant |

**One additional flagged file would flip this result.** It clears the preregistered threshold and is
reported as clearing it — moving the goalposts after seeing p = 0.042 would be exactly the manoeuvre
preregistration exists to prevent — but a single-observation margin is not a sturdy finding, and quoting
"p < 0.05" without this table would misrepresent how much weight it can carry.

### Why the conclusion is nevertheless reasonably held

The weight is not in this p-value. It is in **three independent controls converging**, each removing a
different rival explanation, each preregistered, each with its own comparator:

| rival explanation | control | result |
|---|---|---|
| "it reacts to messy code" | E18 — defective files, no absent control | 3/80 = 0.037, indistinguishable from clean (p = 0.59) |
| "it recalls a public corpus" | E19 — full surface anonymisation, paired | rate **unchanged**, 10/53 → 10/53, diff 0.000 |
| "it recognises endpoint code" | E20 — handlers in both arms | 0.250 vs 0.071, p = 0.042 |

Three different confounds, three different designs, no result pointing the other way. A marginal p in one
of them is much less troubling when the other two are not marginal at all — and the effect size here
(3.5×) is consistent with E18's, not a knife-edge artefact of one test.

### What is still not closed

- **Structural familiarity.** E19 changed names, not control-flow shapes. Untested.
- **A genuinely unseen target.** Still does not exist for this lab, so full transfer stays unproven.
- **Sensitivity is unchanged and low** (~19–25%), and a third of calls are non-answers.
- **Ground-truth exhaustiveness**, noted before the run: an arm-C handler could genuinely lack a control
  the corpus never labelled, which would make one of those 3 flags a true positive scored as a false one
  — that bias runs *against* the hypothesis, so it does not threaten this direction.

## E21 — PREREGISTRATION: how much of the low sensitivity is non-answers? (written before measuring)

Registered 2026-07-26 04:25 +07. **Nothing below was measured before this text was committed.**

- **Why (Stage 1).** Sensitivity is ~19–25%, low enough that the generative-role finding is a research
  result rather than a usable capability. But **a third of all calls are non-answers** — the model asks a
  question or returns a refactor instead of a review. A non-answer is not a negative detection; it is a
  **missing measurement**. If those resolve on a second attempt, sensitivity has been systematically
  **under-measured** by the instrument, and the fix is engineering rather than research.
- **Hypothesis.** A material fraction of non-answers resolve into a substantive verdict on one retry, so
  the effective flag rate with non-answers resolved is **higher** than the published 10/60.
- **Method.** Take every arm-A file whose E17 verdict was `non-answer`. Retry each **exactly once**, with
  the **frozen instrument** — same prompt, same classifier, same temperature. Take whatever comes back.
- **The anti-p-hacking rule, committed in advance.** Retries are permitted **only** for `non-answer`
  results, and **exactly one** per file. A file that returned a substantive `clean` is **never** retried,
  because retrying negatives until they turn positive is precisely the manoeuvre this rule forbids.
  Whatever the single retry returns is final, including `non-answer` again.
- **Primary outcome.** (a) proportion of non-answers that resolve; (b) the recomputed arm-A flag rate
  with resolved verdicts folded in, reported **alongside** the original, never replacing it.
- **What this cannot do.** It **does not revise E17's published result.** E17's preregistered comparison
  stands exactly as reported; this measures a property of the *instrument*, not of the hypothesis, and
  any recomputed rate is labelled as such.
- **Falsifying result.** Few or no non-answers resolve ⇒ the non-answer rate is a stable property of the
  model on this task, sensitivity is genuinely ~19%, and no engineering fix is available at the prompt
  level.
- **Bounds carried forward:** file-level, one model, contaminated corpus (narrowed by E19).

## E21 — RESULT: the low sensitivity is REAL, not an artefact of non-answers

Run 2026-07-26. Every arm-A file whose E17 verdict was `non-answer`, retried **exactly once** with the
frozen instrument, taking whatever came back.

| | count |
|---|---|
| arm-A non-answers | 20 of 60 (33%) |
| of those, **file missing on disk** — never shown to the model | **1** |
| genuinely asked and unanswered | 19 |
| **resolved on one retry** | **10 of 19 = 53%** |
| …resolved to `clean` | **9** |
| …resolved to `flagged` | **1** |
| still `non-answer` after retry | 9 |

| rate | value |
|---|---|
| published arm-A (unchanged, still the result of record) | 10/60 = **0.167** |
| with non-answers resolved once | 11/60 = **0.183** |

### The hypothesis was half right and practically wrong

The preregistered hypothesis was that sensitivity had been **under-measured** because non-answers are
missing measurements rather than negative detections. Half of that is true: **53% of non-answers do
resolve on a single retry**, so the instrument was leaving real verdicts on the table.

But the recovered verdicts are almost entirely **`clean`** — 9 of 10. Folding them in moves sensitivity
by **1.6 percentage points**, from 0.167 to 0.183. There is no meaningful sensitivity hiding in the
non-answer bucket.

**Conclusion: ~19% sensitivity is a genuine property of the model on this task, not an instrument
artefact.** When the model does answer about a file containing an absent control, it usually says the
file is fine. Four in five are missed for real, and **no retry-level engineering fix recovers them**.
This closes the open question in the direction that constrains the finding rather than flattering it.

### Two secondary observations

- **9 of 19 non-answers persisted through the retry**, so roughly half the non-answer rate is a *stable*
  behaviour on those particular files, not transient noise. The model repeatedly declines to review
  certain files, which is a usability property worth knowing before anyone builds on this.
- **One arm-A entry was never shown to the model at all** — `flag.txt`, listed in ground truth but absent
  from the corpus, and a text file rather than source. E17's harness caught the `OSError` and scored it
  as a non-answer, conflating "the file could not be read" with "the model declined". Fixed in the
  instrument; magnitude is 1 file in 60 (published rate 0.167 → 0.169 on the corrected denominator), so
  **no conclusion changes** — but the buckets now mean what their names say.

**E17's published result is unchanged and remains the result of record.** This measured a property of
the instrument, not of the hypothesis, exactly as the preregistration committed.

## E22 — PREREGISTRATION: is the instrument deterministic? (written before measuring)

Registered 2026-07-26 04:50 +07. **Nothing below was measured before this text was committed.**

- **Why.** A Stage-8 review of the E17–E21 chain measured **3 of 10 verdicts flipping** on identical
  inputs at `temperature=0.0`, and observed that **E19's "3 lost / 3 gained" is exactly what a ~30% flip
  rate predicts on 53 files at a 0.189 base rate — with or without mutation**. E19 and E20 both **reuse**
  E17 verdicts on an explicit determinism assumption. If that assumption is false, both are
  uninterpretable, and two claims published tonight must be withdrawn.
- **Hypothesis (the one being tested, not hoped for).** The instrument is **not** stable: repeated calls
  on identical input produce different verdicts at a materially non-zero rate.
- **Method.** 15 arm-A files, each queried **twice** in the same run with the frozen instrument
  (same prompt, same classifier, `temperature=0.0`). Compare verdicts **and** raw prose.
- **Primary outcome.** Verdict disagreement rate across the 15 pairs, with a 95% interval.
- **Secondary.** Whether the raw prose differs even when the verdict agrees — separating *model*
  non-determinism from *classifier* boundary effects (the classifier is a pure function, so any verdict
  flip must originate in the model).
- **Decision rule, committed in advance.** If the disagreement rate is materially above 0, then **E19's
  and E20's reuse of E17 verdicts is invalid**, both are downgraded to **inconclusive**, and the
  research log and decision 0027 are corrected accordingly — regardless of how much that costs the
  night's conclusions.

## E22 — RESULT: the instrument is NOT deterministic (36% of verdicts flip). E19 and E20 are DOWNGRADED

Run 2026-07-26. 14 arm-A files, each queried **twice in the same run**, identical input, frozen prompt
and classifier, `temperature=0.0`.

| measure | result |
|---|---|
| **verdict disagreement on identical input** | **5 of 14 = 36%** |
| **identical raw prose across the two calls** | **0 of 14 = 0%** |

Flips observed: `non-answer→flagged`, `non-answer→clean`, `clean→non-answer`, `flagged→clean`,
`clean→flagged`. The model never once returned the same text twice at temperature 0.

### Executing the preregistered decision rule

The preregistration committed, before the data existed: *"If the disagreement rate is materially above
0, then E19's and E20's reuse of E17 verdicts is invalid, both are downgraded to inconclusive, and the
research log and decision 0027 are corrected accordingly — regardless of how much that costs the night's
conclusions."* 36% is materially above 0.

**E19 (memorisation) → INCONCLUSIVE.** It paired *newly measured mutated* verdicts against *reused
original* verdicts, on the stated assumption that the instrument is deterministic. It is not. Its
headline "3 lost, 3 gained, paired difference exactly 0.000" is **precisely what a ~36% flip rate
produces on 53 files at a 0.19 base rate — with or without mutation**. The observation is fully
explained by instrument noise, so it cannot evidence anything about memorisation. **The claim "surface
memorisation is excluded" is WITHDRAWN.**

**E20 (file role) → INCONCLUSIVE.** Its arm A′ (7/28) is reused E17 verdicts, not a fresh measurement,
against a freshly measured arm C. With a 36% flip rate the two arms are not measured on comparable
footing, and the result was already fragile (one flag flips the p-value). **The claim "the missing
control drives it, not file role" is WITHDRAWN pending a re-run.**

### What survives, and why

**E17 and E18 are affected but not invalidated.** Both compare **two arms measured the same way in the
same run**; per-file noise inflates variance but does not systematically bias a between-arm comparison.
Re-scored with the corrected classifier they are *stronger* than published — E17 9/60 vs **0/40**
(p = 0.0078), E18 arm B **0/80** vs 9/60 (p = 0.0003). But their true intervals are **wider than
reported**, because every single-shot verdict carries a ~36% chance of differing on a re-run, and none
of the published intervals model that.

**E21 is corroborated rather than threatened**: 53% of non-answers changing on retry is the same
phenomenon measured from a different angle.

### The methodological lesson, which is bigger than these experiments

**`temperature=0` does not mean deterministic**, and this lab assumed it did — in a preregistration,
in two experimental designs, and in a protocol section on freezing instruments. Nothing in the
protocol required *measuring* run-to-run stability before building a paired design on top of it.

A single-shot LLM verdict is a **noisy measurement**, not an observation. Any design that reuses one
run's verdicts as fixed values is invalid. Repeated sampling — the same file queried k times, with the
verdict taken as a rate rather than a label — is mandatory for anything paired, and the protocol is
amended accordingly.

## E23 — PREREGISTRATION: memorisation, re-done under the determinism rule (written before measuring)

Registered 2026-07-26 05:20 +07. **Nothing below was measured before this text was committed.**

- **Why.** E19's conclusion was withdrawn because it paired *freshly measured* mutated verdicts against
  *reused* original ones, and E22 then measured the instrument flipping **36%** of verdicts on identical
  input. The question it asked — is the effect memorisation? — is still the most important open question
  about decision 0027, and it is still answerable. It just needs a design that survives a noisy
  instrument.
- **The design change.** Both arms are measured **fresh, in the same run, on the same files**: each file
  is queried once as **original source** and once as **anonymised source** (identifiers, route literals
  and filename replaced; semantics untouched). Nothing is reused from any earlier run.
- **The statistic changes too.** Per-file verdicts are **not** compared, because at a 36% flip rate an
  individual verdict carries no information. The comparison is between **aggregate flag rates**, where
  the same noise applies to both arms and therefore does not bias the difference. Reported with a
  bootstrap interval that reflects the observed instability rather than pretending to precision.
- **Hypothesis.** If detection were surface memorisation, anonymisation should **reduce** the aggregate
  flag rate. If it is reasoning, the two rates should be comparable.
- **Falsifying result.** A materially lower aggregate rate on the anonymised arm.
- **Power, stated honestly in advance.** ~53 files per arm at a ~0.17 base rate detects only a **large**
  reduction. A null result therefore **cannot** establish equivalence — it can only fail to find a
  collapse. If the interval is wide the verdict is **inconclusive**, and the contamination bound on 0027
  stays at full width. This is the same limit E19 had; the difference is that this design is not also
  invalidated by instrument noise.
- **Instrument.** Frozen prompt and positive control, with the **corrected classifier** (SM13) — which
  is a change from E19 and is stated as one, not hidden.

## Confound disclosed and quantified: our own gateway corrupts the source before the model sees it

Found by the Stage-8 review of the generative chain, verified and measured here. It applies to **every**
experiment in that chain and had been disclosed nowhere.

The egress guardrail's `_ASSIGNMENT` rule (`infra/litellm/guardrails/egress_redaction.py:107`) redacts
the value after any of `token|secret|password|passwd|api_key|client_secret|access_token|refresh_token|
private_key|access_key|authorization|cookie` followed by `:` or `=`. In a security corpus of web
application code, those are not secrets — they are **ordinary identifiers**. `password = request.form[...]`,
`token = ...`, `authorization: ...` are exactly what this code is made of.

**Measured on the experiment's own files:**

| arm | files containing redactable assignments | total occurrences |
|---|---|---|
| absence-class (arm A) | **22 of 59 = 37%** | **68** |
| clean controls | 13 of 40 = 32% | 33 |

The model's replies corroborate it directly — several say things like *"Redaction broke syntax"*.

**Direction of the bias, which is the part that matters:** roughly a third of files in both arms arrive
damaged, but arm A carries **twice the occurrences** (68 vs 33) because it *is* authentication and
authorization code. The arm expected to contain findings is the arm most corrupted. That biases
**against** every positive result in the chain, so:

- the surviving findings (E17 p = 0.0078, E18 p = 0.0003) hold **despite** a handicap, not because of a
  helpful artefact;
- the measured sensitivity (~15–19%) is an **underestimate** of what the model could do on intact
  source, and should be quoted as a floor rather than an estimate.

**This is a design tension, not a bug.** The gateway redacts on the egress path by policy (decision
0006, 0017) and that policy is correct for its purpose: preventing secret leakage to a third-party
model. It simply was never designed for a workload whose *legitimate content* is authentication code.
Any future run that needs intact source must either measure through a path exempt from `_ASSIGNMENT`
or report this handicap alongside the numbers. Reported here rather than quietly fixed, because
silently disabling a security control to improve a research number is precisely the trade this project
exists to refuse.

## E23 — RESULT: anonymisation does not reduce detection (valid design this time)

Run 2026-07-26. Positive control passed. 53 files, **both conditions measured fresh in the same run**,
aggregate rates compared — the design E19 should have had.

| condition | flagged |
|---|---|
| original source | 11/53 = **0.208** |
| identifiers + routes + filename anonymised | 14/53 = **0.264** |

**Aggregate difference (anonymised − original) = +0.057, 95% CI [−0.038, +0.151].**

### What this supports, stated at the strength the power allows

- **A collapse is excluded.** Surface memorisation predicts anonymisation *reducing* detection. It did
  not reduce it at all; the point estimate is slightly *higher*, and the interval's lower bound
  (−0.038) rules out even a 5-point drop. **Memorisation is not the primary driver.**
- **Equivalence is NOT established.** The interval is wide. A small memorisation contribution remains
  entirely possible and is not claimed to be absent. This is exactly the limit the preregistration
  named in advance, and it is not being quietly dropped now that the direction is favourable.

### Why this one counts and E19 did not

E19 asked the same question and got a suspiciously perfect null (paired difference exactly 0.000). That
null was an artefact: it compared *freshly measured* mutated verdicts against *reused* originals, and
E22 then measured the instrument flipping **36%** of verdicts on identical input — enough to produce
E19's entire result by itself. E23 measures **both arms fresh, in the same run**, and compares
**aggregate rates**, where identical noise applies to both arms and cannot bias their difference.
Per-file verdicts are never compared, because at this flip rate a single verdict carries no information.

### A free stability check fell out of it

The same 53 files have now been measured in the original condition three times across three runs:
**10, 10, 11 flagged** (0.189, 0.189, 0.208). Individual verdicts churn heavily — 36% flip — but the
**aggregate rate is stable to within ~2 points**. That is the empirical justification for the design
change: rates are measurable on this instrument, labels are not.

**Consequence for decision 0027:** the contamination bound narrows again, but by less than E19 claimed
and on evidence that survives its own instrument. *Surface* memorisation is not driving the effect;
*structural* familiarity remains untested; and no genuinely unseen target exists, so transfer to
private code is still unproven.

## E24 — PREREGISTRATION: file role, re-done under the determinism rule (written before measuring)

Registered 2026-07-26 05:25 +07. **Nothing below was measured before this text was committed.**

- **Why.** E20's conclusion was withdrawn: it compared a **reused** arm A′ (7/28, taken from E17) against
  a **freshly measured** arm C, which is invalid once E22 measured the instrument flipping 36% of
  verdicts. The question it asked is still open and still matters — it is the last confound standing
  between decision 0027 and a clean mechanism claim.
- **The design change, identical to the one that rescued E23.** **Both arms measured fresh, in the same
  run**, compared as **aggregate rates**. Nothing reused. Per-file verdicts never compared.
- **Arms** (file role held fixed — every file is an endpoint handler):
  - **A′** — handler files **with** an absence-class vulnerability, sampled fresh from the corpus.
  - **C** — handler files **without** one: all 42 that exist.
- **Hypothesis.** The model responds to the **missing control**, not to endpoint-ness: arm A′'s aggregate
  flag rate exceeds arm C's.
- **Falsifying result.** Comparable rates ⇒ the model is reacting to *endpoint-ness*, and decision 0027's
  mechanism claim narrows to "recognises request-handling code" — a much weaker and less useful finding.
- **Primary test.** One-sided Fisher exact on ITT counts, α = 0.05, plus a bootstrap interval on the
  difference so the result is not read from a p-value alone.
- **Power, stated in advance.** Comparable to E20's: powered for a large gap only. **A mid-range result
  is reported inconclusive**, and the confound stays open rather than being resolved by wishful reading.
- **Instrument.** Frozen prompt and positive control, **corrected classifier** (SM13) — the same one E23
  used, stated as a change from E20 rather than hidden.

## E24 — RESULT: the missing CONTROL drives it, not the file role (valid design this time)

Run 2026-07-26. Positive control passed. **Both arms measured fresh, in the same run**, with the
corrected classifier. File role is held fixed — every file in both arms is an endpoint handler.

| arm | flagged |
|---|---|
| **A′** handlers **with** an absence-class vulnerability | 9/40 = **0.225** |
| **C** handlers **without** one | 2/42 = **0.048** |

**Difference +0.177, 95% CI [+0.031, +0.326]. One-sided Fisher p = 0.0195 → null rejected.**

### Fragility, reported as it was for E20

| arm C | p | verdict |
|---|---|---|
| 1/42 | 0.006 | significant |
| **2/42 (observed)** | **0.020** | **significant** |
| 3/42 | 0.048 | significant |
| 4/42 | 0.095 | not significant |

**E24 tolerates two additional flags before crossing α; E20 tolerated one.** The interval also excludes
zero, which E20's presentation never established. This is a sturdier result than the one it replaces —
not because the effect grew, but because the design stopped comparing a reused arm against a fresh one.

### Why this counts and E20 did not

E20 measured arm C fresh and **reused** E17's verdicts for arm A′. Under an instrument that flips 36% of
verdicts (E22), those two arms were not on comparable footing, and the comparison was withdrawn. Here
both arms are drawn and measured in the same run. Nothing is reused.

**The file-role confound is closed again — this time on evidence that survives its own instrument.**
The model is responding to the **absent control**, not to the file being a request handler.

### Honest note on what changed between the two runs

Arm A′ moved from 7/28 = 0.250 (reused) to 9/40 = 0.225 (fresh), and arm C from 3/42 = 0.071 to
2/42 = 0.048 — the latter re-measured with the corrected classifier. Both moved modestly and in
different directions, which is what ~36% per-file instability looks like when it is averaged into a
rate. The conclusion is unchanged; the confidence in it is better founded.

## E25 — PREREGISTRATION: turn the detector on our OWN code (written before measuring)

Registered 2026-07-26 05:47 +07. **Nothing below was measured before this text was committed.**

- **Why.** Every generative-role result rests on RealVuln, which is public and LLM-seeded. The lab has
  repeatedly recorded "no genuinely unseen target exists" as the reason transfer is unproven. **That was
  wrong.** Sentinel's own source is real Python, written over the past weeks, and first pushed to a
  remote hours ago — comfortably after any plausible training cutoff for the model in use. It is the
  unseen target the lab kept saying it did not have.
- **What this can and cannot establish, stated first.** There is **no ground truth** for our own code, so
  **recall is unmeasurable** and no rate here is comparable to E17/E23/E24. What *is* measurable:
  1. does the detector produce **any** absence-class flags on genuinely unseen code, and
  2. when it does, are those flags **real** on manual adjudication?
  A finding here is a *capability demonstration on unseen code*, **not** a recall measurement, and it
  will be labelled that way.
- **Method.** Run the frozen instrument (corrected classifier, positive control gated) over Python files
  from `agent/` and `evaluation/` — the request-handling and probing surfaces most analogous to the
  corpus. Report every flag with its prose.
- **Adjudication.** Each flag is checked **by hand against the actual source**, and recorded as TRUE
  (a real missing control), FALSE (the control exists or the claim is wrong), or N/A (not applicable —
  e.g. the file is a test harness where the "missing" control is intentional). **Adjudications are
  written with the evidence, so a reader can disagree.**
- **The obvious bias, named in advance.** I am adjudicating findings on code this project wrote, which
  is the worst possible position from which to judge them fairly. Every adjudication therefore quotes
  the specific lines it rests on, and any flag I mark FALSE must be accompanied by the control that
  makes it false. If I cannot point at the control, it is not FALSE.
- **Falsifying result.** Zero flags on unseen code, or flags that are uniformly false on adjudication ⇒
  the capability does not appear outside the memorised corpus, and decision 0027's transfer bound
  hardens rather than narrows.

### E25 — why this target is genuinely unseen (checked before reading any result)

The claim needs to be exact, because "our own code" is not automatically unseen.

| fact | value |
|---|---|
| repository visibility | **public** (not private — so privacy is *not* the argument) |
| repository created | 2026-07-23 |
| `agent/` source first committed | 2026-07-24 |
| first push to any remote | 2026-07-25 |

**The argument is timing, not secrecy.** The scanned files were written on 2026-07-24 and reached a
remote on 2026-07-25 — **one to three days** before this measurement. A model already deployed and
answering requests cannot have trained on source that did not exist when its training ran. Public
visibility is irrelevant at this timescale; a crawler could not have collected, and a training run could
not have consumed, code this recent.

**Stated limits of that argument:**

- The exact training cutoff of the model in use is **not published**, so this rests on the general fact
  that a deployed model's corpus predates its deployment, not on a specific date.
- The model has **no retrieval or tool access** through this gateway — it receives only the message
  content — so it cannot fetch the repository at inference time.
- **Framework idioms are of course familiar.** Django, Flask and `requests` patterns are everywhere in
  training data. What cannot be familiar is *this code*: these functions, this structure, these controls.
  That is precisely the distinction E23 could not make (it removed *surface* identity from memorised
  files) and this target can: the code itself is new.

This makes E25 the transfer test the lab kept recording as impossible — with the caveat that it can
demonstrate **capability on unseen code**, never **recall**, because no ground truth exists for it.

### E25 — a construct-validity limit identified DURING the run, before any result was read

Sentinel's own `agent/` and `evaluation/` modules are **libraries, CLIs and probers — not a web
application**. The corpus files that produced every prior result are Django/Flask **request handlers**,
and the rubric asks specifically about *endpoints* with no authorization check, *objects fetched by
user-supplied id*, *authentication endpoints* with no rate limit.

**Most of those questions do not apply to this code**, because there are barely any endpoints in it.

**Consequence: the two outcomes are not symmetric, and that asymmetry is recorded now, not after.**

- **If it flags something and the flag survives adjudication:** that is a genuine capability
  demonstration on code the model provably cannot have seen. Informative, and the stronger branch.
- **If it flags nothing:** the result is **ambiguous and must not be read as a failure of transfer**.
  "No absence-of-control findings" is the *correct* answer for a library with no request handlers. It
  would be indistinguishable from "the capability does not transfer", and this design cannot separate
  them.

So E25 can **support** transfer but cannot **refute** it. A refutation would need unseen code of the
same *kind* as the corpus — a recently-written web application with hand-built ground truth, which this
lab still does not have. The preregistered falsifier ("zero flags ⇒ transfer bound hardens") is
therefore **withdrawn as unsound**: it would have drawn a conclusion this sample cannot support.
Withdrawn before seeing the data, not after.

## E25 — RESULT: zero flags on genuinely unseen code. Specificity transfers; sensitivity is untested.

Run 2026-07-26. Positive control passed. 25 files of Sentinel's own `agent/` and `evaluation/` source,
written 2026-07-24 and pushed 2026-07-25 — one to three days before this measurement.

| verdict | count |
|---|---|
| clean | 17 |
| non-answer | 8 (32%, in line with every other run) |
| **flagged** | **0** |

### The reading, constrained by the limit recorded before the data was seen

This is the **ambiguous branch**, and the pre-recorded analysis applies without amendment: our own
modules are **libraries, CLIs and probers, not a web application**, and the rubric asks about endpoints,
ownership checks on user-supplied ids, and authentication rate limits. **Most of those questions do not
apply to this code.** Zero findings is the *correct* answer for a library with no request handlers, and
is indistinguishable from a failure of transfer. The preregistered falsifier was withdrawn for exactly
this reason **before** the result was read.

**What may NOT be concluded:** that sensitivity transfers to unseen code. Untested here, because there
are no known positives to find. Also **not** concluded: that our own code is secure — that would require
ground truth this experiment does not have, and a scanner reporting nothing is not evidence of absence
(this project's own decision 0024 exists because of that fallacy).

### What it does establish: specificity transfers

The model examined 25 files of code it **cannot have trained on** and **manufactured no
absence-of-control findings at all**. That is the same behaviour measured on the corpus — 0 of 40 clean
files flagged (E17, corrected), 0 of 80 defective-but-not-absence files flagged (E18, corrected) — now
reproduced on genuinely unseen input.

It is a modest result and it is the *cheap* half of the pair: not inventing findings is easier than
finding real ones. But it is the half that a false-positive-averse pentest workflow cares about most,
and it is the first behaviour of this detector confirmed on code outside the memorised corpus.

### The honest scoreboard on transfer

| property | on the corpus | on unseen code |
|---|---|---|
| specificity (does not invent findings) | 0/40, 0/80 | **0/25 — transfers** |
| sensitivity (finds real absent controls) | ~19–22% | **untested — no ground truth** |

**Closing that gap needs what the lab still does not have:** a recently-written web application with
hand-built ground truth. Our own code was the unseen target the lab wrongly believed did not exist; it
is simply the wrong *kind* of code to measure recall on.

## E26 — PREREGISTRATION: sensitivity on unseen code with known ground truth (written before measuring)

Registered 2026-07-26 05:55 +07. **Nothing below was measured before this text was committed.**

- **Why.** E25 established that *specificity* transfers to unseen code but left *sensitivity* untested,
  because our own source is a library with no request handlers and therefore no known positives. The
  missing piece is a **recently-written web application with hand-built ground truth**. It can be built.
- **Method.** A small Flask application is authored **now**, in this session, as matched pairs of route
  modules: each pair implements the same feature, one variant **with** the required control and one
  **without**. Ground truth is exact by construction — I know what was planted, because I planted it.
  Provably unseen: the code will not exist until minutes before the measurement.
- **Primary outcome.** Sensitivity (fraction of planted-defect modules flagged) **and** specificity
  (fraction of controlled modules flagged), on code with zero possibility of memorisation.
- **THE BIAS THAT WORRIES ME MOST, named before writing a line of it.** I am authoring the test set, and
  an author who knows what the detector looks for can write defects in a **textbook shape** the model
  spots easily, inflating sensitivity into meaninglessness. Three constraints against that:
  1. **Matched pairs.** Vulnerable and controlled variants implement the *same* feature in the *same*
     style, differing only in the control. Anything that makes a defect easy to spot also appears in its
     control twin, where it must NOT be flagged.
  2. **No announcements.** No comment, name, or docstring may hint at the defect — no `# vulnerable`,
     no `unsafe_`, no `TODO: add authz`. Written as a competent developer writes code they believe is
     fine.
  3. **Realistic idiom.** Ordinary CRUD handlers with ORM calls, serializers and error handling — not
     four-line demonstrations.
- **What a high score would and would not mean.** High sensitivity here shows the model detects
  **planted defects of the kinds I chose, written in my style** — it does **not** generalise to a real
  client codebase, whose defects nobody designed to be findable. Stated now so it cannot be dressed up
  later.
- **Falsifying result.** Sensitivity near zero on planted defects ⇒ the capability does not transfer to
  unseen code, and decision 0027's central claim is confined to the memorised corpus.
- **Instrument frozen:** same prompt, corrected classifier, positive-control gate.

## E26 — RESULT: sensitivity DOES transfer to unseen code. The bottleneck is my classifier, not the model.

Run 2026-07-26 on four matched pairs authored minutes earlier (`evaluation/authored-unseen/`), shown
blind under shuffled `module_N.py` names. Positive control passed.

**Automated scoring: sensitivity 2/4, false positives 1/4.** Hand-adjudication — required by the
preregistration, and decisive here — gives a different and better-supported picture.

| file | truth | model's own words | automated | **adjudicated** |
|---|---|---|---|---|
| `invoices_a` | CWE-639 planted | *"IDOR in `detail`. Auth only. No org check. Any user reads any invoice by id."* | flagged | **HIT** |
| `exports_a` | CWE-862 planted | *"Authz hole. Any logged-in user dumps full org payroll + national_id + salary. Only checks auth, not role."* | flagged | **HIT** |
| `webhooks_a` | CWE-306 planted | *"**Missing webhook signature verify.** Trust boundary open. Anyone POST fake `invoice.paid` → free active status."* | **clean** | **HIT — classifier miss** |
| `reset_a` | CWE-307 planted | echoed the file back as a code block; no finding stated | clean | **MISS (genuine)** |
| `invoices_b` | control present | *"`page` unvalidated → 500; unbounded OFFSET DoS via slow SQL"* | **flagged** | **not an absence claim — classifier FP** |
| `exports_b` | control present | CSV-injection note | clean | ok |
| `reset_b` | control present | code-quality notes | clean | ok |
| `webhooks_b` | control present | error-handling note | clean | ok |

### The classifier, not the model, is the limiting factor

**`webhooks_a` is the important row.** The model detected the planted defect *precisely* — named the
missing signature verification, the trust boundary, and the exploit path. My classifier scored it
**clean**, because `_CONCEPT` has no term for **signature verification / HMAC / webhook authenticity**.
Verified directly: `_ABSENCE` matches ("Missing"), `_CONCEPT` does not.

**`invoices_b` is the mirror image.** The model made *no* absence-of-control claim — it reported a
validation/DoS issue — and the classifier counted it as a flag anyway.

**Adjudicated: model sensitivity 3/4, model false positives 0/4.** The model neither missed three
defects nor invented a finding on a control; the instrument mis-scored one in each direction.

### Consequence, and it reaches backwards

**Every sensitivity figure this lab has published is a floor, under-counted by an unknown margin.** The
~19–22% measured in E17/E23/E24 was scored by this same vocabulary, which demonstrably fails to
recognise a correctly-worded finding when the model uses a security term outside its list. The
*comparisons* survive — the same classifier scored every arm, so its blind spots apply equally to both
sides and cannot manufacture a between-arm difference — but the *absolute rates* are too low, and by an
amount nobody has measured.

This compounds the gateway-redaction confound, which pushes the same direction. Two independent reasons
the published sensitivity understates the model.

### What this establishes about transfer

- **Sensitivity transfers.** On code written minutes before measurement, with exact ground truth and no
  possibility of memorisation, the model found **3 of 4** planted absence-of-control defects and
  described each correctly.
- **Specificity holds.** **0 of 4** controls drew an absence claim from the model.
- Combined with E25 (0 findings on 25 unseen library files), **both halves of the behaviour now have
  evidence outside the memorised corpus.**

### Limits, unchanged and stated plainly

- **n = 8.** A demonstration, not a rate. No p-value is quoted because none would be meaningful.
- **I authored the defects.** They are of classes I chose, in my style. The matched-pair design stops
  conspicuousness from inflating the score — anything obvious appears in the twin too, where the model
  correctly stayed silent — but it cannot make my defects representative of a real client codebase.
- **`reset_a` is a genuine miss**, and rate-limiting absence is exactly the class CWE-307 covers, the
  most common absence class in the corpus.

## E27 — PREREGISTRATION: how much did the classifier under-count? (written before measuring)

Registered 2026-07-26 06:02 +07. **Nothing below was measured before this text was committed.**

- **Why.** E26 caught the scoring classifier calling a *correct* detection "clean" — the model named a
  missing webhook signature verification precisely, and `_CONCEPT` had no term for it. Every sensitivity
  figure this lab has published was scored by that vocabulary, so all of them are floors by an
  **unmeasured** margin. This measures the margin.
- **THE OVERFITTING RISK, named first.** Expanding the vocabulary *after* seeing which term was missing
  is exactly how a classifier gets tuned to flatter its own results. Mitigation, committed in advance:
  **new terms are derived from the CWE definitions of the eight classes under test** (284, 285, 200,
  306, 307, 639, 862, 863) — the standard terminology for each class — **not** from the observed misses.
  The webhook term will appear because CWE-306 is "Missing Authentication for Critical Function", not
  because E26 tripped over it.
- **Method.** Extend `_CONCEPT` per CWE class. Re-score **every stored response** from E17, E18, E23,
  E24, E25 and E26 with old and new vocabulary. Report both.
- **Primary outcome.** The change in each published rate, and whether any **between-arm conclusion**
  moves.
- **Prediction, recorded before running.** Absolute rates rise in **both** arms of every comparison,
  because the same vocabulary scored both. Between-arm conclusions should be **stable**. If a conclusion
  flips, that is a finding about the fragility of the whole chain and will be reported as one.
- **Falsifying result for the mitigation.** If the new vocabulary raises the *vulnerable* arm while
  leaving *control* arms untouched, that asymmetry is evidence the terms were tuned to the answer rather
  than to the CWE definitions, and the expansion must be reverted.

## E27 — RESULT: the under-count is narrow; and I broke my own re-analysis rule

Run 2026-07-26. `_CONCEPT` extended from the CWE definitions of the eight classes under test, then every
stored response re-scored with old and new vocabulary.

### Finding 1 — the vocabulary gap was real but narrow

| measurement | old vocabulary | new vocabulary |
|---|---|---|
| E17 vulnerable / clean | 9/60 · 0/40 (p = 0.0078) | **9/60 · 0/40 (p = 0.0078)** |
| E18 messy control | 0/80 (p = 0.0003) | **0/80 (p = 0.0003)** |
| E23 original / anonymised | 8/53 · 8/53 | **9/53 · 8/53** |
| E25 our own code | 0/25 | **0/25** |

**Almost nothing moved.** The gap E26 exposed — no term for signature verification — mattered there
because that test set contains a *webhook*; the RealVuln corpus files do not. So the published
sensitivity figures are floors, as stated, but the margin on **this corpus** is **~1 file in 53**, not
the wide unknown E26 implied. That is a materially smaller correction than the one I flagged, and it is
reported as smaller.

**The mitigation passed its own falsifier.** The preregistration said that if the expansion lifted only
the *vulnerable* arms while leaving controls untouched, the terms were tuned to the answer and must be
reverted. It lifted one vulnerable file and no controls — but it lifted essentially nothing anywhere,
which is the outcome consistent with terms derived from CWE definitions rather than from observed
misses.

### Finding 2 — E23 and E24 CANNOT be faithfully re-scored, because I truncated their storage

Re-scoring E24 from its stored responses gives **6/40 vs 2/42 (p = 0.117)**, against the live run's
**9/40 vs 2/42 (p = 0.0195)**. The difference is not the vocabulary. It is truncation:

| artefact | stored cap | responses hitting the cap |
|---|---|---|
| E17 / E18 | ~600 chars | 1 of 99 · 1 of 80 — negligible |
| **E23 / E24** | **400 chars** | **21 of 53 (40%) · 30 of 82 (37%)** |

The live runs classified the **full** model output; the artefacts kept only the first 400 characters, so
any finding stated past that point is invisible to a re-score.

**This breaks protocol §9 rule 2 — "never discard what re-analysis needs" — written by me, last night,
after E14 lost its grouping unit the same way.** The rule was about a grouping key; the same mistake
recurred as a character limit, and I did not recognise it as the same mistake while writing the code.

**Consequences, stated precisely:**

- **E17, E18, E25 are re-analysable** and their published numbers are confirmed by independent re-scoring.
- **E23 and E24 are NOT re-analysable.** Their **live results stand as published** — the classification
  happened on complete output — but they cannot be re-verified from the committed artefacts, and any
  future re-score of them will *under*-count. Marked accordingly in the ledger.
- Storage is raised to capture the full response going forward. That does not recover E23 and E24; only
  re-running them would, and that is recorded as owed work rather than quietly skipped.

**The lesson, which is the same one twice:** a rule against discarding re-analysis inputs has to name
*every* form of discarding — dropping a column, truncating a string, rounding a float. I wrote the rule
about columns and then truncated a string eight hours later.

## E28 — PREREGISTRATION: re-run E24 with full storage (written before measuring)

Registered 2026-07-26 06:06 +07. **Nothing below was measured before this text was committed.**

- **Why.** E27 established that E24's committed artefact truncates responses at 400 characters, which
  37% of them exceed, so its published result — sound as a live measurement — **cannot be re-verified**.
  That was recorded as owed work rather than skipped. This pays it.
- **Second purpose, which makes this more than bookkeeping.** The instrument flips 36% of verdicts
  (E22). A second independent run of the *same* comparison measures something no single run can: whether
  the **conclusion** is stable across runs even though individual verdicts are not. That is the property
  the whole chain implicitly assumes, and it has never been tested directly.
- **Method.** Identical design to E24 — both arms measured fresh in the same run, same populations, same
  frozen prompt, same corrected classifier, positive-control gated — with responses now stored in full.
- **Primary outcome.** Arm A′ and arm C flag rates, and the Fisher p, compared against E24's
  (9/40 = 0.225 vs 2/42 = 0.048, p = 0.0195).
- **Prediction, recorded in advance.** Rates will differ from E24's by a few files, because that is what
  36% per-file instability does. **The conclusion — arm A′ materially above arm C — should hold.**
- **Falsifying result.** If the conclusion flips (arm C comparable to arm A′), then E24 was a lucky draw,
  the file-role confound is open again, and decision 0027 loses that support for a second time. That
  outcome is published if it occurs.

## E28 — RESULT: the conclusion replicates to within 0.026, on an instrument that flips 36% of verdicts

Run 2026-07-26, identical design to E24, full response storage, both arms measured fresh.

| run | arm A′ (handlers **with** an absent control) | arm C (**without**) | difference | 95% CI | Fisher p |
|---|---|---|---|---|---|
| **E24** | 9/40 = 0.225 | 2/42 = 0.048 | **+0.177** | [+0.031, +0.326] | 0.0195 |
| **E28** | 7/40 = 0.175 | 1/42 = 0.024 | **+0.151** | [+0.027, +0.276] | 0.0241 |

**Arm C moved by one file and arm A′ by two — and the difference reproduced to within 0.026.**

### This is the direct test of the assumption the whole chain rests on

Every experiment here assumes that a conclusion drawn from a single run is stable, on an instrument
measured flipping **36% of individual verdicts** (E22). That assumption had never been tested; E28 tests
it directly, and it holds:

- **Individual verdicts are unreliable** — arm A′ lost a file, arm C lost a file, and E22 showed 36% of
  single verdicts flip on identical input.
- **The aggregate difference is reliable** — +0.177 against +0.151, with overlapping intervals and the
  same verdict at a comparable p.

This is the empirical justification for the design rule adopted after E22 (*measure rates, never reuse
labels*), now confirmed rather than merely argued. It also matches the earlier incidental check: the same
53 files scored **10, 10, 11** flagged across three runs.

### Debt paid, and what it bought

E27 recorded re-running E24 as **owed work** because its stored responses were truncated at 400
characters. E28 pays it: responses are stored in full, so this result **can** be re-verified from its
artefact, unlike the one it replaces.

**The file-role confound is closed on two independent runs.** Decision 0027's mechanism claim — the model
responds to the missing control, not to the file being a request handler — now rests on a replicated
result rather than a single marginal one. E24 stands as reported; E28 is the version future work should
re-analyse.

**Unchanged limits:** n is small; one model; one corpus; the defect distribution is RealVuln's;
structural familiarity untested; and every sensitivity figure remains a floor.

## E29 — PREREGISTRATION: tighten the determinism estimate (written before measuring)

Registered 2026-07-26 06:24 +07. **Nothing below was measured before this text was committed.**

- **Why.** The 36% verdict-instability figure (E22) became the most load-bearing number of the session:
  it **withdrew two preregistered experiments** (E19, E20), forced two rebuilt designs (E23, E24), and
  produced two protocol rules. It rests on **n = 14**. A number carrying that much weight should not
  have an interval that wide, and no one has ever reported one for it.
- **Method.** 24 files queried **twice each in the same run**, identical input, frozen prompt and
  classifier, `temperature=0.0` — same protocol as E22, larger sample, drawn to include **both** arms
  (absence-class and control files) rather than arm A only, since E22 sampled only vulnerable files and
  instability could plausibly differ by arm.
- **Primary outcome.** Verdict disagreement rate with a **95% bootstrap interval** — the interval E22
  never reported.
- **Secondary.** Disagreement rate **split by arm**, to test whether instability is uniform or
  concentrated where the model is closer to a decision boundary.
- **Prediction, recorded in advance.** The pooled rate lands near E22's 36%, with an interval wide enough
  that "roughly a third" is the honest phrasing rather than "36%". If it lands far from 36%, the earlier
  figure was a small-sample artefact and every statement citing it needs the corrected number.
- **What does NOT change either way.** The two withdrawals stand regardless: E19's and E20's designs
  reused single verdicts as fixed values, which is invalid at *any* non-trivial instability, and both
  have since been rebuilt and re-established (E23, E24, E28).

## E29 — RESULT: instability confirmed at ~40%, and the interval is wide enough to change the phrasing

Run 2026-07-26. 24 files (12 absence-class, 12 control) queried twice each in the same run, identical
input, frozen instrument, `temperature=0.0`.

| | disagreement | identical prose |
|---|---|---|
| **E22** (n = 14, absence arm only) | 5/14 = **0.357** | 0/14 |
| **E29** (n = 24, both arms) | 10/24 = **0.417**, 95% CI **[0.208, 0.625]** | **0/24** |
| **pooled** (n = 38) | **15/38 = 0.395** | **0/38** |

**E22's 0.36 sits comfortably inside E29's interval**, so the earlier figure was not a small-sample
artefact — but the interval is **[0.21, 0.63]**, which is far too wide to keep quoting a two-significant-
figure number.

**Correction to how this has been stated all session:** "36% of verdicts flip" is replaced by
**"roughly 40% of verdicts flip, 95% CI [21%, 63%]"**, or in prose, **"between a fifth and two-thirds,
best estimate around two in five."** Every place citing the precise figure is updated. Nothing else
changes — every conclusion drawn from it required only that instability be *materially non-zero*, and
0.21 at the interval's floor is still catastrophic for any design reusing single verdicts as labels.

**In 38 paired calls the model never once returned identical text.** That is the more striking number
and it needs no interval.

### Secondary: instability may be higher on control files, but this cannot tell

| arm | disagreement |
|---|---|
| absence-class | 4/12 = 0.333 |
| control | 6/12 = 0.500 |

Suggestive — a model closer to a decision boundary on files with nothing to find would behave this way —
but **n = 12 per arm**, and no test on that would be worth reporting. Recorded as an observation to
follow up, explicitly **not** as a finding.

### What does not change

Both withdrawals stand. E19 and E20 reused single verdicts as fixed values, which is invalid at any
instability in this range — and both were rebuilt and re-established on valid designs (E23, E24, and
E28's replication to within 0.026). The rule adopted after E22 — **measure rates, never reuse labels** —
is unaffected, and E28 demonstrated its payoff directly.

## E30 — PREREGISTRATION: propagate measurement noise into the published intervals (written before measuring)

Registered 2026-07-26 06:36 +07. **Nothing below was measured before this text was committed.**

- **Why.** E22/E29 measured the instrument flipping **~40%** of verdicts (95% CI [21%, 63%], n = 38).
  **Every interval this lab published is a bootstrap over FILES only** — it models which files were
  sampled, and not at all the fact that each file's verdict is itself a noisy draw. So every published
  interval is **too narrow**, by an amount nobody has computed. This computes it.
- **Method.** Pure simulation, no model calls. For each published comparison, resample files *and*
  re-draw each verdict under the measured flip probability, then re-derive the interval. Compare against
  the published one.
- **Primary outcome.** The widened interval for each headline comparison, and **whether any conclusion
  changes sign or loses significance** once measurement noise is honestly included.
- **Prediction, recorded in advance.** Intervals widen materially. The strongest results (E18, p = 0.0003;
  E17, p = 0.0078) should survive. **The marginal ones (E24/E28 at p ≈ 0.012–0.02) are the ones at risk**,
  and if they cross into non-significance under honest noise propagation, that is reported as the result
  and decision 0027's file-role support weakens accordingly.
- **What this cannot fix.** Widening an interval after the fact is a correction to *reporting*, not to
  *design*. The right design is repeated measurement per file (k runs, verdict as a rate), which this
  lab has not done and which is recorded as owed work rather than simulated away.

## E30 — RESULT: my noise model was wrong, and my own data caught it before it was published

Run 2026-07-26. Pure simulation, no model calls.

**The simulation said every published interval crosses zero:**

| comparison | published CI | naive noise-propagated CI |
|---|---|---|
| E17 absence vs clean | [+0.067, +0.250] | [−0.167, +0.225] |
| E18 absence vs defective | [+0.067, +0.250] | [−0.133, +0.196] |
| E24 handlers with vs without | [+0.030, +0.326] | [−0.175, +0.246] |
| E28 replication | [+0.051, +0.302] | [−0.174, +0.243] |

The "published CI" column is left exactly as it stood when this simulation was run, because those are the
values the simulation was compared against and rewriting them would misrepresent what was actually
argued. E28's interval has since been corrected to **[+0.027, +0.276]** by the artefact reconciliation.
That correction *strengthens* the falsification below rather than weakening it: it shrinks the observed
between-run drift, which is the quantity the noise model overestimated.

Published unexamined, that reads as *"the entire generative-role finding dissolves once measurement
noise is honestly modelled"* — a dramatic, self-flagellating headline, and **wrong**.

### The model is falsified by a direct measurement this lab already has

The simulation implies the between-arm difference should vary by roughly **±0.2** between runs.
**E28 measured that variation directly: +0.177 vs +0.151 — a drift of 0.026.** The model is off by nearly
an order of magnitude against an empirical replication of exactly the quantity it is modelling.

**The error:** I treated the measured **0.395 as a per-verdict flip probability**. It is not. It is the
probability that **two independent draws disagree**, which for a file with latent propensity θ is
2θ(1−θ). Modelling it as a flip means a genuinely-flagged file reports "flagged" only 60% of the time
**regardless of its true state** — which annihilates the signal by construction, in both arms, no matter
what the data says. The simulation was not measuring the finding's fragility; it was measuring my own
mis-specification.

Note also that **0.5 is the maximum disagreement rate achievable by any single θ**. Observing 0.395
pooled therefore implies a **mixture** — most files stable near θ≈0, a minority churning near θ≈0.5 —
not a uniform 40% corruption of every verdict.

### What is actually true about the intervals

The published intervals **are** too narrow — they bootstrap over files and ignore per-file measurement
variance, which is a real omission. But the correct magnitude of that widening is **not** derivable from
the disagreement rate alone without a per-file propensity model, and **the direct empirical estimate
already exists**: E28's replication puts run-to-run drift of the headline difference at **0.026**, which
is small beside the file-sampling intervals of ±0.15–0.30.

**No conclusion changes.** The published intervals stand as the dominant source of uncertainty.

### The lesson, and it is the sharpest of the session

**A simulation is an instrument, and instruments get validated against measurements — not the reverse.**
I built a noise model, it produced a dramatic result that would have retracted five findings, and the
only thing that stopped it was that this lab had already *measured* the quantity the model was
estimating. Without E28's replication, this would have been published as a devastating self-correction
and been entirely spurious.

Worth stating plainly because the failure mode is seductive: **the wrong result was the humble-looking
one.** Every safeguard in this protocol is aimed at claims that flatter the author, and this one would
have passed all of them while being just as false.

**Owed work, recorded not simulated away:** the right fix is repeated measurement per file — k runs, the
verdict taken as a rate — which converts per-file noise into a quantity that can be propagated honestly
instead of assumed.

## E31 — PREREGISTRATION: measure per-file propensities directly (written before measuring)

Registered 2026-07-26 06:40 +07. **Nothing below was measured before this text was committed.**

- **Why.** E30 failed because it inferred a per-verdict flip probability from an aggregate disagreement
  rate, which is not recoverable that way: 0.395 disagreement is consistent with many different mixtures
  of per-file propensity θ. E30 recorded the fix as owed work — **measure θ per file directly** — rather
  than simulating around it. This does that.
- **Method.** 12 files (6 absence-class, 6 control), each queried **k = 3 times** in the same run,
  identical input, frozen instrument. Per-file flag rate is the estimate of θ.
- **Primary outcome.** The **distribution** of θ across files — specifically whether it is a mixture
  (most files near 0 or 1, a minority near 0.5) or broadly uniform. That distinction is exactly what E30
  got wrong by assumption.
- **Secondary.** Whether θ separates the arms: absence-class files should concentrate at higher θ than
  controls if the detector carries signal, and the *shape* of that separation is more informative than
  any single-run rate.
- **Prediction, recorded in advance.** A mixture — most files stable at θ ≈ 0, a minority churning.
  If instead θ is broadly spread, then single-run measurement is worse than this lab has assumed and the
  published rates need re-derivation from repeated sampling, not just wider intervals.
- **Limit, stated in advance.** k = 3 estimates θ to ±0.29 at best; this characterises the *shape* of the
  distribution, not any individual file's θ. n = 12 is a sketch, not a census.

## E31 — RESULT: the mixture is confirmed, and it RESOLVES the whole determinism thread

Run 2026-07-26. 12 files (6 absence-class, 6 control), each queried **k = 3 times**, frozen instrument.

| per-file flag propensity θ | files |
|---|---|
| **stable at θ = 0** (never flagged in 3 runs) | **10 of 12** |
| stable at θ = 1 (flagged in all 3) | 1 of 12 |
| churning (θ = 0.33) | 1 of 12 |

| arm | mean θ | values |
|---|---|---|
| absence-class | **0.222** | 0.33, 0, 0, **1.00**, 0, 0 |
| control | **0.000** | all six at 0 — **never flagged in 18 calls** |

**The preregistered prediction — a mixture, most files stable, a minority churning — is confirmed.**

### The finding that resolves everything: most "instability" is NOT flag instability

E22/E29 measured **~40% verdict disagreement**. E31 shows what that disagreement mostly *is*:

`['clean','non-answer','clean']`, `['non-answer','clean','non-answer']`, `['clean','non-answer','clean']`

**Files oscillating between `clean` and `non-answer` — which does not move the flag rate at all.** Under
E22/E29's definition that counts as a disagreement; under the quantity every experiment actually measures
(the flag rate) it is θ = 0 in both cases. Meanwhile **only 1 of 12 files churns on the flag decision
itself: ~8%, not 40%.**

**This explains, at last, three things that had been in tension all session:**

1. **Why E28 replicated to within 0.026** while the raw disagreement rate suggested it should not have. The
   quantity being replicated — the aggregate flag rate — rides on ~8% churn, not 40%.
2. **Why E30's model was catastrophically wrong.** It applied a 40% flip to the *flag* label. The real
   flag-level churn is roughly a fifth of that, and it is concentrated in a minority of files rather
   than smeared across all of them.
3. **Why E29's "controls look less stable" was a red herring.** Control files churn between `clean` and
   `non-answer` — never onto a flag. On the measured quantity they are the *most* stable arm in the
   study: **θ = 0.000 across all six, 18 consecutive calls without a false claim.**

### Consequence for the published numbers

**The published intervals are closer to right than E30 implied and than E22/E29 made them look.** The
dominant uncertainty really is file sampling; flag-level measurement noise is real but small (~8% of
files) and concentrated. The honest statement about instability is now:

> **~40% of raw verdicts differ between runs, but almost all of that is `clean`↔`non-answer` churn.
> Flag decisions — the thing every result is built on — churn on roughly 1 file in 12.**

Every place citing instability is updated to distinguish the two.

### Limits, unchanged

k = 3 estimates θ to ±0.29 at best, and n = 12 is a sketch. This establishes the *shape* — a mixture,
dominated by stable-at-zero, with control files the stablest — not any individual file's θ, and not a
precise churn rate. Proper propagation still wants larger k, which stays recorded as owed.

## E32 — PREREGISTRATION: structural familiarity, the last untested memorisation channel (written before measuring)

Registered 2026-07-26 09:40 +07. **Nothing below was measured before this text was committed.**

- **Why (Stage 1).** E23 showed detection survives *surface* anonymisation (identifiers, route literals,
  filename). Its stated limit — carried in decision 0027 ever since — is that **mutation changed names,
  not shapes**: a model could still recognise a distinctive code structure. That is the last untested
  memorisation channel, and it is the reason 0027 still cannot promise transfer.
- **This also pays two recorded debts.** E23's artefact is non-re-verifiable (responses truncated at 400
  chars, E27) and is one of the four artefacts SM17 lists as known-stale. This run stores responses in
  full and produces a fresh artefact.
- **Method.** On top of E23's surface anonymisation, add a **structural** change: **reorder top-level
  function and class definitions**. Applied only where provably safe — a file qualifies only if it has
  ≥2 top-level definitions and **no non-definition statement sits between the first and last** (module-
  level assignments or decorated registrations could depend on order). **41 of 53** arm-A files qualify.
  Verified per file: the mutated source must still parse, preserve the import set byte-identically, and
  preserve the AST node-type profile.
- **Design (per the determinism rule).** **Both arms measured fresh, in the same run**, compared as
  **aggregate rates**. Nothing reused; per-file verdicts never compared.
- **Hypothesis.** Detection is reasoning, not structural recall: the flag rate survives combined
  surface + structural anonymisation.
- **Falsifying result.** A materially lower rate on the mutated arm ⇒ structural familiarity contributes,
  and decision 0027's transfer bound must widen again.
- **THE LIMIT, STATED FIRST because it decides what this can claim.** Reordering top-level definitions
  changes the file's **global** shape — it defeats whole-file n-gram recall. It does **not** change the
  **intra-function control flow**, which is where a "this is that vulnerable handler I've seen" judgement
  would most plausibly live. So E32 can weaken structural memorisation at the file level and **cannot
  eliminate** it at the function level. Anything stronger needs semantics-preserving control-flow
  rewriting, which cannot be automated safely at this scale and stays recorded as owed.
- **Power.** 41 files at a ~0.2 base rate detects only a large collapse. A null is **not** equivalence;
  if the interval is wide the verdict is inconclusive, exactly as E23's was.
- **Instrument frozen:** same prompt, corrected classifier (SM13), positive-control gate with the
  transport-failure rule.

## E32 — RESULT: INCONCLUSIVE, and the point estimate leans the unwelcome way

Run 2026-07-26. Positive control passed. 41 files, both arms measured fresh in the same run, responses
stored in full.

| condition | flagged |
|---|---|
| original | 11/41 = **0.268** |
| surface-anonymised **+ top-level definitions reordered** | 8/41 = **0.195** |

**Difference −0.073, 95% CI [−0.195, +0.049] → INCONCLUSIVE**, exactly as the preregistration said a
wide interval must be reported.

### What this does and does not say

- **It does NOT show structure is irrelevant.** The interval spans a 20-point collapse and a 5-point
  increase. Nothing is established in either direction.
- **The point estimate leans toward structural familiarity mattering.** −0.073 is a drop, not a null.
- **It does NOT establish a drop either.** A 41-file sample at a ~0.27 base rate cannot resolve an
  effect this size, which the preregistration stated before the run.

### The comparison with E23 is suggestive and NOT valid as evidence

E23 (surface anonymisation only) gave **+0.057**; E32 (surface **+** structural) gives **−0.073** — a
swing of 0.13 in the direction of "structure carries something". **This comparison must not be quoted as
a finding**, for a reason that is disqualifying on its own: **the two runs use different file sets**
(53 vs 41; E32 only accepts files where reordering is provably safe), and E32's original arm scores 0.268
against E23's 0.208 on the *same* instrument, which shows the subsets differ in difficulty before any
mutation is applied. The clean comparison would need both mutations run on one identical file set.

### Consequence for decision 0027 — the bound does NOT narrow, and the earlier narrowing gets a caveat

0027 currently records that surface memorisation is not the driver (E23) with structural familiarity
listed as outstanding. That stands, with one change: **the outstanding item is now known to be
non-trivially large in the point estimate**, not merely untested. The transfer bound stays at its
current width, and the honest phrasing is:

> Surface memorisation is not the driver. **Structural familiarity is untested-to-inconclusive, and what
> evidence exists points at it contributing rather than not.**

**Owed, unchanged and now better motivated:** run both mutation levels on one identical file set, at a
sample size chosen for the ~0.07 effect this run suggests — roughly 300+ files per arm, which this
corpus can supply but a single session's call budget cannot.

## E33 — CANCELLED at the power gate (Stage 3), before any model call

Proposed 2026-07-26 10:05: run surface-only and surface+structural mutation on **one identical file set**,
removing the confound that disqualified the E23-vs-E32 comparison.

**Cancelled. The corpus cannot answer it.**

| n per arm | calls | power to detect the 0.07 drop E32 suggests |
|---|---|---|
| 41 (E32's set) | 82 | **0.12** |
| **117 — every file in the corpus supporting both mutation levels** | 234 | **0.32** |
| 150 | 300 | 0.42 (files do not exist) |
| 250 | 500 | 0.62 (files do not exist) |

Only **117 of 175** absence-class files support both mutations (a file is excluded when reordering could
change behaviour). So **32% is the ceiling this corpus allows** at one measurement per file — a design in
which a true effect is missed two times in three, and a null says nothing.

**Why this is a cancellation and not a smaller run.** The tempting move is to run 117 anyway and report
"no significant difference". That sentence would be indistinguishable from "we could not have found one",
and this lab has already published one underpowered result it had to withdraw (E16b). Protocol Stage 3
exists for exactly this: *a known-underpowered run is cheaper to cancel than to publish and retract.*
Second cancellation at this gate today; the first was a multi-language trial with 4 JavaScript ground-truth
entries.

**What would actually answer it,** recorded so the next session does not rediscover the arithmetic:
repeated measurement (k≥3 per file) to cut per-file noise, at n≈117 — roughly **700 calls**. E31 makes
this more attractive than it first looks: flag-level churn is only ~1 file in 12, so most files are
stable and repeated sampling buys real precision rather than averaging noise.

**Consequence:** decision 0027's structural-familiarity item stays exactly where E32 left it —
inconclusive, point estimate leaning toward structure contributing, transfer bound not narrowed.

## E34 — PREREGISTRATION: scale the authored-unseen test to a measurement (written before measuring)

Registered 2026-07-26 10:08 +07. **Nothing below was measured before this text was committed.**

- **Why (Stage 1).** E26 measured sensitivity on genuinely unseen code — 3/4 planted defects found, 0/4
  false claims — and was explicitly labelled a **demonstration, not a rate** (n = 8, no p-value quoted).
  It is the strongest transfer evidence this lab has and the weakest-powered. The corpus cannot fix the
  structural question (E33 cancelled), but this one is fixable: the test set is **authored**, so n is a
  choice rather than a constraint.
- **Method.** Extend `evaluation/authored-unseen/` from 4 matched pairs to **12** (24 modules), written
  in this session and therefore outside any deployed model's training set. Each pair implements the same
  feature twice, differing only in whether the required control is present.
- **Deliberate changes from E26, to attack author bias rather than repeat it:**
  1. **New CWE classes** not used in E26 — mass assignment, missing tenant scope on a bulk endpoint,
     unauthenticated internal admin route, missing re-authentication on a sensitive change, missing
     object-level check on delete, information exposure through an error path.
  2. **Three frameworks** (Flask, FastAPI, Django) rather than one, so "this author's Flask style" is
     not the thing being detected.
  3. **Subtle controls** in some `_b` variants — a control that is present but easy to overlook (a
     dependency-injected guard, a queryset filter in a base class) — so specificity is tested against
     near-misses, not only against obvious guards.
- **Constraints carried over unchanged:** matched pairs (anything conspicuous appears in the twin, where
  it must NOT fire); no comment, name or docstring hints at the defect; realistic CRUD idiom; files
  shuffled and shown as `module_N.py` so neither name nor order leaks the answer.
- **Primary outcome.** Sensitivity (planted defects flagged) and false-positive rate (controls flagged),
  with a one-sided Fisher exact test — the statistic E26 could not justify at n = 8.
- **Power, computed before writing any code.** At 12 pairs: 9/12 vs 1/12 → p = 0.0028; 7/12 vs 2/12 →
  p = 0.0498. **So the design detects the effect E26 suggested, and is marginal if sensitivity falls to
  ~0.58.** Stated in advance rather than discovered afterwards.
- **Falsifying result.** Sensitivity near the control rate ⇒ the E26 demonstration does not survive
  scaling, and decision 0027's transfer claim weakens.
- **The bias that remains, unfixable by scaling.** I still author the defects. Matched pairs stop
  conspicuousness from inflating the score; they cannot make my defects representative of a real client
  codebase. This closes the *power* gap, never the *realism* gap.

## E34 — RESULT: significant, and the MISS pattern is worth more than the rate

Run 2026-07-26. Positive control passed. 12 matched pairs, 3 frameworks, shown blind as `module_N.py`.

| scoring | sensitivity | false positives | one-sided Fisher |
|---|---|---|---|
| **as run** (classifier at run time) | 7/12 = 0.583 | 2/12 = 0.167 | **p = 0.0447** |
| rescored (reassurance vocabulary extended by category) | 7/12 | 1/12 = 0.083 | **p = 0.0136** |
| hand-adjudicated, **model** errors only | 7/12 | **0/12** | — |

E26 at 3/4 vs 0/4 gave p = 0.0714 — **not** significant, which is why it was published as a
demonstration. Scaling to 12 pairs was the fix, and it worked.

### Where the capability actually is — the finding of this run

| CWE class | planted | detected |
|---|---|---|
| **639** ownership / IDOR | 4 | **4** |
| **306** missing authentication | 2 | **2** |
| 862 missing authorization | 2 | 1 |
| **307** no rate limit / lockout | 1 | **0** *(also missed in E26)* |
| **915** mass assignment | 1 | **0** |
| **209** error path leaks trace | 1 | **0** |
| **620** no re-authentication | 1 | **0** |

**The model detects absent ownership and absent authentication essentially reliably (6/6) and misses
rate-limiting, mass assignment, error-leakage and re-authentication entirely (0/4).** Authorization is
mixed (1/2). That is far more actionable than "58% sensitivity": the aggregate number is an average over
classes the model is good at and classes it does not see at all, and CWE-307 has now been missed in
**both** authored runs.

### Specificity held against deliberately subtle controls

Two `_b` variants hid the control on purpose — one enforced ownership through an **injected dependency**
(no check visible in the handler body), one applied the scope **inside a service `base()` method**. The
model correctly stayed silent on both. That is the specificity result this run was designed to stress,
and it is the strongest one so far.

### Both "false positives" were mine, not the model's

- **`download_b`** — the model wrote *"Org filter on get. IDOR blocked."* It **recognised the control**.
  The classifier scored it as a finding because "blocked" was not in the reassurance vocabulary.
  Fixed by extending that vocabulary **as a category** (blocked/prevented/mitigated/guarded/scoped),
  the same way E27 derived concept terms from CWE definitions rather than from whichever word tripped
  the run.
- **`email_b`** — the model wrote *"No rate limit. Brute password / spam confirmations."* **The model is
  right.** That file re-checks the password and has no throttle. It is a real absent control that I did
  not plant and did not record.

### A design flaw in my own test set, disclosed

`email_a` and `email_b` differ in re-authentication and **both lack rate limiting**. A matched pair is
only "controlled" with respect to the *planted* class; it can carry an **unplanted** defect, which makes
the control arm not truly clean and turns a correct model finding into a scored false positive.
**Every matched-pair result in this lab inherits that flaw**, including E26's. The fix for a future set
is to audit each `_b` variant against the full absence-class list, not only against its own pair.

### Limits, unchanged

n = 12 pairs. I authored the defects — matched pairs stop conspicuousness from inflating the score but
cannot make my defect distribution representative of a client codebase. This closed the **power** gap
E26 left. It did not close the **realism** gap, and the class breakdown above is the honest warning:
a corpus weighted toward CWE-307 or 915 would have scored far worse.

## E35 — PREREGISTRATION: re-run the headline comparison, paying the stale-artefact debt (written before measuring)

Registered 2026-07-26 10:20 +07. **Nothing below was measured before this text was committed.**

- **Why.** `generative-260726.json` carries E17, this lab's **most load-bearing result** (absence-class
  vs clean files, p = 0.0078 after correction). SM17 lists it as **known-stale**: it predates the
  E26/E27/E34 classifier corrections, so its committed numbers were produced by a classifier that no
  longer exists. The published figures are the *re-scored* ones, which is defensible but leaves the
  headline resting on an artefact nobody can regenerate.
- **This is a replication, not bookkeeping.** A fresh run of the same design with the current instrument
  is an **independent second measurement of the core finding**. E28 did exactly this for the file-role
  comparison and reproduced its difference to within 0.026; the headline has never had the same treatment.
- **Method.** Identical design to E17 — 60 files holding an absence-class vulnerability, 40 clean
  controls, frozen prompt, positive-control gate — with the **corrected classifier** and **full response
  storage**. Both arms measured in the same run.
- **Primary outcome.** Flag rate in each arm and the one-sided Fisher p, compared against the re-scored
  E17 (9/60 = 0.150 vs 0/40 = 0.000, p = 0.0078).
- **Prediction, recorded in advance.** Rates shift by a few files — flag-level churn is ~1 in 12 (E31) —
  and **the conclusion holds**: the vulnerable arm materially above the clean arm.
- **Falsifying result.** The clean arm rises to meet the vulnerable arm, or the gap loses significance.
  That would mean E17 was a lucky draw and decision 0027's primary evidence needs re-basing. Published
  if it occurs.
- **Limits unchanged.** Same corpus, same model, same gateway redaction confound (37% of absence-class
  files arrive with identifiers rewritten), same file-level granularity.

### E34 — CORRECTION after an independent audit of the test set: 2 of 12 control variants were not controls

The `_b` variants were audited by a reviewer who did not write them and did not see the results, against
the **full** absence-of-control list rather than each pair's own planted class. Report:
`docs/plans/reports/2026-07-26-authored-control-variant-audit.md`.

**Two of twelve "controlled" files carry an unplanted absence-class defect:**

| pair | planted control | unplanted defect found | verified |
|---|---|---|---|
| `email` | CWE-620 re-authentication — **present and correct** | **CWE-307**: `check_password` behind no throttle or lockout. A hijacked session brute-forces the password using the 403/200 split as an oracle. | yes — the model had flagged it and was scored wrong for doing so |
| `lookup` | CWE-209 error-path — **present and correct** | **CWE-306 + 200**: the endpoint has **no authentication at all** — no decorator, no `current_user()`, no dependency — while returning `{id, status}` for an arbitrary `?ref=`. | yes — confirmed by inspection: `@bp.get` then `def account()`, nothing else. Every other Flask `_b` gates (invoices_b 4 sites, exports_b 2, internal_b 2) |

**`lookup` is the worse case: the missing authentication is in BOTH arms**, so `lookup_a`'s label ("one
defect, CWE-209") is also wrong. That pair cannot be scored in either direction and is excluded, not
relabelled.

### Re-scored, with both numbers published

| scoring | sensitivity | false positives | p |
|---|---|---|---|
| all 12 pairs (as published above) | 7/12 = 0.583 | 1/12 = 0.083 | 0.0136 |
| **10 pairs with valid ground truth** | **7/10 = 0.700** | **0/10 = 0.000** | **0.0015** |

**The exclusion improves the result, so the justification has to be stated and judged, not assumed.**
It is legitimate here because the audit was **independent, blind to the outcome, and decided on a
criterion unrelated to it** — *does the control variant actually control?* — not because the excluded
files scored badly. Both numbers are published so a reader can disagree with the exclusion and still
have the conservative figure. **The conservative figure is the one quoted in decision 0027.**

**The artefact now agrees with the published figure.** `authored-unseen-v2-260726.json` had stored the
as-run scoring (`tp = 7, fp = 2, p = 0.0447`) while the log and decision 0027 both quoted the re-scored
`7/12 vs 1/12, p = 0.0136`; re-deriving its verdicts from the stored prose brings the artefact to
`tp = 7, fp = 1, p = 0.0136`. **No published number moves** — and note the direction: here the stale
artefact was the *pessimistic* one, understating a result the documents had already corrected.

### The finding underneath, which matters more than either number

Both defects have the **same shape**: the control class was applied only where it was the answer key.
`reset_b` is rate-limited because CWE-307 was *its* planted class; `email_b` is not. `invoices_b`,
`exports_b` and `internal_b` authenticate; `lookup_b` does not. That is **one systematic authoring bias,
not two slips** — an author writing matched pairs defends the class under test and stops thinking about
the rest.

**It predicts recurrence in any test set authored this way, including E26's four pairs.** The protocol
gains a rule: **a control variant must be audited against the full class list by someone who did not
write it, before it is used as ground truth.**

## E35 — RESULT: the headline replicates, and comes back stronger

Run 2026-07-26. Positive control passed. Same design as E17, current instrument, full response storage.

| run | vulnerable arm | clean arm | one-sided Fisher |
|---|---|---|---|
| **E17** (re-scored with the corrected classifier) | 9/60 = 0.150 | **0/40** | p = 0.0078 |
| **E35** (fresh, independent) | **14/59 = 0.237** | **0/40** | **p = 0.000350** |

**Specificity is 0/40 in both runs — 80 consecutive clean files without a single false claim.**

### What replicated and what moved

- **The conclusion replicated and strengthened.** The separation is larger and the p-value an order of
  magnitude smaller. The preregistered falsifier — the clean arm rising to meet the vulnerable arm —
  did not occur; the clean arm did not move at all.
- **Sensitivity rose from 0.150 to 0.237.** Two changes since E17 both push that way and neither is a
  fluke: the classifier now recognises findings its earlier vocabulary missed (E26/E27/E34 corrections),
  and unreadable files are no longer scored as model non-answers (E21). This is the "published rates are
  a **floor**" caveat being paid out in the expected direction.
- **The file-missing bucket did its job**: 1 of 60 excluded as never-shown rather than silently counted
  as a model failure. That fix came from E21 and this is its first clean demonstration.

### Debt paid

`generative-260726.json` is regenerated by the current instrument with responses stored in full
(cap 4000, median length 185 — nothing truncated). It is **no longer known-stale** and can be
re-verified from the artefact, which was the point.

**Two of SM17's four known-stale entries can now be cleared** — this one, and `mutation-transfer`
(E19, withdrawn and superseded by E23). The remaining two are `messy-control` (E18) and
`role-control-v2` (E24, superseded by E28).

### Unchanged limits

Same corpus, same model, same gateway-redaction confound (37% of absence-class files arrive with
identifiers rewritten), file-level granularity, and the sensitivity figure remains a floor rather than
an estimate.

## E36 — PREREGISTRATION: re-run the mess control, clearing the last live stale artefact (written before measuring)

Registered 2026-07-26 10:45 +07. **Nothing below was measured before this text was committed.**

- **Why.** `messy-control-260726.json` (E18) is the arm that rules out "the model just reacts to
  defective code" — the control decision 0027 rests on for its class-specificity claim. It is still
  listed known-stale: produced before the E26/E27/E34 classifier corrections. Of the three remaining
  stale entries it is the only one carrying a **live** conclusion; the other two are superseded records
  (`mutation-transfer` = withdrawn E19, `role-control-v2` = superseded by E28).
- **Replication, not bookkeeping.** E35 just re-ran the headline and it came back stronger. This does the
  same for the supporting control, so both halves of 0027's mechanism argument will rest on
  independently replicated runs rather than on single measurements.
- **Method.** Identical design to E18 — 80 files carrying real vulnerabilities of **presence** classes
  only (no absent control) — current instrument, full response storage, positive-control gated.
- **Primary outcome.** Flag rate on the messy arm, and the Fisher p against E35's freshly-measured
  vulnerable arm (14/59), replacing the cross-run comparison E18 had to make against an older run.
- **Prediction, recorded in advance.** The messy arm stays near zero. E18 re-scored gave 0/80.
- **Falsifying result.** The messy arm rises materially. That would mean the model does react to
  defectiveness after all, and **0027's class-specificity claim collapses** — the single most damaging
  outcome available to this decision. Published if it occurs.
- **A caveat this run inherits and cannot fix.** The E34 audit found that an authored "control" can carry
  an unplanted defect. E18's messy arm is drawn from the **corpus**, not authored, so its labels come
  from RealVuln ground truth — which is *also* not exhaustive. A file recorded as presence-class-only
  could still lack a control nobody labelled. That biases **against** the hypothesis (it would raise the
  messy arm), so a near-zero result is safe from it; a raised result would be ambiguous.

### E26 — checked against the same audit, and it survives

The E34 audit warned its finding "applies retroactively to anything built the same way, whether or not
it has been re-audited yet". E26 is the obvious candidate: it used the **first four pairs** of the same
set, authored by the same person under the same constraints.

**It was already covered.** The audit reviewed all twelve `_b` variants, which includes E26's four:

| E26 control variant | verdict |
|---|---|
| `invoices_b` | **CLEAN** — both routes call `current_user()`/`abort(401)`, `detail` scopes by `org_id` |
| `reset_b` | **CLEAN** — rate limits on both routes |
| `exports_b` | **CLEAN** — role check present |
| `webhooks_b` | **CLEAN** — HMAC verification present (one out-of-scope limit noted: no replay protection, CWE-294) |

**So E26's result stands unchanged** (3/4, 0/4, p = 0.071 — a demonstration, as it was always labelled).
The two invalid controls are both in the eight pairs added for E34, and neither was part of E26.

Worth noting *why* the first four survived while two of the next eight did not: the audit's own
explanation is that the author applies a control class where it is the answer key. In the first four
pairs, the four planted classes (639, 307, 862, 306) between them cover most of the list — so defending
each pair's own class happened to defend the others too. The eight added pairs introduced classes
(915, 209, 620) whose controls do **not** incidentally cover authentication or rate limiting, and that
is exactly where the two gaps appeared. **The bias was always there; the first set was too small to
expose it.**

## E36 — RESULT: the mess control replicates; class-specificity holds on two independent runs

Run 2026-07-26. Positive control passed. 80 corpus files carrying real vulnerabilities of **presence**
classes only, current instrument, full response storage.

| arm | flag rate |
|---|---|
| files with an **absence**-class vulnerability (E35, fresh) | 14/59 = **0.237** |
| files **defective but with no absent control** (E36, fresh) | 2/80 = **0.025** |
| clean files, nothing wrong (E35, fresh) | 0/40 = **0.000** |

| comparison | p |
|---|---|
| absence-class vs messy-no-absence | **0.000120** |
| messy-no-absence vs clean | **0.44 — no difference** |

### Both halves of 0027's mechanism argument are now independently replicated

| | first run | replication |
|---|---|---|
| headline (absence vs clean) | 9/60 vs 0/40, p = 0.0078 | **14/59 vs 0/40, p = 0.000350** (E35) |
| mess control (absence vs defective) | 9/60 vs 0/80, p = 0.0003 | **14/59 vs 2/80, p = 0.000120** (E36) |

**The preregistered falsifier did not occur.** The messy arm did not rise to meet the vulnerable arm; it
sits at 0.025, statistically **indistinguishable from files with nothing wrong at all** (p = 0.44).
Every one of those 80 files carries a real, ground-truth-confirmed vulnerability, and the model still
produced absence-of-control language about only two of them.

### The one honest difference from E18

The messy arm moved from **0/80 to 2/80**. Two possibilities, and this run cannot separate them:

1. **Instrument change.** The classifier now recognises findings its earlier vocabulary missed
   (E26/E27/E34). The same change lifted the vulnerable arm from 0.150 to 0.237, so a small lift here is
   the expected symmetric effect, not a surprise.
2. **The caveat recorded before the run.** RealVuln's ground truth is not exhaustive. A file labelled
   presence-class-only can still lack a control nobody recorded — exactly the flaw the E34 audit found in
   the *authored* set. Under that reading, one or both of these two flags is a **true** positive scored
   against the model.

Both readings leave the conclusion intact, and the second would strengthen it. **Reported as
unresolved rather than resolved in the favourable direction.**

### Debt cleared

`messy-control-260726.json` is regenerated by the current instrument with responses stored in full.
**The known-stale list is now down to two entries, and neither carries a live conclusion**:
`mutation-transfer` (E19 — withdrawn, superseded by E23) and `role-control-v2` (E24 — superseded by
E28). Every artefact behind a standing claim is re-verifiable.

## E37 — CANCELLED at the power gate (Stage 3), before any model call

Proposed 2026-07-26: ask whether the generative-role capability is **class-uniform** or **concentrated**.
E34 hinted hard at concentration — ownership/authentication **6/6**, rate-limit/mass-assignment/
error-leak/re-authentication **0/4** — but n = 4 on the miss side, which is a hint and not a measurement.

**Cancelled. The corpus cannot answer it either.**

- **Design considered.** A within-file paired McNemar over the **53 corpus files whose ground truth
  carries BOTH** an ownership/authentication class (CWE-639/862/863/285/284/306/287) **and** CWE-307.
  Within-file pairing controls everything about the file — framework, size, style, redaction damage,
  familiarity — so the only thing differing between the two arms is **which class the prose named**.
- **Corpus inventory, measured before any power arithmetic.** Files with ownership/authentication classes
  only: **118**. Files with CWE-307 only: **20**. Files carrying **both**: **53**.

**Power, computed against rates MEASURED on existing data** (ownership/authentication language appears on
**13.3%** of absence-arm files, CWE-307 language on **3.3%**) rather than against rates hoped for:

| design | power |
|---|---|
| paired McNemar, n = 53, one reading per file | **43.3%** |
| unpaired Fisher, 118 vs 20 | **16.0%** |
| paired, k = 3 readings, union estimand, under E31's **measured** flag churn (~1 file in 12) | **53.7%** |
| paired, k = 3, under an **independence** assumption E31 already falsifies | 91.3% |

Null calibration was checked and behaved: **3.3%** paired and **1.8%** unpaired against α = 0.05.

**Why this is a cancellation.** Only the last row clears 80%, and it clears it by assuming the repeated
readings of a file are independent — which E31 measured and falsified: most files sit at θ ≈ 0 and a
minority churn, so three readings of a file buy far less than three independent files. Running the honest
design at 43–54% would produce a null that could not be distinguished from "we could not have found one",
which is the exact failure E33 was cancelled to avoid.

**The second absence-class design cancelled at this gate, after E33, and the pattern is itself the
finding.** E33 died because only 117 of
175 files support both mutation levels; E37 dies because only 20 files carry CWE-307 without an
ownership/authentication class beside it. **The corpus does not contain enough rate-limit-bearing files to
resolve the class question at the detection rates the model actually achieves.** The class breakdown in
E34 therefore stays a hint, and decision 0027's narrowing stays where E34 put it.

**One comparison worth recording on the way out.** E34's *authored* files produced ownership detection at
**4/4**; real corpus files produce ownership-class language at **13.3%**. The gap is an order of
magnitude, in the direction that should worry us: **our own authored test set is easier than reality**,
and the transfer evidence built on it is correspondingly optimistic.

### SUPERSEDED by E42 — the cancellation rested on a correlation figure that did not apply here

The gate above computed the k=3 repeated-reading design at 53.7% power "under E31's measured
correlation", and set aside the 91.3% figure because it assumed independence between readings, which E31
appeared to have falsified. E42 then measured the correlation directly, on this exact material and this
exact measure: the ownership attributions from two independent runs over the same 53 files **overlap in 0
of 6 files**, against an expectation of 0.68 under independence and 6.0 under stability.

For class attribution on this material, independence is not an optimistic assumption — it is the
best-supported model of the data. Recomputing the same design with it:

| k | union rate, ownership | union rate, CWE-307 | power | calls |
|---|---|---|---|---|
| 1 | 0.113 | 0.019 | 44.8% | 53 |
| **3** | **0.302** | **0.056** | **94.6%** | **159** |
| 5 | 0.451 | 0.091 | 99.5% | 265 |

**The cancellation was correct on the evidence available when it was made and is wrong now.** E31's churn
figure came from a different arm and did not generalise; importing it was the error, not the arithmetic
done with it. E37 is reinstated as runnable at k=3 for 159 calls.

One caveat that must travel with the reinstatement: the union-over-k estimand is not the same quantity the
single-reading design measured. It answers "is this class reported in at least one of three readings",
which — given E42's finding that per-file detection behaves like sampling — is the more product-relevant
question, but it is a different question and must be labelled as such rather than quietly substituted for
the original.

## E38 — a stored verdict is a derived value, and ours had drifted from the data

This is an **instrument** entry, not a hypothesis test. Nothing about the model was measured; what was
measured is whether this lab's own committed artefacts still agree with the code that produced them.

- **Hypothesis.** Every artefact under `evaluation/sast-fp-discrimination/` stores, per file, both the
  model's raw prose (`response`) and a `verdict` **derived** from it by the deterministic classifier in
  `run_generative.py`. The classifier has been fixed repeatedly this session — most consequentially, it
  now **strips fenced code blocks before scanning**. The stored verdicts were never re-derived after
  those fixes. If the derivation changed and the derived values did not, the artefacts disagree with
  their own data.
- **Method.** Re-score every stored `response` against the current classifier and compare with the
  `verdict` sitting beside it. No model calls; the prose is fixed and committed.
- **Data.** **11 rows across 7 artefacts** disagree with their own stored prose.
- **Proven cause.** Responses that **echoed the source file back** inside a code fence had been scored
  `flagged` — the classifier was reading the *source*, not the review. With code spans stripped they
  correctly read `clean`. This is the same defect class the code-stripping fix was written for; the fix
  simply never reached the values already on disk.

### It cut both ways, which is the reason to trust the sweep

| | before | after | direction |
|---|---|---|---|
| E35 headline, absence vs clean | 15/59 vs 0/40, p = 0.000185 | **14/59 vs 0/40, p = 0.000350** | **against us** |
| E28 role/filename control | 8/40 vs 1/42, +0.176, p = 0.0120 | **7/40 vs 1/42, +0.151, p = 0.0241** | **against us** |
| E34 authored-unseen | artefact held tp = 7, fp = 2, p = 0.0447 | **tp = 7, fp = 1, p = 0.0136** | **for us** — the artefact was the pessimistic one |

The headline correction removes a flag this lab had been counting. The E34 correction restores one it had
already stopped counting in prose but was still under-counting in the artefact. **A defect that only ever
moved numbers in the author's favour would be a suspicious defect; this one is systematic, and the
distribution of its damage is what a systematic defect looks like.** E28 remains significant with an
interval excluding zero, E35 remains significant by three orders of magnitude, and E34's published figure
does not move at all — but that is the outcome, not the design.

### Reconciliation

Verdicts re-derived from the stored prose, derived statistics (flag rates, differences, Fisher p)
recomputed from the corrected counts, and the previous values preserved **in-file** under a `superseded`
key with a timestamp, a reason and the exact rows that changed. Nothing is overwritten silently. The
operation was verified **idempotent** — a second pass changes nothing — which is the property that makes
it safe to run as a check rather than only as a repair.

### The gap this exposes, and it is the durable part

**The existing freshness guard compares COMMIT TIMES.** An artefact committed alongside the instrument
that scores it passes the guard — while still disagreeing with it, because agreeing was never what the
guard tested. Every one of the 11 drifted rows lived in an artefact the guard called fresh.

> **Freshness is not reproducibility.** The question a guard must ask is not *was this file written after
> the code* but *does re-deriving it from its own stored inputs give back what it says*.

### The second instrument defect found in the same audit: a dead vocabulary

The per-CWE class-attribution vocabulary for **CWE-306** (`unauthenticated|no authentication|missing
authentication`) fires on **0 of 440** real model responses. Not rarely — never. The cause is that the
model writes telegraphically: *"no auth"*, *"No admin gate"*, *"Any user can delete/update"*. **Every
CWE-306 file was therefore uncreditable by construction**, and had been for the whole session.

A replacement derived from the CWE **definition** rather than from whichever phrasing happened to trip a
past run fires on **12 of 440**, all of them on prose the classifier had **flagged** and **0** on prose it
had called clean.

**Blast radius measured, and it is nil:** the class-attribution figure this feeds does not move, because
CWE-306 almost never occurs alone in this corpus and the co-occurring classes already fired. The defect
is real and the number it would have corrupted was, by luck of the corpus, already right.

### Specificity audit across all classes, because it constrains what may be claimed

The same audit asked the prior question: does each class's vocabulary fire on prose that flagged the file
and stay silent on prose that cleared it? Under a per-class **absence rule** — the class term and an
absence marker in the same sentence window, reassurance test applied first — firing rates were:

| class | on flagged prose | on clean prose |
|---|---|---|
| CWE-639 ownership / IDOR | **46.0%** | 0.0% |
| CWE-862 missing authorization | **20.6%** | 0.0% |
| CWE-306 missing authentication (replacement vocabulary) | **19.0%** | 0.0% |
| CWE-307 no rate limit / lockout | **9.5%** | 0.0% |
| CWE-200 information exposure | 4.8% | **2.1%** |

Four of five classes separate cleanly — they fire only on prose that found something. **CWE-200 does
not**: it fires almost as often on prose the classifier cleared as on prose it flagged, which means its
terms are catching ordinary discussion of responses and error paths rather than a claim about a missing
control. **CWE-200's vocabulary is not specific enough to support a class-attribution claim and is
excluded from one.** The four that separate may be used; the fifth may not.

---

## E39 — RESULT: the class narrowing is *consistent with* real corpus code, but does not confirm it

E37 cancelled the significance test of this question at the power gate. The question itself did not go
away: decision 0027 narrows the whole generative-role claim to "absent ownership and absent
authentication" on the strength of **four authored files** in E34, and CWE-307 — no limit on
authentication attempts — is the **most common absence class in the corpus**. If that narrowing is right
it constrains what can be sold; if it is an artefact of four files we wrote ourselves, it undersells.

So this was preregistered as an **estimate, not a test**: report the rates and an interval, claim no
p-value. That distinction is not cosmetic. A p-value from a design already measured at 43% power would be
a number with no evidential warrant attached, and writing one down invites a reader to treat it as one.

**Design — paired inside a single file.** All 53 corpus files whose ground truth carries *both* an
ownership/authentication class and CWE-307. One reading per file; both questions are read off the *same*
prose. Framework, size, style, difficulty and the instrument's own churn are held fixed by construction,
because there is only ever one response. This is why one reading per file suffices here and would not in
an unpaired design.

**A defect in the first version of this run, and what it cost.** The verdicts were scored on the raw
response while the artefact stored the *redacted* one — so the published number would not have re-derived
from the committed evidence. The guard written this morning caught it on its first real use. Scoring now
runs on the persisted text, which makes the artefact reproducible and the estimate **conservative**:
redaction only ever removes characters, so it can suppress a detection but never invent one. It cost
three of 53 files — **all three in the ownership arm**, i.e. the error points against the hypothesis under
test, which is the direction an unavoidable error should point.

| measure | raw prose (not reproducible) | **persisted prose (published)** |
|---|---|---|
| named ownership/authn absence | 9/53 = 0.170 | **6/53 = 0.113** |
| named rate-limit absence | 1/53 = 0.019 | **1/53 = 0.019** |
| difference | +0.151 [+0.038, +0.264] | **+0.094 [+0.000, +0.189]** |

**The published interval's lower bound sits on zero.** The first number I saw was the stronger one; the
one that survives being checkable is weaker, and it is the one that stands. Read honestly: the *direction*
matches E34 and the corpus files agree with the authored ones about which way the asymmetry runs — but
this does **not** confirm the narrowing, and the power gate said in advance that it would not. Anyone
citing +0.094 as established is citing an estimate whose interval includes no effect at all.

**The finding that does not depend on the comparison.** Every one of these 53 files carries a real
CWE-307 defect, and the model named the missing rate limit in **one of them**. That is an absolute
statement, needs no control arm, and is the practically important one: the most common absence class in
this corpus is very nearly invisible to the model in the generative role. The comparison is what is
uncertain; the near-zero is not.

**Also worth recording:** the ownership-arm rate here (0.113) is far below E34's authored-file rate
(ownership 4/4). Third independent sign that the test material we write ourselves is easier than the code
we would actually be sold against.

**Status:** decision 0027's narrowing is retained, with its evidence base widened from 4 authored files
to 53 corpus files, and its confidence explicitly *not* raised. Replication at adequate power needs more
rate-limit-bearing files than this corpus contains — which is now the concrete blocker on this line of
work, and a sourcing problem rather than an experimental one.

---

## E40 — targeted per-class probing: the format finding came first

E39's most consequential number is an absolute one: across 53 corpus files that **all** carry a real
CWE-307 defect, the model named the missing rate limit in **one**. That does not yet say whether the model
*cannot* recognise a missing lockout or simply *does not mention it* when asked one open-ended question
and a juicier IDOR is sitting in the same file. Only the first is a statement about capability, and the two
lead to opposite product decisions: if a targeted question recovers the misses, per-class prompting is the
answer and this is prompt design; if it does not, CWE-307 is outside what this role delivers and no prompt
fixes it.

**Preregistered as a test** — paired within file against E39's 1/53 on the identical files, exact McNemar,
one-sided. Power at n=53: 90% for recovery to 0.20, 70% to 0.15, 36% to 0.10. That gate was deliberately
set where the *decision* changes rather than where a p-value becomes obtainable: recovery below ~10% would
not justify one call per class per file, so failing to resolve a 7% effect is not a failure at anything
worth resolving.

**The leading-question problem, and why this probe carries two canaries.** "Is the rate limit missing?"
invites yes. A model answering yes indiscriminately would score as total recovery while detecting nothing,
and comparing against E39's open-ended prompt cannot catch that, because the two prompts differ in exactly
the way that manufactures the artefact. So the probe refuses to run unless a login handler with no limiter
reads as absent **and** the same handler with `@limiter.limit(...)` does not. One canary would have been
worse than none — it would have licensed precisely the failure it cannot see.

### The first version aborted at its own gate, and that is E16a replicating

The probe originally demanded a one-word verdict — `ABSENT` / `PRESENT` / `NA` — on the first line. Both
canaries came back **unparseable**. The model had ignored the instruction entirely and answered with a
rewritten copy of the file:

```
"```python\n@app.route('/login', methods=['POST'])\ndef login():\n    data = request.get_json()..."
"Syntax error L7: missing `})`.\nTiming leak: exists check before hash.\n\n```python\n@app.route..."
```

E16a established that this model family produces **zero** conformance to machine-readable output contracts
across 5 models × 3 formats, including with prefill. This is a **fourth format**, on the current model,
with the shortest and least ambiguous contract yet attempted — one word from a closed set of three — and it
still conforms zero times out of two. The finding is not that a probe failed; it is that **any measurement
built on this model emitting a structured verdict is measuring the contract rather than the code**, and the
canary gate is what stops that from being discovered after the numbers are published rather than before.

Note the second response: asked only about rate limiting, the model volunteered a syntax error and a timing
leak. It is not refusing to answer — it is answering a question it prefers. That is the same salience
behaviour E39 measured, showing up here in the control rather than the treatment.

**The probe was rebuilt to keep the targeted question and drop the structured answer**: prose out, read by
the same `names_class_absence` rule every other experiment uses, whose CWE-307 specificity is measured
(fires on 9.5% of prose claiming a defect, 0.0% of prose concluding all-clear). The verdict collapses to
two outcomes rather than three, because separating "no login path here" from "there is one and it is
limited" is not recoverable from prose without inventing a second unvalidated classifier — and both mean
the same thing for this measurement: the missing rate limit was not reported.

### RESULT: the probe was abandoned at the canary gate, twice. Per-class prompting is not available here.

The rebuilt prose probe reached the same gate and failed it differently — and worse. Both canaries read
**absent**, including the file carrying `@limiter.limit('5 per minute')` on the line above the handler.
A probe that reports a missing rate limit on code whose rate limit is three tokens long is measuring its
own question. Had it shipped with only the missing-limit canary — the one that passed — it would have
reported recovery, and that number would have become a product recommendation to prompt per class.

Four canary readings across the two formats, inspected directly:

| prompt format | file WITHOUT a limiter | file WITH a limiter |
|---|---|---|
| structured (one word from three) | unparseable | unparseable |
| prose, run 1 | absent | **absent** (wrong) |
| prose, run 2 (diagnostic) | **not-absent** (wrong) | not-absent |

Two things are visible here and they compound. The verdicts are **unstable between calls** at
`temperature=0`, which E22 and E31 already established and which this reproduces on a new prompt. And
underneath that, the model is not answering the question at all. Asked only about rate limiting, it
replied about a syntax error and rewrote the handler — on *both* canaries, in *both* formats. Its one
mention of the actual subject was a dismissal: `→ skipped: token mint, rate limit, add when prod`.

**What this bounds.** E39 left open whether CWE-307's near-invisibility (1 of 53 real defects named) was
capability or salience, and noted that if it were salience the fix would be per-class prompting. This
attempt to do that could not produce an instrument that distinguishes a present control from an absent
one, so **the question stays open and the obvious remedy is not available by this route**. The honest
scope: two formats, four readings, never once discriminating. That is enough to abandon the approach as
measured and not enough to prove no prompt could ever work — a stronger claim needs many more attempts,
and the instability above means each attempt needs repeated measurement to mean anything.

**What it cost, and what it saved.** Fifty-three files' worth of calls were never spent on the real run,
because the gate came first. The alternative — running the corpus, then discovering the control problem
afterwards — is how a lab publishes a recovery rate that is really a leading question. The two-canary
design is the entire reason this is a paragraph in a log rather than a retraction: **the canary that
passed is the one that would have been reported, and the canary that failed is the one that was true.**
Any probe whose prompt argues for a particular answer needs a control that can only pass if the model is
reading the code, and it needs to be built before the run, not after a surprising result.

---

## E41 — RESULT: removing the competition does not recover CWE-307. The explanation is not salience.

E39 left the question that matters commercially unresolved: across 53 corpus files all carrying a real
missing rate limit, the model named it in **one** — but every one of those files also carried an ownership
or authentication defect. An IDOR is a louder finding, and one open-ended answer has room for one
headline. If the near-zero were competition for attention, per-class prompting would fix it and this would
be an orchestration problem with a known remedy. E40 tried to settle that by asking directly and was
abandoned at the canary gate, so the question survived intact.

This settles it without touching the prompt. Same open-ended rubric, same classifier, same everything —
run over the **16 corpus files whose ground truth carries CWE-307 and no other absence class at all**.
Nothing competes for the answer.

| arm | named the missing rate limit | 95% CI |
|---|---|---|
| uncontested (nothing else absent, n=16) | **1/16 = 0.062** | [0.000, 0.188] |
| contested (E39, n=53) | 1/53 = 0.019 | [0.000, 0.057] |

One-sided Fisher **p = 0.41**. No recovery.

**The confound points the wrong way for the comfortable conclusion, which is what makes this readable.**
Files with a single absence class are markedly smaller — median **84** source lines against **189** in the
contested arm. Smaller files are *easier*, so the confound biases toward finding a recovery. The design
was stacked in favour of the salience explanation and the salience explanation still did not appear.

**What this rules out and what it does not.** Powered at 86% for a recovery to 0.30 and 74% to 0.25, the
result excludes a *large* salience effect: it is not the case that the model sees missing rate limits
easily and merely declines to mention them when something else is in the file. A *modest* effect is not
excluded — the uncontested arm's own upper bound is 0.188, and n=16 is what the corpus provides. The
honest ceiling on this line of reasoning is that interval, not the point estimate.

**Converging evidence, three independent measurements.** E34 authored files 0/4, E39 corpus contested
1/53, E41 corpus uncontested 1/16. Different file sources, different competition conditions, different
sizes; detection never rises above 6%. Decision 0027's narrowing to absent ownership and absent
authentication is supported on the negative side by this, and the negative side is the side that
constrains what can be promised.

**A defect in the measurement, disclosed.** One of E39's 53 rows holds an empty response: the runner
catches an API exception and returns the empty string, which the classifier reads as "said nothing" and
the analysis counts as a miss. A dead call and a real miss are therefore **indistinguishable** in that
arm, and the error runs toward the null. It is one row of 53 and does not move any conclusion here, but
the pattern is exactly the one that produced this lab's `RECALL=0.000` incident, and a call that failed
must never be scoreable as a model that declined. A guard now counts empty responses and the runners fail
loudly instead of quietly.

---

## E42 — RESULT: the RATE replicates exactly. WHICH FILE does not replicate at all.

E39 was published as an estimate with the note that it "needs replication before anything rests on it".
This is that replication: the identical 53 files, the identical prompt, the identical classifier, a fresh
set of calls.

**The aggregate reproduced to the digit.**

| | run A (E39) | run B (replication) |
|---|---|---|
| named ownership/authn absence | 6/53 = 0.113 | **6/53 = 0.113** |
| named rate-limit absence | 1/53 = 0.019 | **1/53 = 0.019** |
| difference | +0.094 [+0.000, +0.189] | **+0.094 [+0.000, +0.189]** |

An exact match on an instrument known to churn is itself suspicious, so the first thing checked was
whether the gateway had simply served a cache. It had not: **52 of the 53 responses differ byte-for-byte**
between runs, and the prose differs substantially, not cosmetically. These are genuinely independent
calls that happen to aggregate to the same place.

**And then the part that matters more than the agreement.**

| | |
|---|---|
| files named for ownership/authn in run A | 6 |
| files named for ownership/authn in run B | 6 |
| **files in common** | **0** |
| file-level verdicts identical across runs | 29/53 (45% churn, consistent with E22's ~40%) |

Zero overlap. Under the hypothesis that each run draws its 6 detections independently at the same rate,
the expected overlap is **0.68 files** and P(overlap = 0) = **0.47** — so zero is simply the most likely
outcome of *no per-file stability whatsoever*. If detection were a stable property of a file, the two runs
would share ~6 files; if it were half-stable, ~3.3. They share none.

**This does not weaken E39's number. It changes what the number is about.** The rate is real and
reproducible: ask this model about 53 files of this kind and roughly 11% will come back with the ownership
control named. But **the model is not identifying *which* files have the defect** — run it twice and a
disjoint set comes back. E39's estimate is a statement about a base rate, not about detection of a
particular vulnerability in a particular file, and every downstream reading has to be rewritten in those
terms.

**The consequence for the product is larger than the consequence for the paper.** A scanner that returns a
different 11% of files on each run does not give an engineer something to act on; it gives them a lottery
with a known payout rate. Two runs would produce two disjoint worklists, both defensible, neither
reproducible. Any deployment of the generative role must therefore either aggregate over repeated
readings — which changes the cost model, since the per-file call count is no longer one — or be presented
as a sampling process rather than as a finding.

**A discrepancy with E31 that this run exposes, and which cuts against an earlier decision of mine.**
These two runs give a direct churn measurement on the same 53 files: **24/53 = 45%** of file-level
verdicts changed. Of that, 21% is the benign `clean <-> non-answer` movement E31 described, but **25% of
files changed FLAG STATE** — three times E31's published "flag churn ~1 in 12" (8%). Different arm,
different corpus slice, so this is not a contradiction of E31 so much as evidence that its figure does not
generalise to this material.

It matters because **E37 was cancelled at the power gate partly on E31's number.** That gate computed the
k=3 repeated-reading design as reaching only 53.7% power "under E31's measured correlation", and dismissed
the 91.3% figure as resting on an independence assumption E31 had falsified. If flag decisions actually
churn at 25% here, readings are considerably less correlated than assumed and the true power of a k=3
design sits somewhere between those two numbers rather than at the pessimistic end. **E37's cancellation
should be revisited against the churn measured on the material it would actually run on, not against a
figure imported from a different arm.** That is not a retraction of the cancellation — it was the right
call on the evidence available at the time — but the evidence has changed and the decision is now open
again.

**Honest bounds on this entry.** n=6 per run is small, and 0 overlap is consistent with independence but
does not *prove* it — mild stability cannot be excluded from two runs of six. What can be said is that the
data show no per-file stability, and the burden now sits on the claim that any exists. The obvious next
measurement is k repeated readings per file to estimate a per-file propensity directly, which is E31's
design applied to class attribution rather than to the file-level verdict.

**Status:** E39's aggregate STANDS, replicated exactly. Its interpretation is narrowed from "the model
detects absent ownership in 11% of these files" to "the model reports absent ownership at an 11% rate,
without per-file consistency". Decision 0027's class narrowing is untouched — it was always a statement
about rates by class, and both classes' rates replicated.

---

## E43 — RESULT: neither a lottery nor detection. A mixture, with no file ever reliable.

E42 showed the class-attribution RATE reproducing exactly while the detected FILES overlapped in none of
six. Two explanations survived that, and they lead to opposite product decisions: a **lottery**, where
every file carries the same ~0.11 chance and repeated readings buy only a longer list at the same rate; or
**signal**, where a few files have high propensity and each single run samples a few of them, so repeated
readings genuinely recover detections at k times the cost. Two readings of six files cannot separate those.
Repeated readings of the same file can.

Files reported by either earlier run (**EVER**) against files reported by neither (**NEVER**), k=3
readings each, same prompt, same classifier, groups interleaved so a truncated run would still leave a
comparison rather than one finished group:

| group | per-file propensities | mean |
|---|---|---|
| EVER | 0.00, 0.33, 0.33, 0.67 | **0.333** |
| NEVER | 0.00, 0.00, 0.00, 0.33 | **0.083** |

difference **+0.250, 95% CI [+0.000, +0.500]**.

**The lottery hypothesis is the one that fails.** It predicted both groups landing near the population
rate of 0.113. NEVER did (0.083); EVER came in at three times that. Files that were reported before are
genuinely more likely to be reported again, so there is a real per-file property here — the model is not
sampling uniformly at random.

**But "signal" in its strong form fails too, and this is the part that matters.** The highest propensity
measured on any file is **0.67**. Not one file is reported reliably. The groups overlap heavily: EVER
contains a 0.00 and NEVER contains a 0.33. What the data show is a **mixture** — per-file propensities
spread roughly between 0 and 0.67, with none at either extreme.

**That mixture explains E42 exactly, which is the reason to believe it.** If typical propensities sit
around 0.1–0.35 and none approach 1, then two single-reading runs draw largely disjoint subsets *while
producing the same count* — which is precisely the otherwise-baffling result E42 reported. The
explanation was not fitted to E42; it was measured independently and turns out to predict it.

**What it means for cost and for what may be promised.** Detection accumulates with repeated readings,
which single-run numbers hide entirely:

| file's true propensity | k=1 | k=3 | k=5 |
|---|---|---|---|
| 0.083 | 0.08 | 0.23 | 0.35 |
| 0.333 | 0.33 | 0.70 | 0.87 |
| 0.667 | 0.67 | 0.96 | 1.00 |

So repeated reading is not merely defensible here, it is **required** for the generative role to mean
anything at file level — and the cost model must carry the k, because a per-file call count of one buys a
third of what a naive reading of the sensitivity figure implies. This also independently supports the
reinstatement of E37 at k=3: the union-over-k estimand is not a statistical convenience, it is the only
estimand that matches how this capability actually behaves.

### Deepened to k=9: the signal is real, and the ceiling is real too

k=3 resolves a file only to the nearest third, so the same eight files were read six more times and the
counts pooled — pooled by adding hits, not by averaging two estimates, since a k=3 and a k=6 estimate do
not carry equal weight. Wilson intervals throughout, because the case that matters here is zero hits,
where the normal approximation returns a zero-width interval that is simply a lie.

| group | file | hits/k | propensity | 95% CI |
|---|---|---|---|---|
| ever | sqli/views.py | 6/9 | **0.667** | [0.354, 0.879] |
| ever | bad/mod_api.py | 3/9 | 0.333 | [0.121, 0.646] |
| ever | education_lms/course_operations.py | 1/9 | 0.111 | [0.020, 0.435] |
| ever | config/urls.py | 0/9 | 0.000 | [0.000, 0.299] |
| never | backend/routes/auth_routes.py | 1/9 | 0.111 | [0.020, 0.435] |
| never | backend/app/api/auth.py | 0/9 | 0.000 | [0.000, 0.299] |
| never | backend/app/routes/auth.py | 0/9 | 0.000 | [0.000, 0.299] |
| never | backend/app/main.py | 0/9 | 0.000 | [0.000, 0.299] |

EVER mean **0.278**, NEVER mean **0.028**, difference **+0.250, 95% CI [+0.028, +0.500]**.

**Both of the k=3 result's soft edges hardened, in opposite directions.** The difference interval now
**excludes zero** where before it touched it, so the per-file signal is established rather than merely
directional. And the best file in the set tops out at **0.667 with an interval of [0.354, 0.879], which
excludes 1.0** — so "no file is reliably reported" is now a measured claim rather than an observation
about a small sample.

**The mixture is sharper than k=3 suggested, and it is more lopsided.** NEVER files sit at 0.028, far
*below* the population rate of 0.113 — most files carry essentially no propensity at all, while a minority
carry 0.33 to 0.67. The population rate is an average over a population where the average describes almost
no individual file. That is worth stating plainly: **0.113 is not "each file has an 11% chance"; it is a
few files at 30–70% diluted by many at zero.**

**What that changes about the product answer.** Repeated reading is not merely required, it is
*effective* — but only on the files that carry signal, and it cannot exceed their ceiling. A file at 0.667
is found with probability 0.96 by k=3; a file at 0.000 is never found however large k grows. So repeated
reading converts the capability from a sampler into something usable on part of the corpus, and does
nothing whatsoever for the rest. The honest promise is coverage of a subset, at k× cost, with no way to
know in advance which subset.

### Widened to 16 files: the estimate tightens and the shape holds

Eight more files (four per group) were then read at k=3 and pooled with the rest — 16 files, 3 runs. The
per-file numbers move, as they must at these k values; the shape does not.

| | k=9 on 8 files | **pooled, 16 files** |
|---|---|---|
| EVER mean | 0.278 | **0.291** |
| NEVER mean | 0.028 | **0.021** |
| difference | +0.250 [+0.028, +0.500] | **+0.271 [+0.104, +0.437]** |
| highest per-file | 0.667 | **0.667** |

The interval on the difference **narrows by a third and moves further from zero**. The full EVER
distribution is `0, 0, 0.083, 0.333, 0.333, 0.333, 0.583, 0.667`; NEVER is `0, 0, 0, 0, 0, 0, 0, 0.167`.
That is the mixture stated as plainly as the data allows: **seven of eight never-reported files sit at
exactly zero across every reading, while reported files spread from zero to two thirds.**

Note two files carry no signal despite being in EVER — they were reported once and never again across
twelve and three further readings. Selection into that group came from a *single* earlier reading, so some
of its members are simply files that got one lucky draw. This is regression to the mean operating exactly
as the lottery hypothesis predicted it would, on a minority of the group, while the group as a whole still
separates from NEVER. Both things are true at once, and the mixture is what makes them compatible.

**Honest bounds.** Per-file intervals remain wide — 0.667 is [0.208, 0.939] on the newest file and
[0.320, 0.807] on the best-measured one, so "two thirds" could be a third or could be nine tenths. The
group means are far better determined than any individual file, which is the usual shape of this kind of
measurement and the reason the claims above are about the distribution rather than about any file in it. The propensity
values are each estimated from three readings, so a "0.33" is one hit in three and carries large
uncertainty of its own. What is solid: the lottery is excluded, no file reached reliability, and the
mixture predicts E42. What is not: where exactly the distribution sits, which needs more files and larger
k. Group size was cut rather than k when the call budget bound, because k is what makes the distinction
visible at all.

---

## E44 — the positive control was itself a single reading of a churning instrument

The deeper propensity run refused to start: the positive control did not fire, so the harness gate stopped
it. That gate is the reason this lab no longer publishes zeros from dead harnesses, so the run stayed
stopped and the cause was investigated instead.

The gateway was healthy. **The canary churns.** Reading the identical canary file five times at
`temperature=0`:

| reading | verdict | what came back |
|---|---|---|
| 1 | flagged | "IDOR on `/api/account/<id>`. No auth/ownership." |
| 2 | flagged | "**IDOR** … no auth, no owner check" |
| 3 | flagged | "IDOR on `/api/account`. No auth/ownership." |
| 4 | **clean** | the model echoed the file back inside a code fence |
| 5 | flagged | "IDOR on `/api/account`. No auth. No ownership check." |

Four of five. The one failure is E38's exact failure mode — an echoed file, which the classifier correctly
reads as claiming nothing — reappearing in the control rather than in the data.

**So the gate blocked roughly one legitimate run in five, and had been doing so silently all along.** Every
experiment in this log used a single-reading positive control, on an instrument this lab had already
measured as non-deterministic. The control was written to protect against a dead harness and was itself
built on the assumption the harness was deterministic — the same assumption E22 falsified months of
experiments ago. It is an odd blind spot: the churn was known, and the control was never revisited.

**Fixed by reading the control `n` times and requiring it to fire at least once.** The threshold is
deliberate. This control exists to catch a DEAD harness — truncated input, broken credential, a model
returning nothing — and a dead harness scores 0 of n with certainty no matter how often it is read. So
`need=1` cuts spurious failure from ~0.2 to 0.008 while losing nothing against the failure mode the
control is for. A higher threshold would trade real robustness for the appearance of strictness.

Two details that matter more than the threshold. The tally is **printed and kept**, so a run that scraped
through on 1 of 3 leaves a visible record of a degraded instrument rather than looking identical to one
that passed cleanly. And the change was verified against a planted dead harness (0 of 3, refuses) and a
planted intermittent one (1 of 3, proceeds) before being used — because **weakening a control immediately
after it blocks you is exactly what a lab does wrong**, and the only thing separating this from that is
whether the negative control still bites. It does.

**Scope.** The fix now covers every runner in this directory that carries a positive control — the
generative discrimination run, the messy control, the class-asymmetry run and the competition run — not
only the one where the failure surfaced. Leaving the others on a single reading would have meant knowing
they each carried a ~20% spurious-stop rate and doing nothing, and the change is the same three lines in
each. The correctness-relevant half was never at risk in either case: nothing this control lets through
can be a dead harness, because a dead harness scores zero however often it is read.
