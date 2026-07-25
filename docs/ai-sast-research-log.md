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
| E17 | generative role, powered replication | **STANDS** — p = 0.024; framing corrected (the deterministic zero is *structural*, so it is capability addition, not a horse race) |
| E21 | is low sensitivity an artefact of non-answers? | **STANDS (negative)** — 53% of non-answers resolve but 9/10 resolve to *clean*; sensitivity 0.167 -> 0.183. ~19% is **real** |
| E20 | file role or missing control? | **INCONCLUSIVE (withdrawn)** — reused arm A′ against a freshly measured arm C under a 36%-unstable instrument |
| E23 | memorisation, valid design | **STANDS (bounded)** — anonymised 14/53 vs original 11/53, diff +0.057 [−0.038,+0.151]: no collapse, so surface memorisation is not the driver; equivalence NOT established |
| E22 | is the instrument deterministic? | **STANDS** — **no**: 36% verdict flips, 0/14 identical prose at temperature 0 |
| E19 | capability or memorisation? | **INCONCLUSIVE (withdrawn)** — the paired design assumed a deterministic instrument; E22 measured 36% verdict flips, which alone explains the null |
| E18 | is it detection, or reaction to messy code? | **STANDS** — **detection**: defective code with no absent control draws flags at 3/80, indistinguishable from clean (p = 0.59); vs absence arm p = 0.010 |

**The pattern worth reading this table for:** of the corrections above, **every quantified one moved a
claim against this lab's own headline**. None ever found an understatement.

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
model discriminates. E18 (running) tests whether that discrimination is class-specific or mess-driven.

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
