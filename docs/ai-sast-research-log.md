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
