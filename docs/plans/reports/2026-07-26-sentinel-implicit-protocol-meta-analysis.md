# Meta-analysis: how this lab actually behaved (E1–E13)

Date: 2026-07-26
Scope: read-only analysis of this repository's own experimental record.
Purpose: honest input to a formal lab protocol. Failures are the point.

Primary sources: `docs/ai-sast-research-log.md` (483 lines, E1–E13 + 3 correction sections),
`docs/decisions/0018`–`0025`, `docs/journal/*`, `tests/*`, `plans/reports/redteam-*`,
git history `ad4ca80..3505212`.

Convention: where the log corrects itself, the CORRECTED value is used and the superseded one named.

---

## 1. Experiment inventory

| # | Question | Method | Published result | Verdict |
|---|---|---|---|---|
| **E1** | Can an LLM judge whether pentest findings are correct? | Narrow narrative judge vs human gold set, two provenance conditions (log:15–22; decision 0018) | Under correct `target-derived` label: **refuse 0/12 conformance**. Only a forbidden downgrade to `operator` produced answers (12/12). Deterministic oracle holds the verdict. | **STANDS** |
| **E2** | Does VHX-style LLM triage safely drop SAST false positives? | Clean-room verifier, fail-safe integrity gate, LIVE on RealVuln via Bandit→match→verify→score; 2 models × 2 provenance conditions; n=21 findings (8 real, 13 FP) (log:24–37; 0020) | Correct provenance: **refuse 15/15**, FP-reduction 0. Forbidden `operator` downgrade: FP-red 0.62 but **drops 3/8 real vulns** (SQLi, cmdi, hardcoded cred) in **both** model families. No module shipped. | **STANDS** |
| **E3** | Does an LLM that only *ranks* (never drops) add value? | `annotate.py` over code-derived facts only; memoised (37 LLM calls / 1764 findings); AUC vs deterministic rankers; paired bootstrap (log:39–57; 0021 + amendment) | Published: severity 0.750 < LLM 0.818 < **CWE-prior 0.886**, prior−LLM **+0.069 [+0.045,+0.095] "significant"**. | **CORRECTED** → under leave-one-repo-out + repo-cluster bootstrap: **+0.013 [−0.006,+0.035] = TIE** (0021 §CORRECTION). "Significantly beats" withdrawn. |
| **E4** | Is detection, not ranking, the binding constraint? | `run_multiengine.py`, Bandit + Semgrep over same 63-repo corpus, same matcher, no LLM (log:59–77; 0022) | Bandit recall 0.131, Semgrep 0.118, **union 0.188 = +44% relative recall at no precision cost**; ~37%/30% unique contribution. | **STANDS** — the audit re-ran it and it "reproduced exactly … survived order, engine-order, null-CWE and canonical-semantics challenges" (log:272–275). |
| **E5** | Where does the missed 81% sit — tuning or structure? | `analyze_cwe_gap.py` + `classify_gap.py`, bucketed by a property taken from the CWE *definition*, blind to results (log:79–99; 0023) | Published: presence 43.6% vs absence 4.6% = **9.5×**; **"absence is the larger half" (847 vs 569)**; 54 classes; 31% blind. | **CORRECTED / PARTLY WITHDRAWN** → 78 classes; presence 42.1% (268/637); absence 6.8% (35/513); ratio **6.2×**; **"larger half" WITHDRAWN**; blind **49%** (877). Direction survives (≥3.5×, never inverted); bucket SIZE declared unresolved (640 vulns / 36% unclassified). |
| **E6** | Is OpenGrep viable as a third engine? | Web research only (`plans/reports/researcher-260725-2026-opengrep-viability-report.md`) | "Official ruleset archived Nov 2025 → not viable, skip." | **CORRECTED — and never logged.** E6 has **no section in the research log**; it exists only as the target of a correction at log:325–331. Corrected by E12: archive status verified true via GitHub API, but "unusable" was too strong — VHX runs a vendored offline snapshot. *Frozen ≠ unusable.* |
| **E7** | Does the presence/absence law reproduce on independent data? | Read the project's own DefectDojo lake (`agent/lake.py`); compare CWE classes from its SAST vs DAST scanners; data collected weeks earlier for an unrelated purpose (log:101–124) | Semgrep/WebGoat: CWE-327, 330 (100% presence). Nuclei/Juice Shop: CWE-693, 200 (100% absence). **Zero class overlap.** | **STANDS (direction only)** — but its supporting text still quotes the **withdrawn** figure "CWE-200 scored 0.8% … (237 vulns)" (log:119); corrected value is CWE-200 = 54 vulns at 0% (0023 §Correction). Correction not propagated. |
| **E8** | Can a runtime differential oracle detect missing authorization? | `probe_missing_authz.py`; unauthenticated GET on non-public read-only endpoints; 401/403 = present, 2xx = absent; committed expected-protected negative controls (log:148–175) | **2 FINDINGS** (`/rest/admin/application-version`, `/rest/user/whoami`); "negative controls 3/3 → the oracle discriminates". | **WITHDRAWN.** Two successive corrections: (a) audit found a real FP mode — nonexistent paths return `200 + index.html` on this SPA (log:264–267); (b) the prober was hitting the app's direct publish port, i.e. **probing AROUND Kong**, this project's own enforcement point per decision 0010 (log:424–448, commit `c8fb026`). **Corrected result: E8 found ZERO real missing-authz vulnerabilities.** |
| **E9** | Is more of the absence bucket reachable with credential-free probes? | `probe_missing_limits.py`: bounded identical-GET burst (CWE-770/400); malformed values reusing `agent/fuzz_payloads.CORPUS` + `fuzz_signals.detect` (CWE-200) (log:177–203) | 2 findings: no throttle on `/.well-known/security.txt`; `server_error` on 3/18 payloads at `/rest/products/search`. | **STANDS (findings) / CORRECTED (safety claim).** The "read-only, nothing mutated" framing is **retracted**: the E9 verbose-error probe flipped `errorHandlingChallenge` in the target's DB (0025 §Correction 2026-07-26; commit `1b07237`). |
| **E10** | Why does the field under-invest in absence detection? | Primary data only: parsed OWASP Benchmark `expectedresults-1.2beta.csv` (2740 cases); queried live Juice Shop `/api/Challenges` (113) (log:205–234; 0024) | OWASP Benchmark: 11 categories, all presence-class; **CWE-284/639/862/863/306/307 = 0**. Absence share: Benchmark **0%**, RealVuln 47%, Juice Shop 26–53%. | **STANDS (the 0%/2740 fact) / STALE SUPPORT.** The "RealVuln 47% (847/1790)" comparison row (log:224) and decision 0024's whole framing ("*the larger half*") rest on the figure **withdrawn** by 0023. 0024 carries **no correction note** (verified: `grep -i correct docs/decisions/0024*.md` → empty). |
| **E11** | Does an off-the-shelf AI-native SAST work through this gateway? | Ran the vendored Datadog SAIST Go binary on a corpus repo with `-openai-base-url` pointed at Sentinel's gateway (log:280–307) | (1) Gateway **rejects it**: every call `500 … no sentinel_provenance declaration` — third independent time provenance blocked LLM-SAST, first time the blocker is the *protocol*. (2) **SAIST fails SILENTLY**: printed `Analysis completed successfully … 0 violations` and **exited 0** with every LLM call failing. | **STANDS** |
| **E12** | What is actually inheritable from VulnHunterX? | Cloned it (it had only ever been web-researched); clean-room boundary kept (engine source + prompts deliberately unread); ran Semgrep with VHX's 334 vendored Python rules over the same corpus/matcher (log:309–373) | **VHX's vendored ruleset beats the two-engine union**: 363 TP / recall **0.203** vs union 336 / 0.188 (+8% relative recall, +33% match rate, one tool, offline). Also: 4 conflicting licence signals (README "MIT" vs LICENSE LGPL-2.1 vs pyproject MIT vs Commons Clause on rules). | **STANDS** (self-caveated: "GT-match rate" is `tp/findings`, not true precision). |
| **—** | *(unnumbered)* Exposure gap: gateway routing coverage vs app-side enforcement | `measure_exposure_gap.py`; discover paths from `/main.js` + baseline; probe gateway and app origin as live agent identity (log:375–422) | Published: "**EXPOSURE GAP: 7 of 16 real endpoints have NO control in front of them.**" | **WITHDRAWN.** Three defects (commit `7990718`): branch-ordering bias, regex denominator artefact, and an unauthorized authorization label. Corrected: **32** real routes (not 16), **7** app-enforced (not 2), **zero authorization gaps**; the measurable property is *gateway routing coverage* (6 of 32). |
| **E13** | What is the marginal cost and yield of the LLM layer? | Same target, same gateway, `agent/supervisor.py` ×4: one `--no-llm` floor + three `--model sast-grok45`; FinOps accounting; no mocks (log:457–483) | LLM: 3 calls, ~7k tokens, **$0.048–0.051**, ~35s, 0 errors — and the **same 11 findings and 5 proposals** as the $0 deterministic path. **Marginal yield: zero.** | **STANDS**, with the lab's own hard bound stated in-line: "this measures marginal yield on one app the models have memorised". |

Also formally recorded as an experiment-that-was-killed: **Phase-3 LLM hypothesis layer — CANCELLED at the
red-team gate** before any measurement (`docs/plans/active/2026-07-26-phase3-llm-hypothesis-layer.md`,
commit `f8256f4`), on six independently reproduced grounds. See §7 — this is the single most important
fact for interpreting the headline pattern.

---

## 2. The correction catalogue

Every instance where a published claim was overturned. 15 found.

| # | Claimed | Actually true | Root cause (technical) | Durable guard now? |
|---|---|---|---|---|
| **C1** | E3/0021: deterministic CWE-prior **significantly** beats the LLM annotator, +0.069 [+0.045,+0.095] | **TIE**: +0.013 [−0.006,+0.035] | **Leaky split by structure, not by label.** `rank_baselines.py:71–76` shuffles and splits *rows* 50/50. The 1764 rows come from 63 repos / 16 CWE classes / **37 unique memoised LLM scores**, so held-out rows are near-duplicates of dev rows from the same repo and often the same file. Label hygiene was correct (prior fit on dev only, verified); independence was not. | **NO.** The corrected protocol (leave-one-repo-out + repo-cluster bootstrap) exists only as prose in 0021's amendment. `grep -rl "leave.one.repo\|repo-cluster" evaluation/ tests/` → **no match**. `rank_baselines.py:74` still carries the comment `# fit on dev ONLY — no leakage`, the exact phrase the audit called false-for-structure. **Re-running the committed instrument today reproduces the WITHDRAWN number.** |
| **C2** | E5/0023: 9.5× ratio, 54 CWE classes, absence is the larger half (847 vs 569), 31% blind | 6.2×, 78 classes, larger-half **withdrawn** (513 vs 637), 49% blind | **Label-attribution bug.** `analyze_cwe_gap.py` attributed each hit by `min(cwes)` over *primary ∪ acceptable* instead of the ground truth's `primary_cwe` — **61% of vulns booked under the wrong class** (798→259, 78→77, 639→284, 434→20). | **PARTIAL.** Fixed in code (`run_spike.load_gt` carries `primary`; both files reference `primary_cwe`). But **no test suite covers `analyze_cwe_gap.py`, `classify_gap.py`, `rank_baselines.py` or `run_multiengine.py`** (`grep -rl` over `tests/` → only `ai-sast-verifier-test.sh`, which tests verifier logic offline). Regression is possible and undetectable. |
| **C3** | `classify_gap.py` printed "the absence bucket is the LARGER half" | False in the corrected run (513 vs 637) | **Hardcoded conclusion in output.** A narrative string not derived from the data it accompanied; survived into a run where it was false. | **YES** — now derived (`classify_gap.py:83–89`, with the reason recorded in the comment). |
| **C4** | E8: `/rest/user/whoami` is a missing-authz finding | Not a finding | **Oracle fails open on the SPA fallback.** A path that does not exist returns `200 + index.html`; the oracle read status only → `control-absent`. | **YES** — nonexistent-path negative control, HTML-fallback guard, `allow_redirects=False`, baseline-`confidence` gate; hypothesis-labelled endpoints now report `label-unverified` (log:264–267). |
| **C5** | E8: 2 real missing-authz vulnerabilities | **ZERO** | **Measured around the control.** The prober defaulted to the app's direct publish port `:13000`; authorization is enforced at Kong `:18443` (decision 0010). Same endpoint: app `200`, gateway `401`. The prober bypassed the control under test and manufactured the finding. | **YES, structurally** — verdicts are taken at the enforcement point; an unreachable enforcement origin **errors** rather than judging from the app (0025). Pinned by `tests/defence-in-depth-test.sh` **DD2** with a negative control ("the classifier can fall back to the app origin" must fail). |
| **C6** | E8 v1: `{"version":"20.1.1"}` from an *administrative* endpoint downgraded to "no data" | It is the finding | **Confused impact with verdict.** Response SIZE was used as the verdict; size measures impact, the missing control is the finding. Self-caught. | Partial — recorded as a lesson (log:169–172); the substance/impact separation is now pinned by DD9 (C12). |
| **C7** | E9 v1: `/rest/products/search` "handles errors generically" | It leaks `server_error` | **Instrument weaker than the tool beside it.** v1 used five hand-invented payloads while the project's own fuzzer had already recorded `stack_trace` on that exact endpoint. | **YES, by construction** — the prober now imports `agent/fuzz_payloads.CORPUS` + `agent/fuzz_signals.detect`. Lab rule extracted: "*a disagreement between two instruments is a bug signal, not noise*" (log:196–198). |
| **C8** | Probers are "read-only, nothing mutated" | **False** — runs are state-perturbing | **Safety asserted from the HTTP verb.** Juice Shop writes a `solved` flag on plain GET; this project's own probes had already flipped `securityPolicyChallenge`, `exposedMetricsChallenge`, `errorHandlingChallenge`. HEAD-first explicitly rejected as mitigation (Express runs the same handler). | **YES** — the solved-set is snapshotted before/after every run and the diff published as `target_state_change.flipped_by_this_run` (0025; commit `1b07237`). Contamination is measured, not denied. |
| **C9** | Exposure gap: 2 endpoints are app-enforced | **7** | **Branch-order bias.** The classifier asked "is this HTML?" before "is this 401/403". This app renders 401 as `text/html`, so app-enforced endpoints were discarded as "not an endpoint" — biased **in the direction that enlarged the reported gap**. | **YES** — split into two orthogonal axes (routing / app posture). `DD7` (401+html = enforced; 200+html still discarded) and `DD8` (routing verdict must be constant across every app posture), both with negative controls. |
| **C10** | Exposure gap: 16 real endpoints | **32** | **Discovery regex too narrow.** Matched only quote-delimited path literals, missing Angular template literals (`` `${host}/rest/languages` ``). The denominator was an artefact of one regex. | **YES** — discovery sources now **fail closed** instead of silently reporting a smaller gap from a partial enumeration (commit `7990718`). |
| **C11** | "7 endpoints have NO control in front of them" | **Zero authorization gaps** | **Claim the instrument never tested.** The measurement answered "does the gateway route this?"; the label asserted "is this authorized?". Reading all 7 bodies: every one is public-by-design (catalogue, delivery tiers, CAPTCHA, photo wall, CTF hints). | **YES** — property renamed to *gateway routing coverage*; DD8 keeps the routing axis independent of app posture. |
| **C12** | 0025: "**100%** of non-public routed endpoints have no authorization of their own" (2 of 2) | **1 of 2** | **Status measured, substance not.** Any non-HTML 2xx counted as disclosure. `/rest/user/whoami` returns `200 {"user":{}}` — 11 bytes, no protected data: the app *withholds* by emptiness rather than by 401. Counting it as a bypass inverted its meaning. | **YES** — `_has_substance()` structural check in `map_defence_in_depth.py`; **DD9** asserts both the empty-shell and the real-payload case. |
| **C13** | E6: OpenGrep is "not viable, skip" | Archive status true; "unusable" false | **Unverified external fact asserted as a finding.** The conclusion came entirely from web research; nobody cloned it. | **NO mechanism** — only the E12 precedent ("clone and verify for real"). Same class as C14. |
| **C14** | ~19 tools "surveyed" read as evaluated | Only **2** (Bandit, Semgrep) had ever been EXECUTED | **Research reported at the same confidence as measurement.** Surfaced by an honest self-audit; it is what motivated E11 and E12 (log:281–283, 310–312). | **NO mechanism.** No field distinguishes "researched" from "executed" in the log. |
| **C15** | Week-12 presentation draft: AI detected the findings, confirmed them and removed false positives; per-run cost from a price table; proposals = confirmed vulns; the gateway finding came from the AI; "Sentinel fills the absence gap" | All six contradicted by the project's own data | **Narrative drift downstream of the measured record.** A derived document re-asserted the pre-measurement intuition; e.g. the gateway-finding path *contains no model by construction* (DD1). | **PARTIAL** — `docs/plans/reports/2026-07-26-week12-measured-evidence-sheet.md` traces every number to a source file with corrections inline. Caught by review, not by a check. |

**Pre-E1 ancestry (same failure family, different era)** — `docs/journal/2026-07-23-checks-that-passed-because-they-checked-nothing.md`
records seven instances in one session: a guardrail that read `data["messages"]` while the target scanner
uses the Responses API `input` key (undeclared credential-shaped prompt → HTTP 200, no audit line,
plaintext to the trace store); `grep -q` swallowing the stream its own assertion consumed; a port
pattern matching `PORT:PORT` that could never match `0.0.0.0:4000`; an `ast.walk` "ordering" assertion
that compared a set; a cross-check that was an identity, written into a commit message as evidence; an
FP count over a gitignored (absent) corpus; and a test that was never written. This journal is the
origin of the lab's fail-closed/negative-control reflex — every later guard is a descendant of it.

---

## 3. Root-cause taxonomy

| Class | Instances | n | Durable guard today |
|---|---|---|---|
| **Measured around the control** | C5 (E8/Kong) | 1 | **Yes, structural.** Enforcement-point judging + error-on-unreachable + DD2 with negative control. The lab's own lesson: "*probe at the enforcement point, never around it*" (log:450). |
| **Instrument fails open / passes vacuously** | C4 (SPA 200), C10 (partial enumeration), C15-adjacent, plus 7 pre-E1 journal cases; and observed **in a third party**: E11's SAIST exit 0 on total LLM failure | 10+ | **Yes, and it is the lab's strongest habit.** Every suite carries negative controls by policy (`tests/week10-eval-test.sh:5–6`, `tests/defence-in-depth-test.sh:5–8`, `tests/ai-sast-verifier-test.sh:1–4`); dual fail-closed canaries in 0025 (session canary for identity liveness, *synthetic* canary for prober liveness — synthetic on purpose so a fixed system cannot stop it firing); discovery sources fail closed. |
| **Claim not supported by the instrument** | C11 (routing ≠ authorization), C12 (status ≠ substance), C6 (size ≠ verdict), C3 (hardcoded conclusion), C15 (six narrative claims) | 5 | **Partial.** DD8/DD9 pin the two runtime cases; C3 fixed in code. Nothing prevents a *new* label outrunning a *new* measurement — this is the most-repeated class and has no general mechanism. |
| **Label / attribution bug** | C2 (`min(cwes)` vs `primary_cwe`, 61% misattributed) | 1 | **Partial** — fixed in code, **untested**. No suite covers the SAST measurement stack. |
| **Leaky or non-independent split** | C1 (row split over 63 repos / 37 unique scores) | 1 | **No.** Corrected protocol lives in prose only; the committed script still ships the row split. |
| **Ordering / branch-logic bias** | C9 (HTML checked before status), C6 (impact before verdict) | 2 | **Yes** for C9 (DD7 + DD8 orthogonal axes). |
| **Unverified external fact asserted as finding** | C13 (OpenGrep), C14 (~19 "surveyed" tools) | 2 | **No mechanism.** Corrected only by later doing the work (E11, E12). |
| **Safety property assumed from a proxy** | C8 ("read-only" inferred from the verb GET) | 1 | **Yes** — before/after state diff published every run. |
| **Instrument weaker than an adjacent tool** | C7 (hand-invented payloads vs the project's own fuzz corpus) | 1 | **Yes, by reuse** — and the extracted rule ("inherit, don't rebuild, applies to internal tooling too") is now a stated norm. |
| **Correction not propagated to dependents** | E7 quotes withdrawn CWE-200 figures (log:119); E10's comparison row and **all of decision 0024** rest on the withdrawn "larger half" | 2+ | **No mechanism.** No back-reference index from a corrected claim to the documents that cite it. |

Direction of bias, stated bluntly: of the 12 quantified corrections, **every single one moved a claim
against the lab's own headline** — the gap was smaller (C9, C11, C12), the finding did not exist (C4,
C5), the significance vanished (C1), the ratio shrank and the size claim died (C2, C3), the denominator
doubled (C10), the safety claim was false (C8). Zero corrections found the lab had *understated* a
result. That is either unusually honest error-hunting or a systematic optimism in first-pass instrument
design; the record cannot distinguish, but the base rate is worth watching.

---

## 4. What consistently worked

1. **Negative controls, mandated per-assertion.** The policy is written into the test headers:
   "Every 'must hold' claim carries a negative control (a mutated input would fail the same
   assertion)" (`tests/week10-eval-test.sh:5–6`). Caught: DD1-neg proved the LLM-import detector was
   not a vacuous grep; DD7-neg proved content-type could mask an app-side control; DD9-neg proved the
   substance check still registers a real payload; EA2-neg mutates a planted label to prove the oracle
   is not a rubber stamp. E8's own negative controls (3/3 protected) **failed to catch C5** — they
   were all "expected-protected" endpoints and none tested whether the prober was talking to the
   enforcing layer. The lab drew the right lesson: "*a control-plane sanity check belongs in every
   runtime oracle*" (log:452).

2. **Fail-closed canaries with distinct jobs.** 0025 runs two: a **session canary** (an ACL-permitted
   endpoint must return 2xx with the minted token, else refuse to run — without a live identity every
   reply is 401 and everything looks protected) and a **synthetic canary** (an unrouted path must
   classify `not-routed` every run, *deliberately not a real finding*, so fixing the system cannot
   silence the canary). Pinned by DD5 and DD6. This is a direct engineering response to E11's
   third-party silent-failure observation.

3. **Structural / AST-level invariants instead of behavioural ones.** DD1 asserts *no LLM surface is
   reachable from the verdict path* by inspecting imports and call sites — "a component that never
   consults a model cannot be talked out of a finding by one"
   (`tests/defence-in-depth-test.sh:27–28`). This is the enforceable form of a policy that would
   otherwise be a promise.

4. **Deterministic oracles holding the verdict.** E1 → decision 0018: the LLM judge is *demonstrated*
   and measured, never trusted; the verdict comes from a deterministic oracle scored against a
   synthetic corpus with a planted, known-by-construction confusion matrix (EA2: TP=3, FP=1, FN=3,
   TN=2 with one FN per pipeline stage). Ground truth by construction, not a self-written baseline.

5. **Fail-safe defaults in the LLM path.** `tests/ai-sast-verifier-test.sh` V2: a refusal or prose
   reply parses to `unknown` → **effective KEEP**. The one design choice that made E2's negative
   result safe to run live at all.

6. **Adversarial review by someone who did not write the instrument.** This is the highest-yield
   practice in the whole record:
   - The 2026-07-25 independent audit re-executed the entire stack and **reproduced every published
     number exactly before challenging it**, then found C1, C2, C3, C4 (log:236–278).
   - Two NOT-CLEAN red-team lenses rewrote the absence-coverage plan twice
     (`plans/reports/redteam-260726-0006-absence-coverage-oracle-validity.md`; commits `fc8f8f5`,
     `6c2a3a4`) and one of them found C5.
   - A measurement-validity red-team returned **CANCEL-THIS-PHASE** on Phase 3, with all six findings
     independently reproduced against the live harness (`redteam-260726-0034-phase3-measurement-validity.md`).
   - Four-lens red-teams are standard per week (`plans/reports/redteam-2607*-week{6,7,8,9,10}-*`:
     assumption-destroyer / failure-mode / scope-complexity / security-adversary).
   - The lab's own verdict: "**self-review does not catch the errors that matter**" (log:455) and
     "Two of my conclusions were wrong in ways I could not see from inside" (log:278).

7. **Leave-one-repo-out (as a *concept*).** It converted a headline into a tie (C1) — the single
   highest-value statistical move in the record. It is also not committed (§6).

8. **Independent, non-purpose-collected data.** E7's strength is explicitly that "nothing about this
   data was collected to test this hypothesis" (log:122–123) — the project's own lake, different
   targets, different tools, weeks earlier. Zero class overlap.

9. **Committed reproducible baselines + a $0 floor arm.** Negative results ship as scorecards
   (`baseline-260725-{sast-sol,grok45}.json`, `annotate-baseline-260725.json`,
   `multiengine-baseline-260725.json`, `gap-classification-260725.json`), and E13 ran a `--no-llm`
   deterministic floor as the control arm before three LLM runs. The floor arm is what made "marginal
   yield: zero" a measurement rather than an impression.

10. **Primary-source verification over literature.** E10 parsed OWASP Benchmark's own
    `expectedresults-1.2beta.csv` and queried the live `/api/Challenges` rather than citing a paper;
    E12 cloned VHX and hit the GitHub API for the archive flag instead of trusting E6's research.

11. **Killing an experiment at the gate.** Phase 3 was cancelled *before* spend because its A/B could
    not be blinded and its finding class was tautological. Not sunk-cost-continued.

12. **Redaction at capture + gitignored artefacts** (DD3, DD4, with a negative control proving the
    seam alters a planted JWT+email) — the only guard class that protects the *user* rather than the
    result.

---

## 5. The implicit protocol (descriptive, as practised in E8–E13 + 0025)

Reconstructed from the most mature experiments. This is what the lab *does*, not what it says.

1. **Motivate from a prior measured result or an honest self-audit.** Every mature experiment names
   its parent: E9 ← E8's scope limit; E10 ← E5's "why does the field under-invest"; E11/E12 ← the
   audit finding that only 2 of ~19 tools had been executed; E13 ← the Week-12 business case needing
   a cost-and-yield anchor.
2. **State a falsifiable hypothesis in one sentence**, in the log, before the method.
3. **Scout the live target/harness for feasibility before planning.** 0025's plan was reframed at the
   validate gate when it turned out Kong routes 8 endpoints, only 2 non-public, both correctly
   protected → absence-recall could only ever measure 0/2.
4. **Write a plan under `docs/plans/active/` for anything spanning sessions**, then submit it to a
   multi-lens adversarial red-team **before implementation**. Outcomes are real: v1→v2→v3 rewrites,
   or CANCEL.
5. **Design the instrument to fail closed and to discriminate.** Concretely: negative controls per
   assertion; a liveness canary and a synthetic canary; refuse-to-run without a live identity;
   error rather than fall back to a weaker origin.
6. **Prefer a deterministic mechanism; exclude the LLM from any verdict path structurally**, and
   assert that exclusion with a test (DD1).
7. **Take verdicts at the enforcement point**, never around it; consult secondary origins only to
   refine severity.
8. **Run offline unit-level proof against committed corpora and captures first**, then the live run.
9. **Run a control arm** — a `--no-llm`/deterministic floor, or the pre-existing tool's output.
10. **Reuse the project's own instruments** rather than reinventing them; treat disagreement between
    two instruments as a bug signal.
11. **Redact evidence at capture; gitignore identity-bearing artefacts.**
12. **Record the result in `docs/ai-sast-research-log.md` with hypothesis / method / data table /
    conclusion — including the instrument bugs found along the way, in the entry itself.**
13. **State the coverage bound in the same breath as the finding** ("8 routed endpoints, gateway-fronted
    slice only, never whole-app coverage").
14. **Promote a durable result to `docs/decisions/`** with Status, Context, Decision, Measured result,
    Consequences, and an explicit Deferred list where each deferral needs its own decision.
15. **Submit the published result to an independent adversarial re-run.** The re-runner reproduces the
    numbers first, then attacks them.
16. **On a correction: amend in place, keep the superseded value visible, name what falls and what
    stands, and pin the fix with a new test carrying the negative control that would have caught the
    original.** DD7–DD10 exist for exactly this reason; commit `7990718`'s message states each one.
17. **Commit message carries the reasoning**, not just the change (see `c8fb026`, `1b07237`, `7990718`,
    `f8256f4` — these are the most informative artefacts in the repo after the log itself).

---

## 6. Gaps — where the implicit protocol is silent or inconsistent

**Choosing what to study next.** No mechanism. The log has an "Open questions" block (lines 140–146)
that has never been reconciled: of its three questions, one was answered by E12 (OpenGrep), one is
still open (how much of the absence residual the syndicate recovers), and one was never attempted
(gosec/Brakeman/js-x-ray). Selection is opportunistic — driven by what a self-audit embarrassed, or
what the next deliverable needed.

**Hypothesis before measurement.** Present in E1–E5, E7–E10, E13. **Absent** in E11, E12 (both framed
as "motivation", i.e. exploratory), and in the exposure-gap section, which has a hypothesis but
published its claim *before* the code review that invalidated it. There is no pre-registration: nothing
distinguishes a hypothesis stated before the run from one written up afterwards.

**Success criteria defined in advance.** Inconsistent, and the inconsistency is consequential. The
absence-coverage plan v1 *did* set a ≥0.9 precision gate — and it was **withdrawn** when found
unachievable (`fc8f8f5`, `6c2a3a4`), then the outcome itself was reframed from "detect missing authz"
to "measure where authz is enforced". That may be the right call on an unachievable target, but the
protocol has no rule for *when* moving the goalposts is legitimate versus when it launders a null
result into a finding.

**Sample size and power.** Never discussed. Actual n: E1 = 12 judgements; E2 = 21 findings (8 real);
E7 = 11 SAST + 21 DAST findings (self-caveated); E8 = 5 endpoints; 0025 = 2 non-public routed
endpoints; E13 = **1 target**, 3 repeats. E3 is the only experiment with a bootstrap CI, and it is the
one whose significance evaporated. 0021 itself records that an earlier n=21 subset "was
unrepresentative — it made severity look anti-correlated" — the lesson was noted but never turned into
a minimum-n rule.

**When a result may be published as a decision.** No stated bar. Compare: 0020 shipped from n=21;
0023 shipped a "law" that lost its magnitude and half its size claim a day later; 0025 shipped and was
corrected **twice on the same day**. Decisions are written at the moment of the result, and corrected
afterwards. That is honest, but it means a decision record is not a settled artefact — and downstream
readers cannot tell which decisions have survived an independent audit and which have not.

**Correction propagation.** No back-reference index. Concrete live inconsistencies as of this writing:
E7 (log:119) and E10 (log:224) still quote the withdrawn `CWE-200 0.8% / 237 vulns` and
`47% (847/1790)` figures; **decision 0024 contains no correction note at all** and its title claim
("cannot measure **half** of real vulnerabilities") depends on the "larger half" that 0023 withdrew.

**Guard asymmetry between the runtime and the measurement stacks.** Every runtime correction (C4, C5,
C8, C9, C10, C11, C12) is pinned by a test with a negative control (DD1–DD10). **No correction to the
SAST measurement stack is pinned by anything.** `analyze_cwe_gap.py`, `classify_gap.py`,
`rank_baselines.py`, `run_multiengine.py` have zero test coverage. The most serious consequence: the
leave-one-repo-out protocol that produced the corrected TIE (C1) is not in the code, and
`rank_baselines.py:71–76` still ships the row split with the comment `# fit on dev ONLY — no leakage`.
**Anyone re-running the committed instrument reproduces the withdrawn +0.069, not the corrected +0.013.**

**Experiment identity and completeness.** E6 has no log entry despite having produced a published
conclusion that later needed correcting. The exposure-gap experiment has no E-number. There is no
register that would make either omission visible.

**"Researched" vs "executed" is not a recorded field.** C14 (only 2 of ~19 tools ever run) was found
by an ad-hoc audit and can recur.

**No stopping rule for correction.** 0025 was corrected twice in one day by two different reviewers.
Nothing says how many independent lenses a result needs before it is considered settled — or whether
"settled" exists.

---

## 7. The uncomfortable question

**The pattern.** Every measured AI-vs-deterministic contest ended with AI losing, tying, or the
question being unanswerable. The lab states this as its headline
(`docs/2026-07-26_NguyenManhQuy_Week12.md` §4; commit `f7f3cda`): five contests — judge refuses 12/12
(0018), verifier drops 3/8 real vulns (0020), annotator ties (0021), syndicate LLM adds 0 findings
(E13), third-party AI-SAST cannot connect and exits 0 on failure (E11).

**Evidence that this is a real finding about AI:**

- **The safety failure is not a scoring artefact.** E2's verifier marked real SQLi, command injection
  and a hardcoded credential as false positives — in *both* model families, at 3/8 each (0020). That
  is a behavioural fact about what the model does to a recall-critical decision, independent of any
  benchmark design.
- **It reproduces across models and surfaces.** The refusal-under-correct-provenance result appears
  three times independently: the Week-10 judge (0018), the SAST verifier (0020), and a third-party
  tool that could not even connect (E11) — two model families, three different task shapes.
- **The deterministic wins survived adversarial re-execution.** The audit re-ran E4 over all 63 repos
  and it "reproduced exactly … survived order, engine-order, null-CWE and canonical-semantics
  challenges (union 336 either way; overlap 110/124/102 verified)" (log:272–275). E12's ruleset win
  (0.203 vs 0.188) is the same shape: better deterministic tooling, not more model.
- **E13 was a genuine controlled A/B**: same target, same gateway, same code path, a $0 deterministic
  floor arm, three LLM repeats, 0 errors, FinOps-metered. Same 11 findings, same 5 proposals.
- **The lab corrects against itself, not only against AI.** Its pro-deterministic claims took the
  heaviest corrections in the record (C1 killed a significance result the lab wanted; C2 killed the
  9.5× law's magnitude and size claim; C5 destroyed its own novel runtime finding; C11 erased a
  headline "7 unprotected endpoints"). The correction process is not visibly biased toward the
  preferred conclusion.

**Evidence that this could be an artefact of how the lab designs experiments:**

- **Role selection is systematically unfavourable, by the lab's own design invariant.** Every measured
  AI role is a *verdict or gate* role: judge (E1), drop-verifier (E2), ranker (E3). The lab's core
  rule is that no LLM may hold a decision that removes a finding — so AI is repeatedly measured in
  precisely the position the architecture forbids it to occupy. DD1 asserts structurally that no model
  is reachable from the verdict path. **The generative role — propose where to look, hypothesise
  missing controls — has ZERO measurements**, because Phase 3 was cancelled at the red-team gate
  (`f8256f4`). The one experiment that would have tested AI in a role it might be good at never ran.
- **Two of the five "AI loses" results are results about the lab's own protocol, not about the model.**
  E1's and E2's refusals are responses to Sentinel's provenance datamark — the lab's own artefact
  (decisions 0006/0015). Under the alternate label the same models *did* produce verdicts (12/12,
  15/15). "The LLM cannot be safely instantiated" here means "our contract forbids the configuration
  in which it would answer". E11 is stronger evidence of a *protocol* incompatibility than of a model
  deficiency — the log itself says so ("the first where the blocker is the *protocol*, not the model").
- **E3's setup is close to a tautology.** The LLM was given code-derived facts **only** — rule id, CWE,
  severity — and never the source code, which is its strongest input. The competitor is a
  Laplace-smoothed `P(real|CWE)` fitted on the same corpus. The contest is therefore "zero-shot guess
  at P(real|CWE)" versus "fitted P(real|CWE)" over the same three features. That a supervised fit
  matches an unsupervised guess is not a finding about AI's ceiling; and the corrected result is a
  **TIE**, which the standing-conclusions summary (log:130–132) flattens into the losing narrative.
- **E13 has no headroom and a memorised target.** The deterministic floor already produced 11 findings
  and 5 proposals; the experiment cannot detect an LLM contribution above a ceiling the floor already
  reached. The target is Juice Shop. The log states the bound itself: "this measures marginal yield on
  one app the models have memorised, not on a client's private code, where the LLM's contribution is
  untested" (log:481–483). The Phase-3 cancellation is blunter: "the residual evidence is verbatim
  Juice Shop route names on an Express+Angular stack every model has memorised. Answering the question
  needs a target the model cannot know, not this one."
- **n is small nearly everywhere the AI lost.** E1 n=12, E2 n=21 (8 real), E13 n=1 target. No power
  analysis anywhere. A 3/8 recall loss on 8 positives has a very wide interval; it is a strong
  *safety* signal and a weak *rate* estimate.
- **Single language, single corpus, single app.** RealVuln is Python-only; the runtime work is one
  Node/Angular app behind one Kong instance; two model families. The Week-12 report lists all of this
  in its own ten-gap table, including "generalisation across model families (only 2)" and "coverage of
  the whole app (only the gateway-fronted slice)".

**Not resolved.** Both readings are consistent with every measurement in the record. What the record
*does* support unambiguously is a narrower claim than the headline: **on this corpus and this target,
an LLM placed in a verdict, gate, or ranking role produced no measured gain over a deterministic
mechanism, and in one configuration produced a measured safety loss.** Whether AI adds value in a
generative or hypothesis-forming role is **untested here** — the lab designed that experiment, proved
it undecidable on its only target, and cancelled it.

The lab already knows the discriminating experiment and has written it down as an open question to its
own stakeholders: *"does this handover need a **second** target — not Juice Shop, which the model has
memorised — to demonstrate generalisation?"* (`docs/2026-07-26_NguyenManhQuy_Week12.md` §10 Q3). Until
that runs, on a target the models cannot have memorised, with the LLM in a proposing rather than
deciding role, and with a success criterion fixed in advance, the headline pattern should be read as
**strongly established within the lab's chosen frame and untested outside it.**

---

Status: DONE
Summary: Meta-analysis written to `docs/plans/reports/2026-07-26-sentinel-implicit-protocol-meta-analysis.md` — 13 experiments inventoried (5 STANDS-with-caveats, 4 CORRECTED, 2 WITHDRAWN, 1 never logged), 15 corrections catalogued into 10 root-cause classes, the implicit 17-step protocol reconstructed, and the AI-always-loses pattern assessed from both sides without resolution.
Concerns: Two live defects found while analysing, both read-only-reported and unfixed: (1) `evaluation/sast-fp-discrimination/rank_baselines.py:71–76` still ships the row-level split and the `# no leakage` comment, so re-running the committed instrument reproduces the WITHDRAWN +0.069 rather than the corrected +0.013 tie — the leave-one-repo-out protocol exists only as prose in decision 0021; (2) decision 0024 carries no correction note and its central "larger half" claim was withdrawn by 0023, as do the residual figures at log lines 119 and 224. The entire SAST measurement stack has zero test coverage, unlike the runtime stack (DD1–DD10).
