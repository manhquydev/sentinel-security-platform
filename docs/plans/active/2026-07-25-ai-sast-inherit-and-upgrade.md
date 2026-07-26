# Execution Plan: AI-SAST Inherit-and-Upgrade (grounded-and-hardened triage)

Date: 2026-07-25

## Status

**COMPLETE — spike ran, thesis DISPROVEN, documented (decision 0020), no module shipped.** Phase 0
(license + DESIGN) and Phase 1 (harness + live two-model spike on RealVuln FP-traps) both done. The
measure-first/fail-allowed outcome fired: both `sast-sol` and `grok-4.5` refuse to grade target-derived
code under correct provenance (FP-reduction 0), and drop real vulns when forced via the operator
downgrade (recall floor fails) — so the naive inherit-LLM-triage thesis is disproven and NO verifier
module ships. Honest next direction: broader deterministic SAST foundation + a non-load-bearing LLM
annotator. Scorecards: `evaluation/sast-fp-discrimination/baseline-260725-{sast-sol,grok45}.json`. The three gating decisions stand:
clean-room re-implementation of the method; measure-first spike bar; verifier verdict measured, never
trusted.

**Progress 2026-07-25:** Phase 0 DONE (RealVuln license Apache-2.0 primary-source-verified;
`docs/ai-sast-verifier-design.md` complete). Phase 1 measurement HARNESS built + tested offline
(`agent/verifier/{verify,gate}.py` + clean-room CWE question sets + `evaluation/sast-fp-discrimination/`
scorer + `fetch.sh`; `tests/ai-sast-verifier-test.sh` 5/0 with negative controls incl. the fail-safe
integrity gate and the recall-floor failure). **Live run pending** — validate `fetch.sh` vs the real
manifest, run Semgrep on a bounded subset, build the SARIF↔ground-truth matcher, run the verifier live,
score. No FP-reduction number is claimed until that runs; a miss is an accepted negative result.

Two red-team lenses ran
(`plans/reports/redteam-260725-0919-ai-sast-inherit-{feasibility,license-scope}.md`): feasibility
NEEDS-WORK, license/scope TRIM. Both blocking findings are reconciled below and the plan is **cut to
the smallest honest increment**. Synthesis: `plans/reports/synthesis-260725-0919-sast-inheritance-dossier.md`.
Research: `researcher-260725-0856/0917-*`. **No implementation until the user resolves the open
decisions AND the Phase-0 gate passes.**

## What the red-team changed (honest reframe)

The v1 plan over-claimed *inheritance* and *reuse* and ran on wrong license facts. Corrected:

1. **Licenses were wrong** (verified against actual LICENSE files): VulnHunterX = **LGPL-2.1** (README's
   MIT is false); RealVuln = **Apache-2.0** (not MIT); **DiverseVul = unlicensed → dropped**;
   ZeroFalse = **unverified**; OpenGrep = **LGPL-2.1** (not Apache). The v1 doc asserted "MIT" facts the
   research had only *inferred* — a real misapprehension, now fixed. **Phase 0 must primary-source
   every license before any adoption.**
2. **`guard.py` cannot adjudicate a TP/FP verdict** — it only catches a narrative contradicting
   *code-computed* facts; a verdict has no code ground truth to contradict, and its downplay/
   false-conclusion regexes would quarantine every honest FP. → The verifier verdict is **measured
   against a labelled corpus** (that is the "not trusted"); `guard.py`'s only reuse is the narrow
   CWE-fabrication check; a *new* verdict-integrity check is specced in DESIGN, not claimed as reuse.
3. **`benchmark/scoring` does not measure finding-level FP-traps** — it is OWASP-Java, per-test-case,
   11 CWE. A finding-level FP-trap scorer is **net-new** (honestly labelled), following the existing
   fail-closed-corpus pattern.
4. **The spike cannot use OWASP** (zero FP traps — symmetric safe twins). It must run on a
   **license-clean FP-trap corpus (RealVuln)**, so the FP-trap scorer is a Phase-0/1 *prerequisite*, not
   a later phase. The measurement is a **live-LLM** experiment (thousands of gateway calls) — its
   *outputs* are committed as fixtures for offline re-scoring; the live run is budgeted + kill-switched.
5. **Multi-turn provenance has no schema** — the gateway is stateless per-request with only
   `operator`/`target-derived`; accumulated assistant messages fit neither (elevating model output =
   the forbidden trust inversion). → Design the verifier as **single-turn-per-finding** (one operator
   rubric + one target-derived code/finding message, batched questions, no accumulated assistant
   turns), sidestepping the hole. Resolved in Phase 0.
6. **The "inherit VHX code" path is blocked** (LGPL + Week-12 conveyance/handover + VHX source never
   read + its context extraction is CodeQL-coupled, which we defer). → The executable path is **Branch B:
   clean-room re-implementation of the guided-question *method*** (a small Sentinel-authored template
   set; do **not** copy VHX's 394 templates — they are copyrightable).
7. **Phase 1 (OpenGrep/gosec/Bandit) is orthogonal** — it proves nothing about the verifier and risks
   the Weeks 1–10 lake. → **Cut from this plan**; the spike runs on the *existing* Semgrep/Trivy/Nuclei
   SARIF. Foundation-broadening becomes a separate, later, independently-gated initiative.

## Outcome (cut to the provable core)

Prove — or honestly disprove — one thesis before building anything: **a clean-room guided-question
verifier, run through Sentinel's provenance gateway with its verdict measured (not trusted) against a
license-clean FP-trap corpus, reduces false positives on real FP-traps beyond both raw SAST and the
deterministic-first gate alone, without regressing recall.** If it does, a follow-on plan integrates it;
if it doesn't, that is a documented negative result (like Week-10's judge) and no module is built.

## Constraints (non-negotiable)

- Primary-source license verification before ANY external asset is used; **never commit unlicensed or
  copyleft data** — commit the manifest+scorer, gitignore + fail-closed-fetch the corpus (the existing
  `benchmark/targets/` pattern; `.gitignore` already does this for OWASP/WebGoat).
- Clean-room only: inherit the *method*, never VHX's template text/source.
- Verifier verdicts are **measured against labels, never load-bearing**; provenance-labelled,
  single-turn (no trust inversion); reasoning routed through the PII seam (0017) before any persist.
- Fail-closed, non-vacuous measurement: assert `loaded_cases >= manifest_count`; the ablation isolates
  **LLM-marginal-over-the-deterministic-gate**, not pipeline-vs-raw; the FP-reduction denominator is the
  **LLM-triaged residual**, with an absolute recall floor and a held-out split (the pre-registration).
- Bounded LLM spend (budget + kill-switch, the fuzzer's discipline); offline re-scoring from committed
  output fixtures.

## Non-goals

VHX code adoption; CodeQL; C/C++ fuzzing; OpenGrep/gosec/Bandit foundation (separate initiative);
multi-SAST orchestration; DiverseVul (unlicensed); `evidence_paths[]` schema change (a version bump on
the frozen `schema.py` — deferred); shipping/product; changing the 12-week deliverables; any build
before the spike passes AND the user approves.

## Acceptance criteria

1. **Phase 0 gate**: every external license primary-source-verified + recorded; the verifier + scorer
   `DESIGN.md` (single-turn provenance, verdict-integrity check, corpus fetch/fail-closed, pre-registered
   metric) accepted; the user's license/sequencing/bar decisions recorded.
2. **Phase 1 spike**: on RealVuln (Apache-2.0, fetched not committed), the clean-room verifier's
   **LLM-marginal-over-gate** FP-reduction meets the pre-registered bar **with recall ≥ the floor on a
   held-out split**; measured by the net-new fail-closed scorer; verdict outputs committed as fixtures
   for offline re-scoring. **A miss is an accepted, documented outcome — no build.**
3. Zero changes to Weeks 1–10 (additive `agent/verifier/` spike + new `evaluation/<renamed>/` only; not
   `evaluation/false-positive/`, which already means the egress guardrail).

## Phases

### Phase 0 — Verify, design, decide (BLOCKING; no product code)
- **Licenses**: primary-source-verify VHX (LGPL-2.1), RealVuln (Apache-2.0 + NOTICE duties), ZeroFalse
  (confirm or drop), Juliet (NIST public), OWASP (GPL, manifest-only). Record in the decision doc.
- **DESIGN.md** (`docs/ai-sast-verifier-design.md` — written 2026-07-25): single-turn-per-finding prompt schema; the clean-room
  question method (Sentinel-authored, small set, no VHX text); the **new verdict-integrity check**
  (what code *can* check about a verdict — e.g. the verdict must cite the finding's own signal/CWE, and
  a verdict fabricating a CWE not in the finding is rejected, the one real `guard.py` seam); the
  corpus fetch (gitignore + pinned manifest + fail-closed `loaded_cases>=manifest`); the FP-trap scorer
  unit (per-finding TP/FP, ≠ `benchmark/scoring`); the **pre-registered metric** (denominator =
  LLM-triaged residual, absolute recall floor, held-out split, round cap, ablation = LLM-marginal-over-
  gate). **Gate:** user + (if needed) legal sign-off on the license branch.

### Phase 1 — Verifier viability spike (prove or disprove; then PAUSE)
Minimal clean-room `agent/verifier/` over the existing lake SARIF: deterministic-first gate → single-turn
provenance-labelled triage via `agent/llm.py` → CWE-fabrication reject → `{verdict, confidence}`.
Measure on RealVuln via the net-new scorer; commit verdict-output fixtures; re-score offline in CI
(fail-closed on absent corpus). Report the pre-registered number honestly. **Then stop and report to the
user** — pass → propose a follow-on integration plan; miss → documented negative result.

## Red-team reconciliation ledger (validate artifact)

| Finding | Lens | Resolution |
|---|---|---|
| guard.py can't adjudicate verdicts | feas-1 | Verdict measured vs corpus; new CWE-fabrication-only integrity check; drop guard.py-reuse claim |
| scorer is OWASP-only, net-new needed | feas-2 | FP-trap scorer labelled net-new; not a `benchmark/scoring` reuse claim |
| FP-reduction bar gameable / denominator undefined | feas-3 | Pre-register: denominator=LLM residual, recall floor, held-out, round cap (Phase 0) |
| spike is live-LLM, not offline | feas-4 | Commit output fixtures for offline re-scoring; budget+kill-switch the live run |
| ~1600 LoC/inherit not credible; VHX unread; CodeQL-coupled | feas-5 | Branch B clean-room method; no LoC/time promise; read nothing that binds copyright |
| multi-turn provenance schema hole | feas-6 | Single-turn-per-finding design; resolved Phase 0 |
| OpenGrep parity trivial; also LGPL; coverage unmeasurable | feas-7/scope-3 | Phase 1 foundation CUT to a separate initiative |
| inferred licenses asserted as fact | feas-8/scope-1 | Corrected table; Phase 0 primary-source-verifies all |
| evidence_paths[] edits frozen schema | feas-9 | Deferred (schema version bump) |
| RealVuln Apache not MIT; DiverseVul unlicensed; ZeroFalse unverified; OpenGrep LGPL | scope-1 | Corrected; DiverseVul dropped; ZeroFalse gated on verification |
| OWASP has no FP traps; Phase2/3 inverted | scope-2 | Spike runs on RealVuln; FP-trap scorer is a Phase-0/1 prerequisite |
| committed-corpora vs license-clean | scope-5 | Manifest+gitignore+fail-closed-fetch, never commit data |
| naming collision evaluation/false-positive/ | scope-6 | New dir renamed (e.g. `evaluation/sast-fp-discrimination/`) |
| LGPL "not binary" legal test wrong (Week-12 conveyance) | scope-4 | Branch decision framed around conveyance/handover; clean-room Branch B is the safe path |

## Risks & rollback

Spike fails the bar → stop, documented (no sunk build). License unclean → Branch B clean-room. Cost →
budget+kill-switch+deterministic-first gate, measured before any full build. Everything is additive
(`agent/verifier/` + new eval dir + manifest) and revertible without touching W1–10.

## Deferred (each an explicit decision first)

Foundation broadening (OpenGrep/gosec/Bandit — separate gated initiative); CodeQL; C/C++ fuzzing;
DiverseVul (unlicensed) / Juliet breadth; ZeroFalse (until license verified); `evidence_paths[]` schema;
full VHX integration (only if the spike passes and the license branch is cleared).

## Resolved decisions (user, 2026-07-25)

1. **License branch = clean-room re-implement the method (Branch B).** Inherit only the guided-question
   approach; Sentinel-authored templates, never VHX's text/source. Safe under LGPL + Week-12 conveyance.
2. **Sequencing = after the 12-week track.** This spike is a post-capstone enhancement; Weeks 11–12
   (deploy/FinOps, PRD/handover) come first. This thread stays parked until then.
3. **Spike bar = measure-first.** Run raw-SAST + deterministic-gate + verifier once on RealVuln, record
   the LLM-marginal-over-gate FP-reduction + recall, then set the "proceed" bar just above that baseline
   (decision 0018's threshold policy). No aspirational number pre-committed.

When re-activated post-capstone, Phase 0 begins with these locked; no product code before then.
