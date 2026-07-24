# Execution Plan: Week-7 Advanced Guardrails & Indirect Prompt-Injection Defense (TDD)

Date: 2026-07-24

## Status

Active — hardened + reconciled. Red-team (4/4 lenses) → all blockers resolved on evidence (2 spikes
+ research); plan body rewritten into the reconciled 3-PR structure; validate pass done (see
Validation Log). **CLEAN.** PR1 built + green + STRIDE-clean (code-review adjudication folding in).
PR2 GATED on two user action items (HF license for PromptGuard + confirm sidecar infra). PR3 pending.

## Outcome

A secure input/output boundary for the syndicate that keeps target-derived (attacker-influenced)
content as DATA and cannot subvert the agent's decisions — targeting the ONE real IPI surface (a
scanner finding `title` → recon `_analyze` → the analyst-facing `analysis`), since rogue execution
is already structurally contained (read-only, import-contained exploit, code-computed facts).
Layered: the **structural control** (the code-computed `severity_counts`/`cwe_summary` a hijacked
narrative cannot alter — decision 0012 — plus spotlighting + quarantine of a contradicted analysis),
with **measured detectors** as defense-in-depth (an in-repo heuristic in PR1; the LlamaFirewall
sidecar in PR2). Observable when:

- a hijacked `analysis` (fabricated/downplayed) is **caught + quarantined** by the cross-check
  against the code-computed facts, which remain authoritative and always shown — the structural
  guarantee holds even when a detector is bypassed (0006);
- each detector's recall on planted IPI and its **false-positive rate on real security content** are
  MEASURED (the repo's differentiator), never trusted as the control;
- the Trap runs in an **isolated fixture / ephemeral engagement** — the pinned production lake is
  never touched; no secret/target-raw leaks into logs/checkpoints/spans (Week-6 redaction preserved);
- a self-hosted, reproducible adaptive round stresses the guard (PR3), residual honestly recorded;
- every claim carries a behavioural test with a negative control; existing suites stay green.

## Context

- Charter: `docs/Project_Sentinel_VinUni_x_VinSOC_12-week.md` (Week 7; skill S8; "The Trap"). NeMo
  Guardrails is an EXAMPLE, not a mandate.
- Decision 0006 (frozen): the gateway LABELS provenance and does NOT detect injection; enforcement
  deferred to the agent layer ("Stream D") — THIS week. 12 published defenses fail >90% ASR under
  adaptive attack; action-open agents recover 64% ASR even against a 0% static filter — so the
  primary control must be structural, not a classifier.
- Weeks 1–6 done: provenance client (`agent/llm.py`), syndicate (`agent/supervisor.py` recon→fuzz→
  exploit→interrupt_seam, read-only + HITL-gated + redacted), existing measurement harness
  (`evaluation/` — AgentDojo baseline + guardrail false-positive study).
- Research: `plans/reports/researcher-260724-1430-week7-ipi-defense-state-and-options.md` (state,
  options, the adaptive-eval-is-mandatory finding; NOTE its $/timeline framing was over-scoped and
  its PIArena vehicle is external SaaS — superseded below by a self-hosted adaptive eval).
- Feeds from Week 6: the `interrupt_seam` (Week-8 HITL) and the deferred endpoint-provenance (L1).

## User decisions (advise, 2026-07-24)

1. Guardrail = **layered**: structural capability gate (primary) + a self-hostable framework detector
   (defense-in-depth). NeMo is not required; the framework is chosen for self-hostability.
2. The Trap = **both vectors**: planted lake/scanner text AND a live loopback endpoint, both reversible.
3. Measurement = **full adaptive**, realized **self-hosted** (in-house adaptive attacker + existing
   AgentDojo/FP harness) to preserve the air-gapped/no-external-provider posture and avoid external
   spend — NOT the external paid PIArena SaaS (pending user override).

## Design decisions (research + brainstorm, 2026-07-24)

- **W7-D1 — Structural gate is the primary control.** Target-derived text is confined to DATA
  positions; the agent's actions/tools are gated so no injected instruction can escalate scope,
  change state, or bypass the read-only + HITL posture. The gate is what the ASR test targets; the
  detector is not trusted to be the control (0006).
- **W7-D2 — Framework detector is self-hostable + measured, defense-in-depth only.** A Phase-0 spike
  picks the framework (NeMo Guardrails vs LlamaFirewall vs equivalent) on: self-hostable/air-gapped,
  no external calls, coexists with `rag/.venv` pins, and measurable. Its flags are logged + measured,
  never the sole gate. Version pinned + air-gap-verified BEFORE code (the Week-6 stale-version lesson).
- **W7-D3 — The Trap is reversible by construction.** Both vectors (a planted lake finding/scanner
  text the recon agent reads; a loopback endpoint returning a hijack payload) are added and torn
  down by scripted, idempotent setup/teardown that restores the pinned lake baseline + app state;
  the payloads live in a gitignored/clearly-marked test fixture, never in the committed baseline.
- **W7-D4 — Measurement is self-hosted + adaptive, reusing `evaluation/`.** Before/after ASR against
  the Trap, an in-house adaptive-attacker round (mutating payloads vs the static set), and the
  false-positive-on-security-content study (SAST/CTF payloads) — the differentiator. Thresholds set
  from evidence after measuring, not asserted upfront. No target/attack content leaves the host.
- **W7-D5 — Redaction/air-gap invariants from Week 6 hold.** No secret/target-raw in
  logs/checkpoints/spans; LangSmith stays off; the detector adds no external egress.

## Scope (phased PRs — RECONCILED post-red-team; supersedes the pre-red-team maximal draft)

The real threat is recon-analysis output/decision integrity (an attacker-controlled scanner finding
`title` → recon `_analyze`), NOT rogue execution (already structurally contained: read-only,
import-contained exploit, code-computed facts). The primary control is structural; detectors are
measured defense-in-depth (0006).

- **PR1 (BUILT) — recon-analysis output-integrity guard + isolated Trap + measurement.**
  `agent/guard.py` (spotlight_findings; analysis_integrity_errors cross-checking the code-computed
  `severity_counts`/`cwe_summary`; quarantine; measured detect_injection) wired into `agent/recon.py`;
  Trap = a crafted finding `title` fixture fed to `_analyze` (production lake untouched);
  `evaluation/ipi-guard/` measures injection-success + FP on the security corpus.
- **PR2 (GATED on user action items) — LlamaFirewall as an air-gapped SIDECAR service** (own
  venv/container; AlignmentCheck → local LiteLLM gateway; PromptGuard pre-fetched offline; W7-D6) as
  a second measured detector on the recon-analysis input; measure recall on planted IPI + FP; prove
  the structural control (code-computed facts + quarantine) still holds when the detector is bypassed.
- **PR3 — self-hosted adaptive-attacker eval + consolidated report.** A reproducible (seeded,
  model-snapshotted, N-pinned) in-repo attacker that mutates IPI payloads against the guard; a
  before/after write-up; plus the Week-8-ready capability gate as forward enforcement measured
  against a SIMULATED state-changing action (no live action surface — 0013 preserved). The
  live-endpoint Trap vector is included ONLY if its net-new agent read-path plumbing is pursued
  (acknowledged added scope, not assumed).

Out of scope: a LIVE state-changing action surface (0013 reversal — only if the user explicitly asks),
Week-8 HITL execution, Week-9 PII redaction, external paid eval SaaS, GraphRAG, vLLM.

## TDD Approach (tests-first; per PR; each through implement → code-review → STRIDE audit → fix → re-verify)

- **PR1 invariants (GA1–GA4, met):** GA1 a crafted malicious title / stubbed hijacked analysis is
  caught+quarantined (negative control: benign passes); GA2 the code-computed facts stay intact +
  authoritative regardless of the narrative; GA3 detect_injection recall on planted markers + FP on
  the real security corpus measured; GA4 the Trap touches no production lake.
- **PR2 invariants (GB1–GB4):** GB1 the sidecar runs air-gapped (no external call; AlignmentCheck via
  local gateway; PromptGuard offline); GB2 it flags the planted IPI (measured recall); GB3 FP on the
  security corpus measured + reported; GB4 the structural control (quarantine + code-facts) STILL
  holds when the detector is bypassed (0006 layering proof). Phase-0 for PR2: stand up the sidecar +
  confirm zero external egress before wiring.
- **PR3 invariants (GC1–GC3):** GC1 the adaptive round is reproducible (seed/model/N pinned) and
  meaningfully mutates payloads; GC2 the guard/facts invariant holds across the adaptive round (or a
  measured residual is honestly recorded); GC3 the forward capability gate refuses a SIMULATED
  state-changing action under injection (negative control: an allowed read passes) — non-vacuous
  without a live action surface.

## Risks And Recovery

- **The Trap is a real IPI payload.** Contained: loopback-only; syndicate read-only + facts
  code-owned; the Trap lives in an ISOLATED test fixture / ephemeral engagement, NEVER the pinned
  webgoat/juice-shop baseline (red-team C1/C2/C3). Correction: `verify-lake.sh` is READ-ONLY (detects
  drift, does NOT restore) — so the recovery is "never touch the pinned lake," not "verify-lake
  restores it." An optional end-to-end demo uses a throwaway product dropped on teardown.
- **Framework venv conflict.** Resolved by the sidecar-service isolation (W7-D6); nothing heavy enters
  `rag/.venv`; Weeks 3 & 6 unaffected.
- **Detector treated as the control (0006 failure).** GB4/quarantine + the code-computed facts are the
  structural guarantee; every detector is measured, never a silent gate.
- **Adaptive-eval noise.** Small denominators + live-model variance → pin seed/model-snapshot/run-count;
  report confidence honestly rather than over-claiming ASR movement.
- **Additive**: `agent/guard.py`, recon wiring, the sidecar service, fixtures, eval; Weeks 1–6
  behaviour unchanged (recon changes are additive + backward-compatible).

## Progress

- [x] Scout Week-7 state + research synthesis (existing reports leveraged).
- [x] Advise decisions (layered / both-vectors / self-hosted-adaptive) — user, 2026-07-24.
- [ ] Plan red-team + validate → CLEAN.
- [ ] Phase 0 spike (framework pick + air-gap/compat gate).
- [~] PR1 (reframed) — recon-analysis output-integrity guard: `agent/guard.py` (spotlight_findings,
  analysis_integrity_errors cross-checking the code-computed facts, quarantine, measured
  detect_injection), wired into `agent/recon.py`; isolated-fixture Trap (production Lake proven
  untouched); measurement `evaluation/ipi-guard/`. Green: week7-ipi-guard 4/0, recon-agent 10/0,
  syndicate 30/0, egress 12/0. Honest numbers (reconciled to the committed
  `evaluation/ipi-guard/baseline-2026-07-24.json` per code-review M3): live hijack is rare +
  stochastic on tiny samples (0/8 live in the committed baseline; ~1/11 in another run) — so the
  guard's CATCH is proven **deterministically** via a stubbed hijack (GA1), and a credible ASR needs
  PR3's adaptive round. detect_injection recall 6/6; FP 0/375 (mostly whole Java files — real
  finding-title distribution under-represented, code-review M2). **Code-review + STRIDE done:**
  0 Crit/0 High; primary control (code-computed facts authoritative) verified SOUND by both.
- [ ] PR1 fix (M1 newline-datamark, M2 FP-corpus honesty, M3 done, L1 Info false-quarantine, L2
  real-`_analyze` integration test, I2 omission positive-check) → re-verify → docs + PR.
- [ ] PR2 (LlamaFirewall sidecar detector + FP study) — GATED on user action items (HF license,
  sidecar infra confirm).
- [ ] PR3 (self-hosted adaptive eval + consolidated report; endpoint-vector plumbing if pursued).

## Decisions

- 2026-07-24: User decisions 1–3 + design W7-D1…D5. Self-hosted adaptive supersedes the research's
  external PIArena vehicle (posture + spend), pending explicit user override.

## Validation

- Focused: G1–G8 invariants, each with a negative control.
- Integration/e2e: bounded live Trap→syndicate runs (both vectors) over loopback; adaptive round.
- Repo-required: existing suites green; lake baseline restored after Trap teardown.

## Red Team Review

### Session — 2026-07-24 (all 4 lenses — UNANIMOUS)
**Verdict: NOT CLEAN — fundamental re-scope required.** Reports:
`plans/reports/redteam-260724-1429-week7-{security-adversary,scope-complexity,failure-mode,assumption-destroyer}.md`.
Four independent lenses converged on the same root problems (all file:line-evidenced). The Security
Adversary pinpointed the **single genuine IPI entry point**: an attacker-controlled scanner
**finding `title`** (from the lake) flows verbatim into the recon `_analyze` prompt (`recon.py:148`);
a hijacked `analysis` (fabricated/downplayed finding) reaches the human analyst **unmeasured** —
`redact_persisted` strips markers, not injected instructions/false claims. Exploit `_narrate` input
is code-derived (not a free-text injection surface); fuzz `_guide` runs after probes. THIS
output-integrity threat, not rogue execution, is what Week 7 must defend + measure.

| # | Finding (converged) | Sev | Disposition |
|---|---------------------|-----|-------------|
| 1 | **No action surface to gate → the "structural gate" and its before/after ASR are vacuous.** Syndicate is already read-only (GET-only gateway), exploit non-executing (import-contained) + HITL-fixed verdict. Nothing new for a gate to block; ASR measured against a non-existent action = theatre (AgentDojo `standalone_utility==false` trap). | Crit | **Accept** — the real threat is OUTPUT/DECISION integrity, not execution; re-target |
| 2 | **The Trap is not safely reversible against the pinned production lake.** Recon's DefectDojo account can't delete (0004 → 403); `verify-lake.sh` is read-only (detects, restores nothing); daily scan timers race the window; live-endpoint vector has no agent read-path + mutates a checksum-pinned baseline. | Crit | **Accept** — Trap must live in an ISOLATED fixture/ephemeral engagement, never the pinned lake |
| 3 | **Framework detector can't air-gap.** LlamaFirewall AlignmentCheck needs `TOGETHER_API_KEY` (external); NeMo needs a model backend; torch/transformers conflicts with `rag/.venv` pins. | Crit | **Accept** — drop the heavy framework; a thin self-hosted heuristic/spotlighting detector only |
| 4 | **`evaluation/agentdojo` explicitly "Not a measurement of Sentinel"; Week-7 before/after "out of scope" there. Self-hosted adaptive attacker is net-new/NIH (AutoDojo already named by 0006).** | High | **Accept** — build the minimal Sentinel-specific measurement; reuse the real asset (the FP corpus) |
| 5 | **Maximal-on-every-fork is gold-plating** over controls Week 6 already built + tested (0006 already rejected classifier detection). | High | **Escalate** — user's decisions; re-scope needs user sign-off |

**What survives (verified sound):** the FP/security-payload corpus is real + reusable (the genuine
differentiator); provenance labelling + the read-only/HITL/import containment already hold.

### Evidence-based re-scope (proposed, pending user Decision)
- **Real Week-7 threat = output/decision-integrity subversion** (injected lake/fuzz text → recon
  `_analyze` / fuzz `_guide` / exploit `_narrate` → a fabricated finding / misleading proposal /
  subverted provenance), NOT rogue execution (already contained).
- **PR1:** prove containment holds under IPI + an output-integrity guard, tested against a Trap in an
  **isolated fixture** (never the pinned lake). **PR2:** a thin self-hosted spotlighting/heuristic
  input detector, **measured** (recall on planted IPI + false positives on the existing security
  corpus — the differentiator). **Deferred:** heavy framework (air-gap-blocked), live-endpoint vector
  + capability gate (Week 8, when an action surface/HITL execution exists), external adaptive SaaS.

## Post-red-team decision (user, 2026-07-24): HOLD MAXIMAL SCOPE, resolve blockers first

User chose to keep the layered-framework + both-vectors + full-adaptive scope and resolve the
red-team blockers rather than re-scope. Resolution approach (each done the SAFE way — no durable
decision reversed unless a blocker is genuinely impossible otherwise):

- **Trap reversibility (red-team C2/Failure/Assumption):** the Trap lives in an ISOLATED/ephemeral
  DefectDojo engagement or a pure test fixture — NEVER the pinned webgoat/juice-shop baseline. The
  recon-analysis injection is exercised by feeding a crafted finding `title` fixture straight to
  `recon._analyze` in a test (zero production-lake write). Resolves C1/C2/C3 + timer race without
  delete creds. An ephemeral product (created + fully dropped on teardown) is used only for an
  optional end-to-end demo.
- **Vacuous gate / no action surface (red-team C1):** the capability gate is built as the **Week-8
  forward enforcement** and measured against a **SIMULATED** state-changing action (a stub the gate
  refuses under injection) — non-vacuous, and it does NOT give the live agent a real action surface,
  so decision 0013's read-only posture is preserved. (Building a LIVE action surface now would
  reverse 0013 + pull Week-8 forward — NOT done unless the user explicitly asks.)
- **Real live threat (Security Adversary):** additionally defend + measure recon-`_analyze`
  output-integrity (a hijacked scanner `title` subverting the analyst-facing `analysis`).
- **Framework air-gap (red-team C3 — HARD GATE): SPIKE DONE 2026-07-24, framework layer BLOCKED.**
  Empirical (`scratchpad/w7-guardrail-spike`): **NeMo Guardrails is ruled out** — it needs
  `langchain-core >=0.2.14,<0.4.0` but Week 6 installed `langchain-core 1.5.1` (langgraph 1.2.9);
  installing it breaks the syndicate (hard conflict). **LlamaFirewall 1.0.3** pulls `torch>=2.4.1` +
  `transformers>=4.51.3` (GB-scale into the shared venv) and its flagship AlignmentCheck injection
  detector needs an external API (`openai`/Together) — NOT air-gappable; only local PromptGuard (HF
  model pre-fetch) + regex/CodeShield run offline. Conclusion: the heavy framework as scoped is not
  air-gap-clean. Decision 0006 already rejected classifier detection as the control. → framework
  sub-decision goes to the user (thin self-hosted heuristic vs LlamaFirewall local subset).
- **Adaptive eval:** self-hosted in-repo payload-mutation loop (or AutoDojo if air-gappable);
  reproducibility pinned (seed/model snapshot/run-count). The measurement harness is Sentinel-specific
  (the existing AgentDojo scaffold is NOT it — net-new, acknowledged).
- **Vector-2 (endpoint) read-path (red-team H3/Assumption H3):** requires net-new plumbing to feed an
  endpoint response body into a prompt (today only ≤40-char signal regexes survive) — acknowledged as
  real added scope, built explicitly, not assumed.

## Framework wiring resolved (research 2026-07-24, `researcher-260724-1503-llamafirewall-local-backend-viability.md`)

User chose full LlamaFirewall incl. AlignmentCheck. Verified viable air-gapped, via a durable
architecture that avoids the venv conflict:

- **W7-D6 — LlamaFirewall runs as its own self-hosted SIDECAR SERVICE** (own venv/container with
  torch/transformers/tokenizers<0.22), the agent calls it over loopback — matching the repo's
  existing separate-service pattern (Kong/LiteLLM/Langfuse/Phoenix/rag-db). This SIDESTEPS the hard
  `tokenizers` conflict (rag pins 0.23.1 for fastembed; transformers>=4.51.3 needs <0.22) so Weeks 3
  & 6 do not regress. NOT installed into the shared `rag/.venv`.
- **AlignmentCheck → local gateway:** subclass `CustomCheckScanner` with
  `api_base_url=http://127.0.0.1:4000/v1` (the public `AlignmentCheckScanner` doesn't expose it, the
  parent does) → no external API, no spend, honours the model-egress contract.
- **PromptGuard:** pre-fetch the (gated) HF model once, then `HF_HUB_OFFLINE=1` → fully offline.
- **USER ACTION ITEMS:** (a) accept the Llama-Prompt-Guard HF license + provide HF creds for the
  one-time model fetch (I cannot accept a license on the user's behalf); (b) confirm the added
  sidecar-service infra is acceptable.

## Validation Log

### Session — 2026-07-24
The plan body was rewritten into the reconciled 3-PR structure; this pass verified the resolutions
against the codebase + reconciled the plan with the built PR1. Findings, all resolved:

| # | Checked | Result | Resolution |
|---|---------|--------|------------|
| VF1 | Scope/Outcome match the red-team resolutions | FAILED (Outcome/Scope still carried the pre-red-team "capability gate + before/after ASR + both vectors" framing) | Outcome + Scope + TDD + Risks rewritten to the recon-analysis-integrity target; live-action-surface gate reframed to Week-8 forward-enforcement vs a SIMULATED action |
| VF2 | Trap reversibility claim | FAILED (said "verify-lake.sh restores state" — it is read-only) | corrected: Trap in isolated fixture/ephemeral engagement, pinned lake never touched; verify-lake only detects |
| VF3 | Plan measurement claim vs the committed artifact | FAILED (Progress claimed 1/11 hijack caught; committed baseline shows 0/8 live) — code-review M3 | Progress corrected to the honest stochastic numbers; catch proven deterministically (GA1); credible ASR deferred to PR3 |
| VF4 | PR1 built state matches the plan | VERIFIED | `agent/guard.py` + recon wiring + isolated Trap + `evaluation/ipi-guard/` present; GA1–GA4 + regression green; STRIDE 0-Crit/High/Med; code-review 0-Crit/High |

**Whole-plan consistency sweep:** Outcome ↔ Scope ↔ TDD ↔ Progress ↔ Red-Team resolutions now
agree (recon-analysis integrity, structural facts primary, detectors measured, isolated Trap,
sidecar framework, self-hosted adaptive). **No unresolved contradictions.** Genuine open items are
tracked (not blocking): PR1 fix set (M1/M2/L1/L2/I2); PR2 user action items (HF license + sidecar
infra); PR3 adaptive credibility.

## Result

**Plan CLEAN** (red-team 4/4 resolved on evidence → body reconciled → validate pass + consistency
sweep, no contradictions). **PR1 cooked** (guard + isolated Trap + measurement), verified green,
STRIDE-clean, code-review APPROVE-WITH-MINOR-FIXES — the minor fixes (newline-datamark, FP-corpus
honesty, Info false-quarantine, an integration test, an omission positive-check) are the current cook
`fix` step, then PR1 commits. **PR2** (LlamaFirewall air-gapped sidecar) is GATED on two user action
items (accept the Llama-Prompt-Guard HF license + provide HF creds; confirm the sidecar infra).
**PR3** (self-hosted reproducible adaptive eval + the Week-8-ready forward gate vs a simulated action)
follows. No live action surface / 0013 reversal unless the user explicitly asks.
