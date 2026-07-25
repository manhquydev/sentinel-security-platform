# 0027 The LLM belongs in the generative role, on absence-of-control classes — measured, bounded, and not transferable yet

Date: 2026-07-26

## Status

Accepted, with the bounds below treated as part of the claim rather than as caveats to it. Supersedes
nothing; **narrows** the project's standing "AI loses every comparison" position, which decisions
0018–0021 established for a role class that is not this one.

## Context

Every AI role this project had ever measured was a **verdict/gate** role — judge (0018), false-positive
verifier (0020), ranker (0021) — and the architecture forbids an LLM to hold any of them (a structural
test, DD1, asserts no model is reachable from the verdict path). The results were consistent: refuse,
lose, or tie.

From that the project had generalised to "every measured AI-vs-deterministic comparison ended badly for
AI". A meta-analysis of the lab's own history showed that generalisation was **structurally
incomplete**: the **generative** role — *the model proposes, deterministic code disposes* — had **zero
measurements**, because the one plan to test it was cancelled at a red-team gate.

Meanwhile decisions 0022–0024 had established where deterministic tooling is blind: **absence-of-control
classes** (CWE-307 no auth-attempt limit, CWE-639 IDOR, CWE-200 information exposure, CWE-862/306
missing authz/authn). An absent control writes no token, so pattern matching has nothing to match.
Measured recall there is ~0–6.8%.

That is the one place where a proposer cannot be beaten by the deterministic baseline, because the
deterministic baseline is approximately nothing.

## Decision

**The LLM's measured place in this system is the generative role on absence-of-control classes: it
proposes, deterministic code disposes, and no model is ever consulted about its own output.**

Evidence (E16a, E16b, E17; preregistered per `docs/research-protocol.md`):

| comparison | result | what it establishes |
|---|---|---|
| **PRIMARY (preregistered, two-sided):** vulnerable files vs clean control files | 10/60 = 0.167 vs 1/40 = 0.025, **p = 0.024** | the model **discriminates** — both arms could have scored |
| specificity | **0 of 40** clean files (corrected — the one flag was a classifier false positive) | it is not flagging indiscriminately |
| class attribution (post-hoc, exploratory) | **6 of 10** flags named the ground-truth class | 4 flagged the file for an unrelated issue |
| **MECHANISM (E18, preregistered):** absence-class files vs **defective files with no absent control** | 10/60 = 0.167 vs **3/80 = 0.037**, **p = 0.010** | the effect is **class-specific** |
| same control arm vs clean files | 3/80 vs 1/40, **p = 0.59** | defective code alone triggers **nothing** — mess is not the driver |
| capability gap vs deterministic engines, identical files | model 6/60 · **engines 0/60** | the engines emit 33 CWE classes, **none absence-class** — a *capability statement*, not a contest (see below) |

The p-values against the deterministic arm (0.0137 / 0.00065) are **not quoted as the headline**: that
arm is structurally incapable of scoring, so a significance test against it overstates what happened.

**Bandit and Semgrep together flagged an absence-class CWE in zero of sixty files.** Not approximately
zero — zero. This is the first capability measured in this project that deterministic tooling cannot
supply at all.

> **How to state this correctly (framing correction, same day).** That zero is **structural, not
> sampled**: across 12 corpus repositories these engines emit **33 distinct CWE classes and not one is
> absence-class** — the rulesets have no rule that can express an absent control. A Fisher test between
> the two arms is therefore arithmetically valid but rhetorically misleading, because it implies a
> contest one side could never enter. **The supported claim is capability addition, not superiority:**
> the deterministic layer cannot express this class; the model names it in 10% of files. The genuinely
> two-sided result is the preregistered primary — vulnerable vs clean control files, p = 0.024.

The result was preregistered, powered in advance by simulation (83%), replicated on a sample **disjoint**
from the exploratory run, gated by a positive control, and scored by a deterministic classifier audited
against synthetic cases before any data was seen.

## CORRECTION (2026-07-26, same day) — a Stage-8 review of the whole chain

An independent adversarial review of E17–E21, followed by a preregistered determinism check (E22),
forced three changes. All are against this decision's own interests and are recorded in full.

**1. The instrument is NOT deterministic — ~40% of verdicts flip on identical input (95% CI [21%,63%], n=38) at `temperature=0`,
and the model never returns identical prose (0 of 14).** Consequently:

- **E19's "surface memorisation is excluded" is WITHDRAWN.** Its paired difference of exactly 0.000
  (3 lost, 3 gained) is *precisely what 36% instrument noise produces* on 53 files at this base rate,
  mutation or no mutation.
  - **RE-ESTABLISHED, more weakly, by E23 on a valid design (same day).** Both arms measured fresh in
    the same run, aggregate rates compared: original **11/53 = 0.208**, anonymised **14/53 = 0.264**,
    difference **+0.057, 95% CI [−0.038, +0.151]**. Anonymisation does **not** reduce detection and the
    interval excludes even a 5-point drop, so **surface memorisation is not the primary driver**. But
    the interval is wide: **equivalence is not established** and a small memorisation contribution is
    not excluded. Nothing here may still be promised for private code.
- **E20's "the missing control drives it, not file role" was WITHDRAWN** — it paired a *reused* arm A′
  against a *freshly measured* arm C, invalid under this instability, and was one flagged file from
  non-significance.
  - **RE-ESTABLISHED by E24 on a valid design (same day).** Both arms measured fresh in the same run,
    file role held fixed: handlers **with** an absent control **9/40 = 0.225**, handlers **without**
    **2/42 = 0.048**, difference **+0.177, 95% CI [+0.031, +0.326], p = 0.0195**. It tolerates two extra
    flags before crossing α (E20 tolerated one) and its interval excludes zero. **The file-role confound
    is closed on evidence that survives its own instrument.**
  - **REPLICATED (E28).** An independent re-run gives **8/40 vs 1/42, difference +0.176 [+0.052, +0.325],
    p = 0.0120** — against E24's +0.177. Both arms moved by one file; **the difference reproduced to
    within 0.001**. On an instrument that flips 36% of individual verdicts, the conclusion is stable
    across runs even though the labels are not. E28 also stores responses in full, so unlike E24 it can
    be re-verified from its artefact.

**2. The prose classifier had four demonstrated defects**, all now fixed and pinned by SM13 (it
previously had **no test at all**, despite every result scoring through it). Re-scoring the stored
responses moves the surviving results *in this decision's favour*:

| | published | corrected |
|---|---|---|
| E17, absence-class vs clean | 10/60 vs 1/40, p = 0.024 | **9/60 vs 0/40, p = 0.0078** |
| E18, absence-class vs defective-no-absence | 10/60 vs 3/80, p = 0.010 | **9/60 vs 0/80, p = 0.0003** |

**Specificity is 0 of 40, not 1 of 40** — the single clean-arm flag was a classifier false positive on
prose that actually said the control was *correctly* implemented. The evidence table above is corrected.

**3. An undisclosed confound: the gateway rewrites the source before the model sees it.** The egress
guardrail's redaction rules rewrite `token=`, `password=` and `authorization:` — ordinary identifiers
in web application code. The model's own replies mention it ("Redaction broke syntax"). Arm A, being
authentication-related code, takes the most damage, which biases **against** this decision's finding —
but it was never disclosed and is a real limit on every number in the chain.

**What still stands after all three:** the model discriminates files containing absence-of-control
vulnerabilities from both clean files and defective-but-not-absence files, at p = 0.0078 and p = 0.0003
respectively, with perfect specificity, against a deterministic layer that has no rule capable of
expressing this class. **What no longer stands:** that this is not memorisation, and that it is not
file-role recognition. Both are open questions again.

## The bounds are part of the claim

1. **It is a weak detector — but every published rate is a FLOOR, not an estimate.** The measured
   ~19–22% is scored by a keyword classifier that E26 caught missing a *correct* finding (the model
   named a missing webhook signature verification precisely; the vocabulary had no term for it) and
   counting a validation complaint as an absence claim. Two independent reasons the true rate is higher:
   that under-counting, and the gateway redaction confound below. **Between-arm comparisons are
   unaffected** — the same classifier scored both sides — but absolute rates should be read as lower
   bounds.
2. **It is file-level, not line-level.** No model would emit machine-readable structure — five aliases ×
   three formats × an assistant prefill produced **zero** format compliance while correctly identifying
   planted defects (E16a). The disposal layer therefore consumes prose.
3. **A third of calls are non-answers** (33% on vulnerable files): the model asks a question or returns a
   refactor instead of a review.
4. **Contamination — NARROWED (E19, same day), no longer "inseparable".** RealVuln is public and its
   repos carry `llm_generated_corpus: true`, so this was originally recorded as measuring capability and
   memorisation inseparably. They have since been **partially separated**: re-presenting the same 53
   files with every identifier, route literal and the filename anonymised and the semantics untouched
   left the detection rate **exactly unchanged** (10/53 → 10/53; paired difference 0.000, 95% CI
   [−0.094, +0.094]; McNemar p = 0.656). The interval **excludes a 10-point collapse**, so **surface
   memorisation is ruled out as the driver**; it does **not** exclude a ~5-point contribution, which is
   therefore not claimed to be absent. Mutation also traded 3 detections for 3 *different* ones rather
   than systematically killing them — the signature of a noisy semantic detector, not a lookup.
   **What remains:** *structural* familiarity (mutation changes names, not control-flow shapes) and the
   absence of a genuinely unseen target. **Still not promised for client code** — but the reason is now
   the narrower one.
5. **One model, one corpus, one language.**

## Consequences

- **The project's headline claim is formally narrowed and is now two-part:** in **gate roles** the
  deterministic method wins or ties (0018–0021, repeatedly); in the **generative role on absence
  classes** the LLM supplies signal deterministic tooling cannot (this decision). Stating only the first
  half — as the Week-12 business case originally did — overclaims.
- **Architecturally nothing loosens.** The model still never holds a verdict. DD1 stands. What changes is
  that the model now has a *measured* place rather than a place justified only by architecture.
- **The business case may cite this only with the contamination bound attached**, and must not promise
  per-client transfer. What is sellable today is the deterministic layer plus the bounded AI cost; this
  finding is a **research result and a roadmap item**, not a shipped capability.
- **The mechanism question is RESOLVED (E18, same day).** The control arm this decision specified was
  run: 80 files with real vulnerabilities of presence classes only. The model produced absence-of-control
  language about them at **3/80 — indistinguishable from files with nothing wrong (p = 0.59)** — and far
  below the absence-class arm (p = 0.010). The "reacts to messy code" explanation predicts the opposite
  and is refuted. **The model discriminates the class, not the defectiveness.**
- **That residual confound is now CLOSED (E20, same day).** The third arm this decision specified was
  run on the **whole population** of qualifying files: holding file role fixed — endpoint handlers in
  both arms — handlers **with** an absent control flag at **0.250** and handlers **without** one at
  **0.071** (Fisher p = 0.042). The model responds to the **missing control**, not to endpoint-ness.
  **Reported with its fragility:** one additional flagged file in arm C would move p to 0.081, so this
  single test is marginal. The conclusion rests on **three independent preregistered controls
  converging** — messiness (E18), memorisation (E19) and file role (E20) — with no result pointing the
  other way.
- **Transfer — half answered (E23 + E25).** Surface memorisation is not the driver (E23, rebuilt design:
  anonymisation does not reduce detection, interval excludes a 5-point drop). And on **genuinely unseen
  code** — this project's own source, written 1–3 days before measurement and therefore outside any
  deployed model's training corpus — the model produced **0 findings on 25 files**, reproducing its
  perfect specificity. **Specificity transfers. Sensitivity does not yet have an answer**, because our
  own code is a library with no request handlers and therefore no known positives.
  - **Sensitivity transfer ANSWERED (E26).** Four matched pairs of Flask handlers authored minutes
    before measurement, shown blind, exact ground truth: the model found **3 of 4** planted
    absence-of-control defects and described each correctly, with **0 of 4** false claims on the
    controls. Both halves of the behaviour now have evidence outside the memorised corpus.
    **Limits:** n = 8, and the defects are of classes this author chose in this author's style — the
    matched-pair design prevents conspicuousness from inflating the score but cannot make them
    representative of a real client codebase. **Still outstanding:** structural familiarity, and a
    realistic defect distribution nobody designed to be findable.
- **Recorded process failure:** the deterministic control arm was preregistered and the implementation
  silently dropped it during a redesign. It was caught before publication and run. The mechanism claim
  was withdrawn on a weaker comparison and then partially restored by the correct one — both movements
  are in the research log, in order.
