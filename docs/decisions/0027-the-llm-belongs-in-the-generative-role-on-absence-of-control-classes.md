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
| **PRIMARY (preregistered, two-sided):** vulnerable files vs clean control files | corrected **9/60 vs 0/40, p = 0.0078**; **replicated independently (E35): 14/59 vs 0/40, p = 0.000350** | the model **discriminates**, and the conclusion survives a fresh run |
| specificity | **0 of 40** clean files (corrected — the one flag was a classifier false positive); **replicated again E47: 0 of 16 in both readings** | it is not flagging indiscriminately — and this is the firmest number in the project, never having moved in any run |
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

**1. The instrument is NOT deterministic — ~40% of raw verdicts differ on identical input (n=38) — but E31 shows most of that is clean<->non-answer churn; FLAG decisions churn on ~1 file in 12 at `temperature=0`,
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
  - **REPLICATED (E28).** An independent re-run gives **7/40 vs 1/42, difference +0.151 [+0.027, +0.276],
    p = 0.0241** — against E24's +0.177. Arm C moved by one file and arm A′ by two; **the difference
    reproduced to within 0.026**, and the interval still excludes zero. On an instrument whose raw verdicts differ ~40% of the time (flag decisions ~1 in 12, E31), the conclusion is stable
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

## REFINEMENT (E34, 2026-07-26) — the capability is class-specific, and the aggregate rate hides that

E26's transfer demonstration (3/4, n = 8, p = 0.071 — not significant) was scaled to **12 matched pairs
across Flask, FastAPI and Django**, blinded, with exact ground truth: **sensitivity 7/12, model false
positives 1/12 by classifier, p = 0.0136** — the **conservative** figure, quoted here deliberately. An
independent audit later found **2 of 12 control variants carried unplanted defects** (a rate-limit gap
and a missing-authentication gap the author never planted); on the 10 pairs with valid ground truth the
result is 7/10 with 0 false positives (p = 0.0015). **The weaker number is the one this decision
rests on**, because the exclusion — however well justified — improves the result. The transfer claim is now powered
rather than illustrated.

**The refinement that matters more than the number:**

| absence class | planted | detected |
|---|---|---|
| ownership / IDOR (639) | 4 | **4** |
| missing authentication (306) | 2 | **2** |
| missing authorization (862) | 2 | 1 |
| rate limit / lockout (307) | 1 | **0** — also missed in E26 |
| mass assignment (915) | 1 | **0** |
| error-path exposure (209) | 1 | **0** |
| missing re-authentication (620) | 1 | **0** |

**This decision's claim is therefore narrowed from "absence-of-control classes" to what was actually
measured: absent ownership and absent authentication.** Rate limiting, mass assignment, error-path
exposure and re-authentication were missed in every instance tested. A deployment weighted toward those
classes would see far less than the headline rate — and CWE-307 is the *most common* absence class in
the RealVuln corpus.

**The narrowing now rests on corpus code, not only on four files we wrote (E39).** The four authored
files were the weakest part of this decision, so the same question was put to all 53 *corpus* files whose
ground truth carries both an ownership/authentication class and CWE-307 — paired inside each file, so one
response answers both questions and nothing about the file can differ between the two arms. Result:
ownership/authn named on **6/53**, rate limit on **1/53**, difference **+0.094, 95% CI [+0.000, +0.189]**.

**How the primary claim must now be read (E47).** The two halves of it behave differently and only one was
ever at risk. **Specificity is a floor**: zero flags on clean controls in every reading this lab has taken,
including a fresh independent re-run. **Sensitivity is a rate**: on the same 24 absence-class files, two
independent readings flagged 5 and 3, overlapping in **2**, with **18 of 24 flagged in neither**. So the
supportable statement is *"on a file with a real absent control, one reading flags it about a fifth of the
time, on a shifting subset; on a file with no defect, no reading has ever flagged it."* That is a low-noise
**sampler**, not a scanner — a coherent product, and not the one a reader would assume from a sensitivity
figure alone.

**This has since been raised to a preregistered test (E37, run 2026-07-26).** Three independent runs over
the same 53 files, pooled as a union over k=3 readings: ownership/authentication named on **9/53**, rate
limit on **2/53**, discordant 9 vs 2, **exact McNemar one-sided p = 0.0327 — the null of no class asymmetry
is rejected.** The narrowing now rests on a test, not only on an estimate.

Two qualifications travel with that, and neither is optional. The union estimand is **not** the
single-reading figure below and is larger by construction — quoting it against a one-call-per-file cost
would misprice the capability threefold. And the design's **realized power was 61%, not the 94.6%
preregistered**: the reinstatement assumed independence between readings from E42's six-file overlap, and
this run falsifies it (union came in at 0.170 where independence predicts 0.242). A significant result at
61% power is more likely to overstate the effect, so **the direction is established and the magnitude
should be read as an upper end**.

Read the original estimate precisely, because it is easy to over-read. The **direction agrees** with E34
and the evidence base for the narrowing widens from 4 authored files to 53 real ones — but **that
estimate's interval touched zero, and on its own it did not confirm the narrowing.** The powered
test of the same question was cancelled beforehand at 43% power, and this estimate came out exactly as
that gate predicted it would.

**The replication (E42) changed what this number is a statement about, and this is the most important
qualification in this decision.** An independent re-run of the identical 53 files reproduced both rates to
the digit — 6/53 and 1/53, difference +0.094 — on responses that were **byte-different in 52 of 53 cases**,
so it was a genuine second measurement and not a cached one. But the **6 files detected in the first run
and the 6 in the second overlap in none**. Expected overlap if each run drew independently at the same
rate is 0.68 files; if detection were a stable property of a file it would be 6.

**Why that happens was then measured directly (E43), and it settles the cost model.** Repeated readings of
the same file show the per-file propensity is neither uniform nor stable: files reported by an earlier run
come back at **0.333**, files never reported at **0.083** — so it is not a lottery — but **the highest
propensity measured on any file is 0.67, and none is reliable**. Propensities sit in a mixture roughly
between 0 and 0.67, which is exactly what produces the same count from disjoint file sets.

Deepened and widened — 3 runs over 16 files — both edges of that result hardened: the group difference is
**+0.271 [+0.104, +0.437]**, excluding zero, and the best file tops out at **0.667**, excluding one. So the
per-file signal is established, and so is the ceiling. **Seven of eight never-reported files sit at exactly
zero across every reading**, while reported files spread from zero to two thirds.

**A correction to how the headline rate must be read.** Never-reported files sit at 0.028, far below the
0.113 population rate, while a minority sit at 0.33-0.67. **0.113 does not mean "each file has an 11%
chance"** — it is a few files at 30-70% diluted by many at zero, and the average describes almost no
individual file in the set.

The operational consequence is concrete: detection accumulates with repeated reading (a file at 0.33 is
found with probability 0.33 at k=1, **0.70 at k=3**, 0.87 at k=5), so **the generative role requires
repeated readings to mean anything at file level, and every cost figure must carry the k.** One call per
file buys roughly a third of what the headline sensitivity implies. But repeated reading only helps where
there is signal to accumulate: a file at 0.000 is never found at any k. What may be promised is **coverage
of a subset of the corpus, at k times the cost, with no way to identify that subset in advance.**

**That subset has now been sized (E45), and it is the number this decision should be read through.**
Across two independent readings of the same 53 files, **41 of 53 (0.774, 95% CI [0.645, 0.865]) were never
named at all** — an upper bound on the zero fraction, since a file at 0.333 is missed twice 44% of the
time. Correcting with the measured propensity distribution puts the true figure at roughly **0.60–0.77**.

So **three to four files in five carry no propensity to be reported at any k**, and repeated reading buys
coverage of at most the remaining one to two in five, at k times the cost. That is a materially different
product from "an 11% detector that improves when run repeatedly", and it is the honest description.

**E46 then measured the whole curve on five independent readings of those 53 files, and this is the table
to price from:**

| k readings | files surfaced | vs an independence model |
|---|---|---|
| 1 | 5.2/53 (0.098) | 100% |
| 3 | 11.4/53 (0.215) | 81% |
| 5 | 15.0/53 (0.283) | **70%** |

**Not one file of 53 was reported in all five readings** — the direct, model-free form of "no file is
reliably detected". Ownership never fired on 38 of 53; CWE-307 never fired on 50 of 53.

Three consequences for pricing, none of them optional: coverage **saturates far below 1** (five readings
surface 28% of files); returns **diminish measurably** (k=4→5 adds 1.6 files) and diverge further from an
independence model as k grows; and **any model of the form "11% per reading, so k readings gives k×11%"
overcharges**. The defensible offer is: read every file five times, pay five times, see about a quarter.

So what replicates is a **rate**, not a detection. This model reports an absent ownership control on about
11% of files of this kind, and does not consistently report it on the *same* files. For a product that
means two runs yield two disjoint worklists, both at the published rate — which forces either repeated
readings per file, with the cost model that implies, or presenting the generative role as a sampling
process rather than as a scanner. **No claim in this decision may be read as "the model finds the
vulnerability in this file".** The class-rate comparison this decision rests on is unaffected, because it
was always a statement about rates by class, and both classes' rates replicated exactly.

What does not depend on the comparison: all 53 files carry a real CWE-307 defect and the model named the
missing rate limit in **one**. The most common absence class in this corpus is very nearly invisible to
the model in this role. That number needs no control arm and is the one with commercial consequences.

**And the obvious escape route from that number is now closed (E41).** The natural objection is that the
model *can* see missing rate limits but spends its one answer on the louder IDOR sitting in the same file
— which would make this a prompting problem with a known fix. Two attempts to settle it:

- Asking about CWE-307 **directly** could not be turned into an instrument at all. The leading question
  reported the rate limit absent on code carrying `@limiter.limit('5 per minute')`. Four canary readings
  across two prompt formats, never once discriminating a present control from an absent one. Abandoned at
  the gate, before any corpus calls were spent (E40).
- Removing the competition instead of changing the prompt: the same open-ended question over the 16 corpus
  files carrying CWE-307 **and no other absence class**. Detection **1/16 = 0.062** against the contested
  1/53, **p = 0.41 — no recovery** — and the uncontested files are *smaller* (median 84 vs 189 lines), so
  the confound favoured the salience explanation and it still did not appear (E41).

This rules out a *large* salience effect, not a modest one: the uncontested arm's upper bound is 0.188 on
n=16, which is all the corpus holds. The practical reading is that **the narrowing is not an artefact of
how we ask**, and per-class prompting is not an available remedy on this model.

**Specificity strengthened:** two controls were deliberately hidden — one injected as a dependency, one
applied inside a service `base()` method — and the model correctly stayed silent on both.

**A flaw in the test method, disclosed:** a matched `_b` variant is only "controlled" for its *planted*
class and may carry an unplanted defect. E34's `email_b` does — the model correctly flagged a real
missing rate limit there, and it was scored as a false positive. Every matched-pair result in this lab
inherits this, and future sets must audit controls against the full class list.

## REPLICATED ON BOTH HALVES (E35 + E36, 2026-07-26)

Both legs of this decision's mechanism argument now rest on **two independent runs each**, not on single
measurements:

| claim | first run | independent replication |
|---|---|---|
| discriminates absence-class from **clean** files | 9/60 vs 0/40, p = 0.0078 | **14/59 vs 0/40, p = 0.000350** |
| discriminates absence-class from **merely defective** files | 9/60 vs 0/80, p = 0.0003 | **14/59 vs 2/80, p = 0.000120** |

**Specificity across both runs: 0/40 clean files flagged — 80 consecutive, no false claim.** Defective
files with no absent control sit at 2/80, **statistically indistinguishable from files with nothing
wrong** (p = 0.44), while every one of those 80 carries a real confirmed vulnerability.

Sensitivity rose from 0.150 to 0.237 between runs. Two instrument corrections since the first run push
that way — the classifier now recognises findings its earlier vocabulary missed, and unreadable files
are no longer counted as model failures — which is the "published rates are a **floor**" caveat paying
out in the predicted direction rather than a change in the model.

**Every artefact behind a standing claim in this decision is now re-verifiable from the repository.**

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
  - **Structural familiarity — TESTED, INCONCLUSIVE, leaning against us (E32, 2026-07-26).** Adding a
    provably-safe structural mutation (top-level definitions reordered) on top of surface anonymisation
    gives **8/41 vs 11/41, difference −0.073, 95% CI [−0.195, +0.049]** — the interval spans a 20-point
    collapse and a 5-point rise, so nothing is established. **But the point estimate is a drop**, so the
    honest status is no longer "untested": it is *inconclusive with the available evidence pointing at
    structure contributing*. **The transfer bound does not narrow.** A clean answer needs both mutation
    levels on one identical file set at ~300 files/arm. The limit of even that: reordering changes
    file-level shape, never intra-function control flow.
    realistic defect distribution nobody designed to be findable.
- **Recorded process failure:** the deterministic control arm was preregistered and the implementation
  silently dropped it during a redesign. It was caught before publication and run. The mechanism claim
  was withdrawn on a weaker comparison and then partially restored by the correct one — both movements
  are in the research log, in order.
