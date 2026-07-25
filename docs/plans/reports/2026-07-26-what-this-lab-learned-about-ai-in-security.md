# What this lab actually learned about AI in security

Synthesis across 20 experiments (E1–E20). Written 2026-07-26 at the close of the research session that
adopted `docs/research-protocol.md` and then turned it on the lab's own published claims.

Sources: `docs/ai-sast-research-log.md` (entries are authoritative), decisions 0018–0027.

---

## The one-sentence answer

**AI does not belong where it decides; it belongs where it proposes.** Every measured attempt to give a
model a *verdict* role — judge, verifier, ranker — ended with the model losing, tying, or refusing. The
one role never tested until this session, *proposing candidates for deterministic code to verify*, is
the only place the model supplies something the deterministic layer cannot produce at all.

---

## 1. Where AI loses (established, repeatedly)

| role | experiment | result |
|---|---|---|
| judge findings correct/incorrect | E1, 0018 | **refuses 12/12** under correct provenance |
| verify and drop false positives | E2, 0020 | **hides 3 of 8 real vulnerabilities** — unsafe |
| rank findings for triage | E3/E14, 0021 | **loses** to a free CWE prior: −0.095 [−0.128, −0.063] per application |
| narrate a syndicate run | E13 | **+$0.05, +35 s, zero additional findings** |

These are gate roles, and the architecture already forbids the model to hold them — a structural test
(DD1) asserts no model is reachable from the verdict path. The measurements say the architecture was
right for reasons beyond principle.

## 2. Where AI wins (established this session)

On **absence-of-control** classes — missing authorization, missing ownership checks, no rate limit, no
authentication, information exposure — pattern SAST is not merely weak. It is **structurally blind**:
Bandit and Semgrep emit **33 distinct CWE classes across the corpus and not one is absence-class**. There
is no rule that can express an absent control, because an absent control writes no token to match.

There, the model contributes:

| measurement | result |
|---|---|
| flags files with an absent control vs clean files | 10/60 vs 1/40, **p = 0.024** |
| names the ground-truth class | 6 of 10 flags |
| deterministic engines on the identical files | **0 of 60** |

Three preregistered controls, each removing a different rival explanation:

| rival explanation | control | outcome |
|---|---|---|
| "it reacts to messy code" | E18 — defective files with no absent control | **0.037**, indistinguishable from clean (p = 0.59) |
| "it recalls a public corpus" | E19 — full anonymisation of identifiers, routes, filename | rate **unchanged**: 10/53 → 10/53, paired diff 0.000 [−0.094, +0.094] |
| "it recognises endpoint code" | E20 — handlers in **both** arms | 0.250 vs 0.071, p = 0.042 *(marginal: one flag flips it)* |

No result points the other way. The convergence is the evidence; no single p-value here is sturdy alone.

## 3. What is still not true

- **It is a weak detector.** ~19–25% of vulnerable files flagged. Four in five missed.
- **File-level only.** Five model aliases × three output formats × an assistant prefill produced **zero**
  machine-readable structure (E16a), while correctly identifying planted defects. The models will not be
  told what shape to answer in; the disposal layer has to consume prose.
- **A third of calls are non-answers.**
- **Structural familiarity is untested** — mutation changed names, not control-flow shapes.
- **No genuinely unseen target exists** for this lab, so full transfer remains unproven.
- **One model, one language, one corpus** — and that corpus is synthetic-seeded, not organic CVEs.

**Therefore: a research result and a roadmap item, not a shippable feature.** The business case sells the
deterministic layer plus a bounded, metered AI cost. It does not sell this.

## 4. What the deterministic layer is actually worth

| finding | measurement |
|---|---|
| multi-engine union recall | **+43.6% relative [+31.5%, +58.4%]**, no measurable precision cost *vs Bandit* — but **22 of 63 repos gain nothing**, so the promise is portfolio-level, never per-application |
| presence vs absence detection | **6.2×** (corrected from a published 9.5× after a CWE-attribution bug misfiled 61% of vulnerabilities) |
| the standard benchmark | contains **0 of 2740** absence-of-control cases — the class is not under-measured, it is **unmeasured** |
| cost of the AI layer | **$0.048–0.051 per run**, ~7k tokens, ~35 s, stable across three live runs |

## 5. What the lab learned about itself — the most transferable part

Twelve quantified corrections in this project's history. **Every one moved a claim against the lab's own
headline. Not one ever found an understatement.** That asymmetry is the finding a reader should take
away, because it will hold for anyone doing this work.

Concrete failures, each now guarded:

| failure | how it was caught | guard |
|---|---|---|
| a **retracted claim still live in code** — the committed instrument printed "+0.069, prior WINS" a day after the decision withdrew it | writing the protocol | correction-propagation law; SM3 |
| the **grouping unit discarded** from the artefact, so the corrected number was unreproducible | Stage-5 check | SM2 verifies the join or aborts |
| **wrong estimand** — 98% of the ranked pairs were cross-repository | Stage-8 review of my own work | SM4 pins both estimands |
| **two vacuous tests** — one recomputed the expression it asserted; one exempted any file containing the word "ties" | Stage-8 review | rewritten as empirical + line-scoped |
| **a harness bug printed `RECALL=0.000`**, which read exactly like the null result we half-expected | Stage-5 question | positive control now gates every run |
| a **classifier that scored "access control looks properly implemented" as a finding** | audited on synthetic cases *before* reading data | SM8 |
| a **mutator that renamed a module path**, breaking imports invisibly to an AST node-count check | validation before measuring | imports asserted byte-identical |
| a **preregistered control arm silently dropped** during a redesign | caught before publication | run, and the claim it restored recorded in order |

**The five rules worth keeping:**

1. **Preregister, and name the estimand in it.** Pooling across groups and averaging within them answered
   the same question in *opposite directions* here.
2. **A correction is not done until the instrument is fixed and a test pins it.** A prose amendment is a
   note about a correction, not a correction.
3. **Every run needs a positive control.** A broken instrument fails in the flattering direction — it
   hands you the null result you were expecting, wearing the costume of rigor.
4. **Have someone else attack it who did not build it**, and have them review the *tests*, not just the
   result. Both vacuous assertions were written by the author of the code they guarded.
5. **Report the fragility next to the number.** "p = 0.042" and "one observation would flip it" are the
   same fact, and only publishing both is honest.

## 6. Open questions, in priority order

1. **Structural familiarity** — does detection survive control-flow-level mutation, not just renaming?
2. **A genuinely unseen target** — the only way to settle transfer. Candidate: code written after the
   model's cutoff, or a private codebase with hand-built ground truth.
3. **Line-level attribution** — blocked by E16a's conformance failure; would need an extraction layer
   over prose, or a model that follows format instructions.
4. **Sensitivity** — 19% is too low to rely on. Is it a prompt ceiling, a model ceiling, or a
   file-level-granularity artefact?
5. **Generalisation beyond one pinned application** for every runtime finding (0025).
