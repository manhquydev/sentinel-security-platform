# Sentinel Research Protocol

How this lab runs an experiment. Every rule here exists because this lab **already made the mistake it
prevents** — the citations are our own corrections, not imported best practice. Rules without a scar
behind them were rejected as ceremony (§7).

Derived from three studies (2026-07-26): how real security labs work
(`plans/reports/researcher-260726-how-real-security-labs-work.md`), experimental-rigor standards
(`docs/plans/reports/2026-07-26-experimental-rigor-standards.md`), and a meta-analysis of this lab's own
13 experiments and 15 corrections
(`docs/plans/reports/2026-07-26-sentinel-implicit-protocol-meta-analysis.md`).

---

## 0. The one-line summary

**Measure, don't trust — including yourself.** Every quantified correction this lab has ever made moved
a claim *against* its own headline. None found an understatement. Assume the same bias in the next
experiment.

---

## 1. Scope

Applies to any work that produces a **number, a finding, or a claim** that leaves this repo — research
log entries, decisions, reports, and the business case. It does not apply to routine implementation.

Two tiers, decided *before* work starts:

| Tier | When | Required |
|---|---|---|
| **Exploratory** | Scouting, feasibility, "is this even measurable?" | §2 stages 1–3 only. Results may **never** be cited as evidence, and are labelled `exploratory` in the log. |
| **Load-bearing** | Any result that will become a decision, a published claim, or an input to the business case | Full §2, plus the load-bearing items of §3. |

Promoting exploratory → load-bearing requires re-running under the full protocol. An exploratory number
does not become evidence by being reused.

---

## 2. Stages

### Stage 1 — Select
State why this question, and what changes depending on the answer. If no decision changes either way,
do not run it.

*Gap this closes: the meta-analysis found no next-experiment selection mechanism at all — experiments
were chosen by momentum.*

### Stage 2 — Preregister (before touching the instrument)
Write into the research log **before** measuring:
- the **falsifiable hypothesis** (not a research question);
- the **primary outcome**, operationalized (the exact number and its computation);
- the **analysis plan** — split strategy, statistic, and what result would **falsify** the hypothesis;
- what result would make us **abandon** the idea.

Anything measured but not preregistered is reported as **exploratory**, in a separate section. This is
what stops the outcome from being chosen after seeing the data.

*Scar: no experiment before E14 had a written success criterion in advance.*

### Stage 3 — Check power before running
State n and the grouping unit. If the corpus cannot support the claim, say so and stop — a
known-underpowered run is cheaper to cancel than to publish and retract.

*Scar: a planned multi-language engine trial was cancelled at this gate on 2026-07-26 — RealVuln's
ground truth is 2089 Python entries against 4 JavaScript, so the comparison was underpowered by
construction. Cancelling cost 10 minutes; publishing would have cost a retraction.*

### Stage 4 — Build the instrument, with its controls
Mandatory before any result is read:
- a **negative control** — an input that MUST NOT trigger (proves the instrument can say "no");
- a **positive control / canary** — an input that MUST trigger every run (proves it is alive);
- **fail-closed**: on any error the run exits non-zero. Never report a smaller number from a partial run.

*Scars: a third-party AI-SAST exited 0 while every model call 500'd (E11); our own discovery step once
fell back to a partial path list and would have reported a smaller gap with exit 0; the runtime probers
now carry both canaries.*

### Stage 5 — Verify the instrument measures what you claim
Ask literally: *what would this instrument print if my hypothesis were false?* If the answer is "the
same thing", it is not an instrument. Check specifically:
- Am I probing **the control itself**, or around it?
- Does my grouping unit leak? If rows share a repo/app/author, **split by that group, never by row.**
- Does the corpus actually contain the class I am claiming to measure?

*Scars: E8 probed the app's direct port and "found" an authorization gap that Kong was correctly
blocking — the finding evaporated. The exposure-gap classifier ran two independent questions through one
ordered branch chain and under-counted app-side controls 7→2. Decision 0021's split was by row, not by
repo. Decision 0024 found a benchmark containing 0% of the class under study.*

### Stage 6 — Run, with the control arm
Every AI-vs-deterministic comparison runs a `--no-llm` control arm. Report the delta, including zero and
negative.

### Stage 7 — Report effect size and interval, never a bare point estimate
A single number with no interval is not a result. Bootstrap over the **grouping unit**. State the
practical meaning, not just significance.

*Scar: "+44% recall" (0022) and "+0.069 AUC" (0021) were both bare micro-averaged point estimates. One
collapsed to a tie under grouped resampling.*

### Stage 8 — Adversarial review before publication
An **independent** reviewer that did not build the instrument must first **reproduce the number**, then
attack it. Self-review is not sufficient.

*Scar, stated by the lab in its own log: "self-review does not catch the errors that matter." Three of
this lab's strongest claims were overturned by adversarial review, never by the author.*

### Stage 9 — Publish with the bound attached
A result may become a **decision** only when: preregistered, controls passed, interval reported,
adversarial review survived, and the **coverage bound stated in the same breath as the finding** — not
in a footnote.

Negative results are published with equal weight. This lab's most valuable outputs are negative.

---

## 3. Pre-flight checklist

**Always (cheap):**
1. Falsifiable hypothesis written down, before measuring.
2. Primary outcome operationalized; exploratory outcomes named separately.
3. Grouping unit identified; split by it, never by row.
4. Negative control + canary exist and are asserted.
5. Instrument fails closed on error.
6. Seeds fixed; tool versions pinned and recorded.
7. Corpus composition audited — does it contain the class being claimed?
8. Effect size + interval, never a bare point estimate.

**When load-bearing (add):**
9. Bootstrap CI over the grouping unit.
10. Ablation: does the component actually contribute over the baseline?
11. Contamination check — could the model have memorized this target? (see §5)
12. Independent adversarial reproduction before publication.

---

## 4. The correction-propagation law

*Added 2026-07-26 after the defect described below. This is the newest and most important rule.*

When a published claim is corrected, **the correction is not complete until the instrument itself is
corrected and a test pins the corrected behaviour.** A prose amendment in a decision document is *not* a
correction — it is a note about one.

Required, in this order:
1. Fix the **instrument**, not just the document.
2. Add a **test with a negative control** that fails if the old behaviour returns.
3. Update the decision **and** the research log.
4. Grep the repo for the superseded number and fix every surviving copy.

**The scar that created this rule:** decision 0021's "+0.069, significant" was withdrawn in prose and
amended to "+0.013 [−0.006, +0.035], a tie". But `rank_baselines.py` kept its row-level
`random.shuffle` split, and on 2026-07-26 the committed instrument still printed
`+0.069 95%CI=[+0.045,+0.095] -> deterministic prior WINS`. For a day, the repo's reproducibility
artifact contradicted the repo's own published correction, and anyone re-running it would have
reproduced the retracted claim with a confident verdict.

**Root cause:** the runtime stack has structural tests (DD1–DD10) pinning every correction; the SAST
measurement stack had **zero test coverage**. Corrections there had nothing to hold them in place.

---

## 5. Contamination rule

Any claim about an LLM's *capability* measured on a famous public target (Juice Shop, WebGoat,
HackTheBox, public CVE corpora) measures **memorization and capability together, inseparably**, and must
say so at the point of the claim.

Corollaries:
- A target that self-identifies (banner headers, `security.txt`, its own metric names) is **not blind**,
  and an A/B "blinded" condition over it measures nothing.
- Note when a corpus is **synthetic/LLM-seeded** rather than organic — RealVuln's repos are
  `vc-*-seeded-v2-*` with `llm_generated_corpus: true`, which bounds what its numbers mean for real code.

*Scar: the Phase-3 LLM hypothesis layer was cancelled at the red-team gate because condition B was never
blind — the target identified itself four independent ways.*

---

## 6. Roles AI may hold in this lab

Set by measurement, not preference:

| Role | Allowed? | Evidence |
|---|---|---|
| Verdict / gate / judge | **No** | LLM judge refused the role 12/12 under correct provenance (0018); LLM verifier dropped 3 of 8 real vulnerabilities (0020). A structural test (DD1) asserts no model is reachable from the verdict path. |
| Ranking / triage where labels exist | **No advantage** | Ties a free deterministic CWE prior (0021, corrected). |
| Narration / summarization | **Yes, bounded** | Costs a measured $0.048–0.051 per run and adds zero findings (E13). Sold as convenience, never as detection. |
| Hypothesis generation | **Unmeasured** | Every measured AI role to date is a verdict-type role the architecture forbids it to hold. The generative role has **zero** measurements. This asymmetry is the lab's biggest open question — see §8. |

---

## 7. Rejected, and why

- **Formal approval committees / sign-off boards** — assume a large team; this lab is one person plus
  agents. Replaced by the Stage-8 independent-agent review.
- **Full OSF registered reports** — months of external peer review; wrong instrument for a 12-week
  capstone. Replaced by the in-repo preregistration of Stage 2.
- **p-values as the headline** — effect size and interval carry the meaning. Keep p only where a
  reviewer expects it.
- **90-day disclosure clocks** — no external vendor is involved; targets are local and disposable.
- **HEAD-first "safe" probing** — explicitly rejected as safety theatre: Express runs the same handler
  for HEAD. Probe safety comes from target disposability and measured state-diffing, not from the verb.

---

## 8. Standing open questions

1. **Is the AI-loses pattern real, or an artifact of our design?** Every measured comparison put AI in a
   verdict-type role the architecture forbids it to hold, and the one generative role was cancelled
   before measurement. Until a generative-role experiment runs, "deterministic beats AI" is only
   established *for gate roles*. Stating it more broadly overclaims.
2. **Does anything here generalize past one memorized target?** Every runtime finding rests on a single
   pinned Juice Shop build.
3. **What is the absence-class recall?** Unmeasurable without a target with genuinely broken
   authorization behind an enforcement point.
