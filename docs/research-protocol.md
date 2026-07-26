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

*Scar (E19): a positive control must distinguish **"the harness could not reach the instrument"** from
**"the instrument answered and was wrong."** A single transient transport failure aborted an entire
experiment whose canary fires reliably (verified 3/3 directly). Retry an **empty/errored** reply; never
retry a **substantive** negative, because retrying until it passes converts the gate into a formality.*

*Scar (E16a, the clearest case yet): an experiment measuring whether an LLM can propose vulnerabilities
printed `RECALL=0.000` on its first run. It had no positive control. The zero was entirely an artefact —
the harness truncated a file mid-function, the model asked a clarifying question, and the parser scored
that as a non-answer. Published unexamined it would have read as "the generative role fails". A planted
blatant defect that the harness MUST surface now gates the run, and it aborts rather than reporting a
zero it cannot distinguish from its own breakage. **A run without a positive control cannot tell a
finding from a broken instrument, and the failure mode is always the flattering direction: a broken
instrument reports the null result you were half-expecting.***

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
- Note when a corpus is **synthetic/LLM-seeded** rather than organic — and check the metadata before
  asserting it. This project stated "RealVuln's repos are LLM-seeded" for months; the benchmark records
  `authorship` per repository and **26 of 66 are `human_authored`** (E59). The disclaimer was wrong about
  40% of the corpus, in the direction that made the work look weaker than it was. **A contamination bound
  is a claim like any other and has to be checked, not inherited.**

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
| **Generation / proposing** (model proposes, deterministic code disposes) | **Yes — measured, bounded** | On absence-of-control classes, deterministic engines flag **0 of 60** vulnerable files while the model names the ground-truth class in **6/60 (p = 0.0137)** on identical files (E17, decision 0027). First capability measured here that deterministic tooling cannot supply. Bounds are part of the claim: ~10% hit rate, file-level only, 33% non-answers, and a public MIXED-provenance corpus (26 of 66 repos human-authored) leaves transfer to private code unproven — though E59 found detection **higher** on the human-authored half, i.e. no evidence for the memorisation story. |

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

1. ~~**Is the AI-loses pattern real, or an artifact of our design?**~~ **ANSWERED (E17, decision 0027):
   it was partly an artifact of role selection.** Every comparison had put the model in a verdict-type
   role the architecture forbids it to hold. Measured in the *generative* role on the classes
   deterministic tooling is blind to, the model wins against a deterministic arm that scores exactly
   zero. The claim is now two-part: deterministic wins or ties in **gate** roles; the model supplies
   what deterministic tooling cannot in the **generative** role.
   **Successor question — also ANSWERED (E18):** the effect is *detection*, not reaction to messy code.
   Files that are objectively defective but carry no absent control draw absence-class language at
   3/80, indistinguishable from files with nothing wrong (p = 0.59) and far below the absence-class arm
   (p = 0.010). **Now open instead:** absent controls cluster in request handlers, so part of the
   discrimination may be *file role* rather than *missing control* — needs a third arm of correctly
   protected endpoint handlers.
2. **Does anything here generalize past one memorized target?** Every runtime finding rests on a single
   pinned Juice Shop build.
3. **What is the absence-class recall?** Unmeasurable without a target with genuinely broken
   authorization behind an enforcement point.

---

## 9. What the first trial changed (E14, 2026-07-26)

The protocol was trialled end-to-end on the lab's own withdrawn +0.069 claim. Four amendments came out
of running it for real rather than reasoning about it:

1. **A joined or reconstructed dataset must be verified element-for-element, or the run aborts.**
   E14 had to recover a discarded grouping unit by replaying a deterministic pipeline. The run was
   allowed to proceed only because the replay matched the committed rows position-for-position. Promoted
   from an implicit part of Stage 5 to a hard gate: *an unverified join is worse than no analysis,
   because it looks like data.*

2. **Never discard ANYTHING re-analysis needs — and "anything" means every form of discarding.** The
   committed baseline recorded no repo field, which is *why* the corrected grouped number had never been
   reproducible. Any artefact that will be re-analysed must persist its grouping key.
   **Amended (E27), because the same mistake recurred in a different shape within eight hours:** two
   experiments stored only the first 400 characters of each model response, which 37–40% of responses
   exceeded. Their live results are sound — classification ran on complete output — but they can never
   be re-verified from the committed artefacts, and a naive re-score *under*-counts them badly enough to
   erase a significant result. **Dropping a column, truncating a string, and rounding a float are the
   same error.** This rule was written about columns and then violated with a string cap by its own
   author the same night, which is the strongest evidence available that a narrowly-worded rule does not
   generalise on its own.

3. **Expect the first version of a test to be wrong.** Two of the six new assertions failed on first run,
   both because the *assertion* was wrong, not the code — a Laplace base rate legitimately varies per
   held-out group, and a conditional verdict string is not a stale claim. The negative control is what
   distinguished "my code is broken" from "my expectation was broken". A test that passes first try on a
   subtle invariant deserves suspicion, not confidence.

4. **Correction propagation is a search, not an edit.** §4 step 4 found the decisions index still
   advertising *both* retracted figures as live findings, 0023's headline contradicting its own
   correction table two paragraphs above it, and 0024's title resting on a withdrawn size claim. The
   originating document had been corrected months of work earlier; the copies had not. Grep is mandatory,
   and the index is the highest-risk surface because it is the most read and the least re-read.

**Generalised lesson.** The runtime stack held its corrections because DD1–DD10 pinned them; the
measurement stack lost its correction because nothing did. **Any code path that produces a published
number needs the same guard as a code path that produces a verdict.** A retracted claim with no test
against it will come back.

---

## 10. What Stage 8 caught that Stages 1–7 could not (2026-07-26)

E14 was written specifically to demonstrate this protocol. It was preregistered, controlled, verified,
interval-reported — and its headline conclusion was still wrong, because it fixed the **split** and
inherited the **micro-averaging** sitting right next to it. An independent reviewer reproduced every
number, then measured that only **1.9%** of the pairs the pooled AUC ranked were within-repository.

Three rules follow, and they are the highest-value output of the whole exercise:

1. **Name the estimand before measuring, and justify it from the deployment.** "AUC" is not one number.
   Pooling across groups and averaging within groups answer different questions and here they disagreed
   in *direction* — tie versus a clear win. Which one is right is a **product** question (does the user
   triage one application at a time, or one global queue?), so it must be argued in the open, never
   settled implicitly by a pooling step. Add to the Stage-2 preregistration.

2. **Fixing a known flaw does not immunise you against its neighbour.** The protocol named
   micro-averaging as half the scar (§2 Stage 7) and E14 still shipped with it. When correcting a
   defect, enumerate the *other* defects of the same family and check each explicitly.

3. **A test written by the instrument's author can be vacuous in exactly the way the instrument is
   wrong.** SM4 recomputed the expression it was asserting and therefore could never fail; SM6's
   file-wide search exempted any file whose docstring merely used the word "ties". Both were written by
   the same person who wrote the code they guarded. **Stage 8 must review the tests, not only the
   result.**

**Standing consequence:** no result becomes a decision on the strength of author-written tests alone.

---

## 11. `temperature=0` is not determinism (E22, 2026-07-26)

The night this protocol was written, three of its own experiments were built on an assumption nobody
tested: that a frozen prompt at `temperature=0.0` returns a stable verdict. **Measured: ~40% of raw verdicts differ (n=38) — but E31 shows most is clean<->non-answer churn; FLAG decisions churn on only ~1 file in 12**, and the model never
returned identical prose once (0 of 38).

Two experiments died of it. E19 paired freshly measured mutated verdicts against *reused* original ones;
its perfect null — 3 lost, 3 gained, difference exactly 0.000 — is what that flip rate alone produces,
mutation or not. E20 compared a reused arm against a fresh one. Both are withdrawn.

**The rules that follow, now mandatory:**

1. **Measure instrument stability before designing around it.** Query the same input *k* times and
   report the disagreement rate. This is a Stage-4 obligation alongside the negative control and the
   canary, not an optional refinement.
2. **A single LLM verdict is a noisy measurement, not an observation.** Where the verdict matters, take
   it as a **rate over k runs**, not a label from one.
3. **Never reuse one run's verdicts as fixed values in a paired design.** If arm A was measured
   yesterday and arm B today, they are not paired — they are two samples from a noisy process, and the
   difference between them carries the noise of both.
4. **A null result is only informative if the instrument is stable enough to have shown the effect.**
   Before concluding "X changed nothing", check whether the instrument could have detected a change of
   that size at all.

*The uncomfortable part: the protocol's own §2 Stage 4 said "build the instrument, with its controls"
and listed a negative control, a canary and fail-closed behaviour. It never said "and check that it
returns the same answer twice." Three experiments were designed, preregistered and published in one
night on top of that gap.*

---

## 12. A simulation is an instrument (E30, 2026-07-26)

A noise model built in the final hour of this session concluded that **every** published interval
crossed zero — that the whole generative-role finding dissolved once measurement error was honestly
included. It was wrong. It treated a measured **disagreement rate** (0.395) as a per-verdict **flip
probability**, and two draws disagreeing with probability 2θ(1−θ) is not the same thing at all.
Modelling it as a flip annihilated the signal in both arms by construction, whatever the data said.

It was caught by one thing: this lab had already **measured** the quantity the model was estimating.
E28's replication put run-to-run drift of the headline difference at **0.001**; the model predicted
~0.2. Two orders of magnitude, against a direct measurement.

**Rules:**

1. **A simulation is an instrument and gets the same treatment as one** — a positive control, a
   sanity check against a known quantity, and Stage-5's question (*what would it print if the
   hypothesis were false?*). A model that outputs the null for every input is not measuring the world.
2. **Validate models against measurements, never the reverse.** Where a direct empirical estimate of the
   modelled quantity exists, it wins. If the model disagrees with it by orders of magnitude, the model
   is broken — that is not a finding about the data.
3. **Watch for the flattering-in-reverse result.** Everything else in this protocol guards against
   claims that flatter the author. This one would have retracted five of the author's own findings in a
   dramatic act of apparent rigour, and it was just as false. **Self-criticism is not self-evidently
   correct**, and a humble-sounding result deserves the same verification as a triumphant one.

---

## 13. An authored control is not a control until someone else audits it (E34, 2026-07-26)

A test set of 12 matched pairs was built to measure detection: each pair implements the same feature
twice, one with a required security control removed, one with it present. The "present" variants were
the ground-truth negatives.

**Two of the twelve were not negatives.** One re-checked a password with no rate limit; one had no
authentication at all while returning account data for an arbitrary user-supplied reference. In the
second case the gap sat in **both** arms, so that pair's positive label was wrong too.

The two were not independent slips. They share one shape: **the author applied each control class only
where it was the answer key.** Rate limiting appears in the pair whose planted class was rate limiting,
and nowhere else. Authentication appears in every control variant except the one whose planted class was
something different. Writing a matched pair focuses attention on the class under test and silently
withdraws it from everything else.

**Rules:**

1. **A control variant must be audited against the FULL class list, not against its own pair's class.**
   Its own class is the one the author was already thinking about; the others are where the defect will be.
2. **The audit must be done by someone who did not write the set, and who has not seen the results.**
   Blind to the outcome is what makes a later exclusion legitimate rather than post-hoc selection.
3. **Publish the pre-audit number as well as the post-audit one.** Excluding invalid pairs will usually
   *improve* the result — here 7/12 → 7/10 and p 0.0136 → 0.0015 — and a reader who distrusts the
   exclusion is entitled to the conservative figure. **Quote the conservative one in decisions.**
4. **Assume this flaw in every previously authored set.** It applies retroactively to anything built the
   same way, whether or not it has been re-audited yet.

*The general form, worth stating because it is not specific to test sets: when you build the thing you
will be graded against, you defend the part you are thinking about. The rest is where you should look.*

## 14. A measurement must be derived from the evidence you can keep (E38–E39, 2026-07-26)

A verdict stored in an artefact is not raw data. The model's prose is the data; the verdict is one
deterministic reading of it. Every fix to the classifier therefore ages every verdict already written
down, silently, and the artefact goes on asserting something about an instrument that no longer exists.

**The scar.** A sweep re-deriving every stored verdict from its own stored prose found 11 rows across 7
artefacts disagreeing with their own data. The cause was specific and provable: responses in which the
model merely echoed the source file back inside a code fence had been scored as findings, before the
classifier learned to strip code spans. The drift went **both ways** — it had inflated one published
headline (15/59 → 14/59) and left another artefact more pessimistic than the figure already published
(fp 2 → 1). A defect that only ever flattered us would be luck; one that runs in both directions is
systematic, and only the sweep could tell those apart.

**Why the existing guard did not catch it.** The freshness guard compares *commit times*, so an artefact
committed alongside its instrument passes while still disagreeing with it. **Freshness is not
reproducibility.** Only re-deriving the value tests the second, and every derived value now carries a
guard that does so, with a planted disagreement as its negative control.

**The rule this generalises to, which is the part that will matter next time.** *Score the evidence you
are able to commit, not the evidence you had in memory.* The first run of E39 computed its verdicts from
the raw model response while persisting a redacted copy — so the published number could not have been
re-derived by anyone, including us. The reproducibility guard caught it on its first real use. Scoring
moved onto the persisted text, and the estimate fell from +0.151 to +0.094 with a lower bound that now
touches zero.

That is the shape to expect: the number you can defend is usually weaker than the number you first saw.
Where redaction, truncation or sampling stands between the measurement and the record, work out which
direction it biases and say so — here redaction can only delete characters, so it can suppress a
detection and never invent one, which makes the surviving rates a floor. And when the loss lands
unevenly across arms, report that too: it cost three files, all in the arm that favoured the hypothesis
under test.

**Corollary.** If prose was truncated when it was stored, it cannot be re-derived at all, and re-scoring
it is worse than leaving it alone — the classifier would be reading text the original verdict was never
based on and would "correct" sound verdicts using evidence that no longer exists. Those artefacts are
reported as *unverifiable*, never as *clean*. Two of ours are.

## 15. A rate is not a detection (E42–E43, 2026-07-26)

An aggregate rate can replicate perfectly while meaning something entirely different from what everyone
reading it assumes. Two independent runs of the same experiment over the same 53 files returned the same
counts — 6/53 and 1/53, difference +0.094, identical to the digit — on responses that were byte-different
in 52 of 53 cases. It was a genuine second measurement, and the six files it named **overlapped with the
first six in none**.

Everything downstream had been written as though the number described *detection*: that the model finds
the missing control in about 11% of such files. It does not. It **reports** at that rate, on a shifting
set of files. Two runs produce two disjoint worklists, both correct at the published rate, and an engineer
handed either one has no way to know that.

Repeated readings of the same file then showed why: per-file propensity is a **mixture**. Files reported
once come back at 0.333 against 0.083 for files never reported — so it is not a lottery, there is a real
per-file property — but the highest propensity measured on any file is **0.67**, and none is reliable.
Propensities spread between roughly 0 and 0.67, which is exactly the shape that yields the same count from
disjoint sets. That the mixture was measured independently and *then* found to predict the earlier
anomaly is the reason to believe it.

**The rules this leaves.**

- **Before describing a rate as detection, measure whether the same items recur.** Two runs and a set
  intersection is enough to find out, and it is cheap next to the cost of publishing the wrong claim. A
  rate that replicates is evidence about the rate and about nothing else.
- **Report the per-item distribution, not only the mean.** "0.333" concealed a spread from 0.00 to 0.67,
  and the spread is the finding — the mean alone reads as a modest detector rather than as a process that
  never reliably identifies anything.
- **Where per-item propensity is below one, repeated reading is required rather than optional, and every
  cost figure must carry the k.** A file at 0.33 is found with probability 0.33 at k=1 and 0.70 at k=3.
  One call per file buys about a third of what a single-run sensitivity implies, and quoting the sensitivity
  beside a one-call-per-file cost overstates both.
- **A union-over-k estimand is a different quantity from a single reading, and must be labelled as one.**
  It is often the honest choice — it matches how the capability actually behaves — but substituting it
  quietly for a single-reading figure inflates the result while appearing to report the same thing.

## 16. Ask the committed data before scheduling a run (E45, 2026-07-26)

A handover plan written at 13:08 listed "what fraction of the corpus carries no signal" as owed work
requiring fresh model calls. Thirty minutes later it was answered from artefacts already in the
repository, at zero cost, and it turned out to be the most commercially consequential number in the whole
line of work.

The reframing that unlocked it: **two independent single readings of a corpus are a propensity measurement
of that corpus at k=2.** They had been filed as "the replication" and read only for whether the headline
reproduced. Weak per file, strong in aggregate — and aggregate was exactly the question being deferred.

**The rule.** Before scheduling a run, state the quantity you want and ask which committed artefacts
already constrain it. Runs cost time and money and consume the instrument; re-reading is free and cannot
fail a canary. This is not an argument against running experiments — it is an argument against running one
whose answer is already on disk under a different name.

**The corollary that keeps it honest.** Re-analysis of existing data is exactly where a lab is most free to
find the answer it wants, because the analyst already knows the data. So a re-analysis must be held to the
same standards as a run: state the estimand first, report the model-free number as the headline and any
model-based refinement second, and prefer a bound you can defend to a point estimate you cannot. In E45
the model-free figure (0.774 never named, an upper bound) leads, and the two model-based corrections
disagreed by 0.09 — that disagreement was reported, because it is the honest measure of how much the model
deserved to be trusted.

## 17. A check with no falsifying outcome is not a check (E50, 2026-07-26)

Every correction in this protocol before now came from a guard catching something: a stale artefact, a dead
vocabulary, a verdict scored on text nobody kept. E50 came from none of them, and no guard in the
repository could have caught it, because nothing was broken. The arithmetic was right, the artefacts were
clean, the instrument was sound.

**The defect was in the question.** A "saturation test" compared union coverage over k readings against the
number of files that fired at least once in those k readings, found them equal, and read the equality as a
ceiling. Those two quantities are *the same quantity* — a file is in the union exactly when it fired at
least once. The comparison had no outcome that could have contradicted the conclusion, so its agreement
carried no information at all, and it felt like confirmation precisely because it was guaranteed.

The claim that rested on it — *"the capability saturates at 0.417; further readings buy cost and nothing
else"* — reached a decision record and a stakeholder report before three additional readings falsified it:
union 0.542 and still climbing, three supposedly-unreachable files surfacing.

**The rule.** Before treating any comparison as evidence, state what result would have falsified it. If no
such result exists, it is a definition being restated, not a measurement. This applies with special force
to checks that feel like confirmation, because a check that cannot fail always does.

**Two properties that make this class hard to catch, and both were present.** The conclusion was
*plausible* — diminishing returns were genuinely measured, so a ceiling was a natural next inference. And it
was *unflattering*, which suppressed scepticism: a lab trained to distrust results that flatter it will
wave through the ones that do not. **Being wrong in the pessimistic direction is still being wrong**, and it
misprices a product just as badly.

**Corollary for guards.** SM24 pinned the affected figure inside a band and passed throughout, because the
corrected value stayed in band. A guard on a *value* cannot detect a broken *question*. Nothing here
substitutes for asking, of each check, what it would look like if the claim were false.

## 18. A coverage number is a function of the budget, not a property of the corpus (E51, 2026-07-26)

Three times in one afternoon the same figure was published, and three times reading deeper moved it:

| | k=6 | k=9 | k=12 |
|---|---|---|---|
| "files never surfaced" | 0.583 | 0.458 | **0.333** |
| "files always detected" | 2 of 24 | 1 of 24 | **0 of 24** |

Every version was an upper bound wearing the clothes of a measurement, and the phrasing made it worse:
*"unreachable by this method at any k"* was written about files that fired three readings later, and
*"detected in every reading"* was written about files that later missed.

**The rule.** Any coverage, recall, or never-surfaced figure produced by repeated sampling **must be
quoted with its k**, and must be described as what that budget bought rather than as what the method can
do. "33% are never surfaced" is not a finding; "33% were not surfaced in twelve readings" is.

**The trap that makes this hard.** The curve goes flat for stretches — here k=8 through k=11 produced
nothing new, then k=12 added a file. A flat stretch feels like a plateau and is the exact evidence a
saturation claim seems to rest on. **A plateau may only be claimed from many readings past the last
increase, never from a flat run**, and the honest default is that no ceiling has been located.

**Corollary for anything selected on a previous reading.** "Always detected" and "never detected" are both
selection effects at small k. Both regress under deeper reading, in opposite directions, and both were
published here before they did.

## 19. A validity threat that no experiment can close still needs an owner and a plan

Rules 1–18 all assume the answer to a doubt is another measurement. Some doubts are not like that, and
this lab has been carrying one all day while treating it as a footnote.

**The standing example.** Every result here is measured on a corpus of mixed provenance — 26 of 66 repos
human-authored, 40 LLM-generated (E59 corrected an earlier blanket claim that all of it was seeded) —
scored against labels that are demonstrably incomplete — a deterministic
scan found ten endpoints with an unbounded client-controlled `limit` and the ground truth labels that class
zero times — and supplemented by matched-pair files this lab authored itself, which three separate
measurements show are **easier** than corpus files. No amount of re-reading, re-scoring or replication
touches any of that. Running more experiments on the same corpus makes the numbers tighter and no more
transferable.

**What was wrong with how it was handled.** It sat in the owed-work list under a line saying it "cannot be
closed by running anything", which is true and is not a plan. A threat filed that way stays filed: it never
competes for effort against items that *can* be closed by running something, so it survives every session
that keeps busy.

**The rule.** A validity threat that no experiment can close must still carry, in writing:

1. **What it invalidates specifically** — not "the results", but which claims and by how much. Here:
   nothing measured transfers to private, human-written code, and the transfer gap is unquantified because
   the only available comparison is against material with the same defect.
2. **A named next action that is not an experiment** — sourcing data, an external review, a licence, a
   collaboration, a purchase. If the action is a decision above this lab's authority, name the decision
   and who owns it rather than restating the constraint.
3. **The cost of the action**, so it can lose to something better on merit instead of by default.
4. **What the results are worth if it is never closed.** Usually not nothing — here the *negative* results
   (the model cannot see CWE-307; no file is reliably detected; the union saturates) are far more robust to
   corpus provenance than the positive ones, because a defect the model misses on easy seeded code will not
   suddenly be found on harder real code.

**The general form.** *Measure what you can, and for what you cannot, write down precisely what you are
therefore not entitled to say.* An unclosable threat is not an excuse for silence and not grounds for
discarding the work; it is a boundary that has to be drawn explicitly, because the alternative is that
every reader draws it wherever flatters them.

## 20. Run the suite BEFORE the push, not after (three times, 2026-07-26)

Not a research rule — an operator rule, recorded because it happened three times in one day and each time
the same way: edit, commit, push, *then* run the suite, discover red, fix, push again. The window between
those two pushes is a period where `main` is broken and anyone pulling it inherits the breakage.

The three:

1. Adding `canary_passes` aged every artefact past its instrument — SM17 red on `main`.
2. The `run_generative` scoring fix changed stored verdicts — SM19 red on `main`.
3. Editing one comment string in `run_multiengine_grouped` aged its artefact — SM7 and SM17 red on `main`
   for 48 minutes, across a session boundary.

**What makes this specific to the way this repository is built.** Its guards deliberately assert over
*committed artefacts* and *git commit times*, so a change to an instrument can turn a guard red without
touching a single number — case 3 was a comment. That design is right and is what caught real defects all
day, but it means "the edit was cosmetic" is never a reason to skip the suite. It also means the fix is
often to regenerate an artefact rather than to change code: the deterministic runners can simply be re-run,
and case 3's re-run reproduced all eight committed totals exactly.

**The rule.** The suite runs between `commit` and `push`, always, including for documentation-only and
comment-only changes. If a run is too slow to sit through, push nothing until it has finished — a delayed
push costs minutes, a red `main` costs whoever pulls next.

## 21. A number computed inline is invisible to every guard you have (E62)

E58 published "the rule adds +0.104 to the model at k=1". The figure was quoted in the ledger and in a
decision record, and when the detector changed it had to be re-checked — at which point it emerged that it
had been **computed in a throwaway command and no instrument was ever committed**. Its denominator implies
48 files; the file sets that exist in the committed artefacts are 60 and 40. Nothing reconstructed 48.

Rebuilt properly the number replicated (+0.103 [0.042, 0.125] over 22 readings), so this rule is not about
a wrong answer. It is about the fact that **nobody could have found out either way.**

**Why the existing guards could not help.** `SM17` compares each artefact against the instrument that
writes it. `rescore_artefacts.py` re-derives stored verdicts from persisted prose. Both operate on
artefacts. An inline computation produces no artefact and no instrument, so it is not merely unchecked —
it is **outside the domain of every check the project runs**, permanently, and it stays that way while
being cited as though it had passed them.

**The rule.** Any number that reaches the log, a decision record, or a stakeholder report is written by a
committed script that persists an artefact. Exploratory commands are fine and are how most of these
findings start — but the moment a figure is going to be quoted, the command becomes a file. If that feels
disproportionate for a one-line calculation, note that E58's was one line.

**Pinned by `SM25`**, which requires every log entry from E60 onward to cite an instrument or artefact.
It is not retroactive: 55 of the 86 earlier entries would fail it, and rewriting history to satisfy a new
guard would destroy the record of how the work actually went. The guard starts where the rule starts.

**The same principle covers cited evidence, not just computed numbers.** `plans/` is gitignored in this
repository and `docs/plans/reports/` is tracked. A committed claim that cites a report under `plans/` is
resting on evidence no reader can open — the E62 defect in a different costume. Several older documents
already do this and are left alone as historical record; anything written from now on cites the tracked
copy. E64 was caught by this while being written: its external-practice source was sitting in the ignored
tree and was moved before the entry was committed.

## 22. A number from another corpus is not a benchmark until your corpus admits it (E65)

E64 quoted a published curve — HARMLESS finding 90% of vulnerabilities at 16% of files — against this
project's 37%, concluded the external method was "more than twice as efficient", and named the gap the
strongest open lead. One measurement retired it: the **oracle** ordering, files opened in descending true
defect count, which no ranker can beat, needs **30.4%** on this corpus. The external figure sits below what
perfect knowledge achieves here, so it was never a target.

The mechanism is the same one §18 records for coverage. An effort-at-recall figure is not a property of a
method; it is a joint property of the method and **how concentrated the defects are**. Thirty-eight percent
of the files here carry a defect. In the setting the external number came from, vulnerable files are a
small minority. The two numbers were never on the same axis.

**The rule.** Before an external figure is used as a target, compute what the *best possible* method
achieves on our data. If the external number beats the oracle, the corpora differ and the comparison is
void — and the oracle, not the external figure, is the baseline worth reporting, because it also states how
much headroom the whole line of work is competing for. Here that headroom was **6.5 percentage points**,
which closed a research direction rather than opening one.

This applies with equal force in the flattering direction: beating an external number on a corpus where the
oracle is generous proves nothing either.

## 23. Preregistration written while the run is in flight is still preregistration — but only if nothing has been read

The organic post-cutoff paired evaluation (E75) was launched before its interpretation criterion was
written. That is a real lapse: §7 requires the decision rule before the data. It was caught while the run
was still executing and with **no output read** — the log was checked for size and process liveness only,
never for content — so the criterion below is recorded now, before any result exists in this session.

**The criterion, fixed in advance.** The evaluation asks whether the model detects maintainer-confirmed
missing-control defects in organic post-cutoff production code. With ~9 repositories the inference is
**collapse versus non-collapse only**, because cluster-robust intervals are downward-biased below ~30
clusters (external review, `docs/plans/reports/researcher-260726-2226-contamination-safe-llm-security-eval-practice-report.md`).
Therefore:

- **COLLAPSE** — the memorisation caveat is confirmed as load-bearing and no generative-role number may be
  presented as transferable — if pre-fix detection at k≤3 is **below half** the corpus rate at matched k
  (corpus k=3 union on positive-arm files ≈ 0.458, so the collapse line is **< 0.229**).
- **NON-COLLAPSE** — the caveat is materially reduced, though not removed — if pre-fix detection is at or
  above that line **and** post-fix (control) flagging stays consistent with the ≤~3% specificity bound
  this project has measured, i.e. the paired arms separate.
- **UNINTERPRETABLE** — if fewer than 8 paired sites resolve, or the canary fails, or the two arms both
  flag at high rates (the model flagging everything is not detection, §15).

**No p-value will be quoted as the headline.** Nine clustered repositories cannot support one. The paired
Fisher figure is reported as a descriptive companion and explicitly not as inference.

**Why the rule matters more than the result.** Writing it afterwards would let any outcome be read as
success — which is precisely how E50's unfalsifiable saturation claim happened. The rule above admits an
outcome that would damage the project's main line of work, and that is the point.
