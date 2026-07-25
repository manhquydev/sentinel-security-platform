# The night the lab audited itself

2026-07-26. The task was not to build a feature. It was to stop working like an enthusiast and start
working like a laboratory — study how real security research is actually run, write our own protocol
from it, then prove the protocol by turning it on our own work.

Turning it on our own work is the part that hurt.

## What we found in our own repository

Decision 0021 had published "+0.069 AUC, the deterministic prior WINS", then withdrawn it as a
row-split artefact and amended it to a tie. That withdrawal was written in prose, in a decision
document, months of work ago.

The code never got the message. `rank_baselines.py` still shuffled *rows* and still printed:

```
paired bootstrap AUC(cwe_prior) - AUC(llm) = +0.069 95%CI=[+0.045,+0.095] -> deterministic prior WINS
```

For a day, this repository's reproducibility artefact **contradicted this repository's own published
correction**, with a confident verdict and an interval that excluded zero. Anyone re-running it would
have reproduced the retracted claim and reasonably concluded the retraction was the mistake.

Worse: the committed baseline had **discarded the repo field**, so the *corrected* number was not
reproducible from committed data either. The right answer existed only as a sentence someone wrote.

The root cause was structural and, once seen, obvious. The runtime stack had DD1–DD10 pinning every
correction with a negative control. The SAST measurement stack had **no tests at all**. Corrections
there had nothing holding them in place, so they drifted back out.

That produced the protocol's newest and most important rule: **a correction is not complete until the
instrument is corrected and a test pins it.** A prose amendment is not a correction; it is a note about
one.

## Then the reviewer turned on us

E14 was written specifically to demonstrate the protocol. Preregistered before measuring. Abort
condition on an unverified join. Grouped split. Interval reported. It concluded: **tie**.

The Stage-8 adversarial reviewer reproduced every number, then measured something we had not thought to
look at — of the 358,020 pairs our pooled AUC was ranking, only **1.9% were within-repository**. We had
fixed the split and inherited the micro-averaging sitting two sections away in our own protocol
document, which names micro-averaging as the other half of the same scar.

On the estimand that matches how the tool is actually used — a pentest team triaging **one client
application at a time** — the same scores give **+0.095 [+0.063, +0.128]**, and the prior wins clearly.

So the claim has now been revised three times:

1. **+0.069, prior wins** — invalid method (row split).
2. **tie** — valid method, wrong estimand (98% of the comparison was cross-application).
3. **+0.095, prior wins per application; tie pooled** — both published, primary stated and argued.

The original *direction* turned out to be right. It was still an invalid result, and saying so plainly
matters more than the fact that it pointed the correct way. A stopped clock does not get credit.

The same review found two of our own guards were defective in precisely the way the instrument was:
**SM4 recomputed the expression it was asserting** and therefore could never fail, and SM6's file-wide
search exempted any file whose docstring happened to contain the word "ties". Tests written by the
author of the code they guard can be vacuous in exactly the direction the author is blind.

## The zero that was not a result

Late on, measuring whether an LLM can *propose* vulnerabilities — the one AI role this lab had never
tested, because every role we ever measured was a gate role the architecture forbids it to hold anyway
— the harness printed:

```
RECALL=0.000
```

That number would have fit the lab's story beautifully. "Every AI comparison ends badly" — here it is
again, cleanly, in the last untested role.

It was an artefact. The harness had truncated a source file mid-function; the model replied *"File
truncated mid-`serialize_dispute`. What needed?"*; the parser scored the clarifying question as a
non-answer. There was no positive control, so a broken harness and a genuine null result were
indistinguishable.

What caught it was the protocol's own Stage-5 question: *what would this instrument print if the
hypothesis were false?* The answer was "0.000 — the same thing it just printed." That is not an
instrument.

**A broken instrument fails in the flattering direction.** It hands you the null result you were
half-expecting, wearing the costume of rigor.

## What the models actually do

With a positive control in place, the real finding arrived: five model aliases, three requested output
formats, plus an assistant prefill — **zero format compliance**. Not one would emit `FINDING: line=… cwe=…`,
or a JSON array, or even begin a reply with the single word YES.

And every one of them that engaged **correctly identified both planted defects**. They were not refusing
on provenance grounds, which is what we predicted. They were not incapable. They simply will not be told
what shape to answer in. They want to hand you a patch.

So the disposal layer had to stop demanding structure and start consuming prose — the model proposes in
its native form, deterministic code decides. Which, on reflection, is closer to "AI proposes, tools
dispose" than forcing JSON ever was.

Then the classifier we wrote to do that disposal turned out to score *"access control looks properly
implemented here"* as a **finding**, and to be structurally incapable of matching the word
"Authorization" at all. We found that by testing it on invented sentences **before** looking at any
experimental data. Had we tested it afterwards, every fix would have been indistinguishable from tuning
until the answer looked good.

## The result we were not allowed to keep

The generative experiment came back: **21% of vulnerable files flagged, 0 of 16 clean control files
falsely flagged.** Separation +0.208, bootstrap interval excluding zero.

It is the first time in this project's history that an AI arm has pointed in AI's favour.

We are not allowed to report it. The preregistration, written before the data existed, said a marginal
result would be **reported as inconclusive rather than spun**. Fisher's exact test — the right test for
these counts, where a bootstrap with a zero cell cannot represent the uncertainty it pretends to — gives
**p = 0.065**. Not significant. Underpowered.

Quoting the bootstrap interval instead would have been the identical error that produced the retracted
+0.069: reading a positive point estimate as a win.

So it is recorded as inconclusive, and a powered replication was sized by simulation (60 + 40, 83%
power), preregistered, and committed to run **once** on a **disjoint** sample with the outcome published
whatever it is. If it lands at 0.06 we say so.

## What actually changed

The lab's headline was "every measured AI-vs-deterministic comparison ended with AI losing, tying, or
being unanswerable." After tonight that sentence has a boundary drawn around it: it is established **for
gate roles**, which is the only place it was ever measured. For the generative role the honest status is
*unresolved, direction positive, underpowered* — no longer an untested blank, and not yet a result.

Twelve quantified corrections in this lab's history have all moved claims **against** its own headline.
None has ever found an understatement. Tonight added more of them, including three against work written
hours earlier by the same process that was supposed to prevent them.

The protocol is not what makes the work correct. Nothing does. What the protocol buys is that the errors
get found by us, in a repository nobody has shipped yet, instead of by a client with a report in their
hand.
