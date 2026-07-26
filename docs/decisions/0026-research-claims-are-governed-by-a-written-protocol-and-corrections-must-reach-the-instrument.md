# 0026 Research claims are governed by a written protocol, and a correction is not done until it reaches the instrument

Date: 2026-07-26

## Status

Accepted. Establishes `docs/research-protocol.md` as the governing process for any claim that leaves
this repository. Trialled end-to-end on this lab's own retracted claim (E14/E15) and amended twice from
what the trial broke.

## Context

Thirteen experiments had been run with **no written protocol**. A meta-analysis of the lab's own history
(`docs/plans/reports/2026-07-26-sentinel-implicit-protocol-meta-analysis.md`) found 15 self-corrections
across E1–E13 and one uncomfortable regularity: **every quantified correction moved a claim against the
lab's own headline. None ever found an understatement.**

Two live defects made the cost concrete:

1. **A withdrawn claim was still shipping.** Decision 0021's "+0.069, deterministic prior WINS" had been
   retracted in prose and amended to a tie. But `rank_baselines.py` kept its row-level split and, on
   2026-07-26, still printed `+0.069 95%CI=[+0.045,+0.095] -> deterministic prior WINS`. The repository's
   reproducibility artefact contradicted the repository's own published correction.
2. **The corrected number was not reproducible either.** The committed baseline had discarded the repo
   field, so the grouped analysis that produced the correction could not be re-run from committed data
   at all. The right answer existed only as a sentence.

Root cause was structural, not careless: the runtime stack had DD1–DD10 pinning every correction with a
negative control; the SAST **measurement** stack had **zero test coverage**. Nothing held its corrections
in place.

## Decision

**1. A written protocol governs any number, finding, or claim that leaves this repository.**
`docs/research-protocol.md`: nine stages (select → preregister → power → instrument with controls →
verify the instrument → run with a control arm → report effect size and interval → adversarial review →
publish with the bound attached), a tiered pre-flight checklist, and explicit rules on contamination and
which roles an LLM may hold. Every rule cites the lab's own scar; practices assuming a large team were
rejected rather than performed.

**2. Preregistration before measuring.** Hypothesis, primary outcome, analysis plan, falsifying result
and abort condition are committed **before** the instrument runs. Anything measured but not preregistered
is reported as exploratory and may not be cited as evidence.

**3. The estimand is part of the preregistration.** "AUC" is not one number. Pooling across groups and
averaging within groups answered the same question in **opposite directions** here — tie versus a clear
win. Which is correct is a *product* question and must be argued in the open, never settled implicitly
by a pooling step.

**4. The correction-propagation law.** A correction is not complete until:
   (a) the **instrument** is fixed, not only the document;
   (b) a **test with a negative control** fails if the old behaviour returns;
   (c) the decision **and** the research log are updated;
   (d) the repository is **searched** for surviving copies of the superseded number.
   A prose amendment in a decision document is not a correction — it is a note about one.

**5. Any code path that produces a published number carries the same guard as one that produces a
verdict.** `tests/sast-measurement-test.sh` (SM1–SM7) now pins the measurement stack, including an
assertion that fails if any superseded figure reappears in measurement code.

**6. No result becomes a decision on author-written tests alone.** Stage-8 review covers the **tests**,
not only the result.

## Measured consequences of applying it

| claim | before | after the protocol |
|---|---|---|
| 0021 prior vs LLM | "+0.069, significant" (retracted, still in code) | **+0.095 [+0.063,+0.128] per application**; +0.012 [−0.006,+0.035] pooled — both published, per-application primary |
| leakage from row-splitting | "+0.057" | **+0.022** at matched fold count and train size (the original confounded grouping with train size) |
| 0022 multi-engine gain | "+44%, no precision cost" (bare point estimate) | **+43.6% [+31.5%, +58.4%]**, precision delta spans 0 — **survives**, and now carries the caveat that **22 of 63 repos gain nothing** |
| 0023 presence-vs-absence | 9.5×, "absence is the larger half" | 6.2×, size claim **withdrawn** — propagated to 0024's title and the decisions index, which were still carrying it |
| generative AI role | untested blank | **unresolved, direction positive, underpowered** (E16b: 21% vs 0% clean, Fisher p = 0.065) |

The protocol both **demolished** (0021) and **confirmed** (0022) load-bearing claims. A process that only
ever destroys is a bias, not a method.

## Consequences

- **The lab's headline claim is now bounded.** "Every measured AI-vs-deterministic comparison ended badly
  for AI" is established **for gate roles**, which is the only place it was ever measured. Stating it more
  broadly overclaims, and the Week-12 business case is written to that boundary.
- **Three of this session's corrections were against work written hours earlier by the process meant to
  prevent them** — including an experiment written specifically to demonstrate the protocol. Fixing a
  known flaw does not immunise an analysis against the neighbouring flaw.
- **A broken instrument fails in the flattering direction.** A missing positive control let a harness bug
  print `RECALL=0.000`, which read exactly like the null result the lab half expected. Positive controls
  are now a hard gate, not paperwork.
- **Cost:** preregistration and adversarial review add real time per experiment. Accepted deliberately —
  the alternative is discovering the error in a client's hands rather than in an unshipped branch.
- **Deferred:** a fully nested bootstrap (the current one reuses pre-computed scores and so understates
  intervals — stated in the artefact, blocking only for a positive claim); generalisation of any runtime
  finding beyond the single pinned target.
