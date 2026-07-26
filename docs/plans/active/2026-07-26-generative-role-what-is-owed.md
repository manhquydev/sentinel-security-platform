# What the generative-role line of work owes, and in what order

Status: active. Written 2026-07-26 after E37–E44. Everything below is runnable; nothing is blocked on a
decision. The ordering is by what would change a conclusion, not by cost.

## The state this hands over

Decision 0027 rests on a claim that has been narrowed three times and now reads: on **absent ownership and
absent authentication**, the model reports at a **rate** of roughly 11% of files, **without per-file
consistency**, with a measured per-file ceiling of **0.667** and most files at exactly **zero**. Repeated
reading is required for the capability to mean anything at file level, and every cost figure must carry
the k.

Two things are settled and should not be re-litigated without new evidence:

- CWE-307 (missing rate limit) is very nearly invisible in this role — 1 of 53 real defects named (E39),
  not recovered by removing competing defects (E41), and not addressable by asking directly, because a
  targeted prompt could not be made to discriminate a present control from an absent one (E40).
- The per-file result is a mixture, not a lottery and not detection (E42, E43).

## 1. E37 — the powered class-asymmetry test (159 calls, ~45 min)

**Why first.** It is the only owed item that can convert a published *estimate* into a *test*, and its
cancellation is already formally superseded.

The original gate computed k=3 at 53.7% power using a correlation figure imported from E31. E42 measured
the correlation on this exact material — two runs' attributions overlapping in 0 of 6 files, against 0.68
expected under independence — and independence is the best-supported model here. Recomputed: **k=3 reaches
94.6% power at 159 calls.**

    ASYMMETRY_OUT=... rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/run_class_asymmetry.py

Run it three times with different output names, then pool. **The estimand changes** and must be labelled:
union-over-k answers "is this class reported in at least one of three readings", which is the
product-relevant question given E43, but it is not the single-reading quantity E39 published. Do not
substitute one for the other silently.

## 2. Widen the propensity measurement (24–72 calls)

E43 now covers 16 files across 3 runs and gives EVER 0.291 vs NEVER 0.021, difference +0.271
[+0.104, +0.437]. The group means are well determined; **individual files are not** — the best file's
interval is [0.320, 0.807].

`run_attribution_propensity.py` takes `PROPENSITY_K` and `PROPENSITY_GROUP`; `pool_propensity.py` globs
every `attribution-propensity-*.json`, so a new run widens the estimate with no code change. The
interesting question was what fraction of the corpus sits at zero. **That is now answered (E45) and this
item is closed: 41 of 53 files were never named across two independent readings (0.774, upper bound), with
the model-corrected zero fraction at roughly 0.60-0.77.** It required no new calls — the two committed
single-reading runs already were a k=2 propensity measurement of the whole slice.

Extended to CWE-307 on the same free data: **52 of 53 (0.981, [0.901, 0.997]) never named**, and at a rate
that low the two-reading bound is effectively the answer.

What remains open here is narrower, and there is one concrete next measurement:

- The per-file intervals for files that DO carry signal are wide (the best is [0.320, 0.807]) — the ceiling
  is established but not located.
- **`realvuln-.../accounts/views.py` is the single file ever named for CWE-307, and it was named in both
  readings (1 of 1) where ownership detections overlapped 0 of 6.** Read that one file at k=9. If it sits
  near 1.0, the rate-limit failure is a *narrow competence* rather than a weak one — a different failure
  mode with different product implications. If it regresses toward the group mean, it was a lucky draw.
  One file, nine calls, and it distinguishes two stories that currently look identical.

## 3. A defect distribution not authored by us

Every matched-pair result in this lab inherits the authoring bias E34 disclosed, and three independent
measurements now show our authored files are **easier than real corpus files** (ownership 4/4 authored vs
0.113 on corpus). The corpus itself is LLM-seeded, which is its own contamination bound. Neither source is
clean, and the honest position is that no current result transfers to private code.

## 4. Not worth doing, and why

- **Re-running E40 with a better prompt.** Four canary readings across two formats never discriminated. The
  failure is that this model does not answer the question asked — it rewrote the file on both canaries in
  both formats. A fifth prompt is not evidence of anything until the conformance problem changes.
- **More authored test files.** See §3: they measure our authoring, and we already know which direction.

## Standing constraints for whoever picks this up

- Score the text that gets **persisted**, not the raw response (protocol §14). The reproducibility guard
  SM19 catches violations, but only after the calls are spent.
- A rate is not a detection (protocol §15). Before describing any rate as detection, run it twice and
  intersect the sets.
- The positive control is read **n times, passing on ≥1** (E44). A single reading blocks about one
  legitimate run in five, and one of the runs behind §2 would have been blocked by the old gate.
- Empty responses are counted and warned: a failed call must never score as a model that declined.
