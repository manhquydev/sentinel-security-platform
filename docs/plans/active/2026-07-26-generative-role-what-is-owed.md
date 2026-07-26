# The generative-role line of work: what is settled, and what is left

Status: active. Rewritten 2026-07-26 15:00 after E37 and E44–E48. The earlier version listed three owed
items; two closed the same afternoon, and one of those needed no model calls at all. This is the current
state, not the morning's.

## What is settled

**The capability is real, bounded, and has a shape a sensitivity figure alone hides.**

| | measured |
|---|---|
| Specificity | **0 flags in 96 clean-control observations**, and zero in every run this project has done. Pinned by SM23 across all committed artefacts. |
| Sensitivity, single reading | ~0.19 on files carrying a real absent control |
| Per-file structure | a **mixture**: 14 of 24 at propensity zero, a tail reaching 1.0 |
| Reliable core | **1 file of 24 flagged in all six readings, 1 more at 5 of 6** |
| Union coverage | saturates at **10 of 24 = 0.417 by k=6**; further readings add cost only |
| Union vs independence | 100%, 81%, 71%, 65%, 61%, 58% at k = 1…6 |
| Class asymmetry | ownership/authn ≫ CWE-307, **p = 0.0327** (E37), realized power 61% |
| CWE-307 | **50 of 53 files never named across five readings**; not recovered by targeted prompting (E40) or by removing competing defects (E41) |

**The two questions that were being conflated, and must not be again:**

- *"Is a control absent somewhere in this file?"* — coarse, has a small reliable core.
- *"Which control is absent?"* — fine, has **no** reliable core: 0 of 53 files across five readings.

Honest product statement: a **low-noise sampler** that surfaces about 40% of defective files when read six
times, never fires on clean code, and cannot reliably say what is wrong. Not a scanner.

## What is left

### 1. A defect distribution not authored by us

Still open, still the largest threat to external validity. Every matched-pair result inherits the authoring
bias E34 disclosed, and three independent measurements show our authored files are easier than corpus files
(ownership 4/4 authored vs ~0.19 on corpus). The corpus is itself LLM-seeded. **Neither source is clean and
no current result transfers to private code.** A data-sourcing problem, not an experiment — running things
cannot close it.

### 2. Where the ceiling sits on other code

Saturation at 0.417 is saturation *of these 24 files*; nothing measured predicts the ceiling elsewhere.
Cheap version: run the k=6 protocol on a second disjoint file set and compare saturation points. ~240 calls.

### 3. Do test files belong in either arm? (blocks every specificity number)

The clean-control arm is defined as "files with no ground-truth entries", which makes it **14% test files**
(8 of 56) while the positive arm has none (0 of 84). A test file has no production controls, so *"is a
required control absent here?"* is ill-posed for it — and the single specificity breach measured so far
came from exactly that subpopulation.

Neither candidate repair works: the prose-level rule removes 2 genuine positive-arm detections and misses
the false positive; the path-level rule removes only the one embarrassing observation, which is a
retraction rather than a fix. **The decision is about the sampling frame, not the classifier**, and it
changes every specificity figure this project has published — so it must be made deliberately. Cost: no
model calls, only a decision and a re-derivation.

### 4. Whether the 14 zero-propensity files are truly unreachable

A file observed at 0 of 6 carries the interval [0.000, 0.390], so some may have small non-zero
propensities. Separating "unreachable" from "very rare" needs large k on those files: 14 × 20 ≈ 280 calls.
Worth doing, because the ceiling is the number the commercial case rests on.

## Not worth doing, and why

- **Re-running E40 with a better prompt.** Four canary readings across two formats never discriminated a
  present control from an absent one; the model rewrote the file instead of answering. A fifth prompt is
  not evidence until output conformance changes.
- **More authored test files.** See item 1 — they measure our authoring, and the direction is known.
- **More readings of the current 24-file set.** The union saturated at k=6; further readings are pure cost.

## Standing constraints

- **Score the text you persist, not the raw response** (protocol §14). Violated in `run_generative` for six
  hours *after* the rule was written; SM19 caught it and every affected figure moved down. Assume other
  runners carry the same bug until checked.
- **A rate is not a detection** (protocol §15). Run it twice and intersect before calling anything detection.
- **Ask the committed data first** (protocol §16). Two questions filed as needing runs were already on disk.
- The positive control is read **n times, passing on ≥1** (E44). Single-read gates block ~1 legitimate run
  in 5; three runs this afternoon had tallies of 1/3, 2/3 and 1/3 and would have been blocked.
- Empty responses are counted and warned — a failed call must never score as a model that declined.
