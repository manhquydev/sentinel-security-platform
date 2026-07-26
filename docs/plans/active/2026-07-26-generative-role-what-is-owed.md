# The generative-role line of work: what is settled, and what is left

Status: active. Rewritten 2026-07-26 15:00 after E37 and E44–E48. The earlier version listed three owed
items; two closed the same afternoon, and one of those needed no model calls at all. This is the current
state, not the morning's.

## What is settled

**The capability is real, bounded, and every coverage number is budget-dependent.**

| | measured |
|---|---|
| Specificity | **2 flags in 328 clean-control observations = 0.61%**, 95% CI [0.17%, 2.2%] (E52). Two different causes; the second may be a **corpus labelling gap, not a model error**. |
| Sensitivity, single reading | ~0.20 on files carrying a real absent control |
| Per-file structure | a **mixture**: 8 of 24 at zero, a long thin tail, **nothing at 1.0** |
| Reliable core | **none.** 2 files at k=4, 1 at k=6 and k=9, **0 from k=12 on**. Best file 14/15 = 0.933 |
| Union coverage at k=15 | **17/24 = 0.708**; last increase at k=9, flat for 6 readings since (not a plateau claim — §18) |
| Never surfaced | **7/24 = 0.292** [0.149, 0.492] at k=15 — after 0.583 (k=6), 0.458 (k=9), 0.333 (k=12) |
| Class asymmetry | ownership/authn ≫ CWE-307, **p = 0.0327** (E37), realized power 61% |
| CWE-307 | **50 of 53 files never named across five readings**; not recovered by targeted prompting (E40) or by removing competing defects (E41) |

**Two questions that must not be conflated:**

- *"Is a control absent somewhere in this file?"* — coarse; best file ~0.92, no certainties.
- *"Which control is absent?"* — fine; **no** reliable core at all: 0 of 53 across five readings.

**The single most important methodological fact, learned three times the hard way:** every coverage and
never-surfaced figure is **a function of the reading budget, not a property of the corpus**. Each deepening
(k=6 → 9 → 12) lowered "never surfaced" and dissolved another "always detected" file. No published version
of either number was ever anything but a bound. **Nothing here may be quoted without its k.**

Honest product statement: a **low-noise sampler**. At twelve readings it surfaces two files in three, misses
one in three, has no individual file it can be trusted on, and essentially never fires on clean code.

## An unplanned finding worth more than the planned ones

The deterministic **shadow detectors** built to test the corpus (E53–E54) are themselves a capability.
Five absent-control conditions — unbounded `limit` (CWE-770), `DEBUG=True`, CORS wildcard, disabled cookie
flags, wildcard `ALLOWED_HOSTS` — each with a self-test proving it fires on the defect and not on the
repair. They found **10 real unlabelled defects** across the corpus at zero marginal cost, deterministically,
with no model, no non-determinism, no k, and no false-positive rate to argue about.

That is worth stating plainly next to everything else measured today: **the cheapest real security value
produced in this whole line of work came from ~40 lines of regex, not from the model.** It does not
generalise the way an LLM does — each detector covers one condition and had to be written by hand — but
what it covers, it covers exactly, repeatably and for free. Any honest product story should lead with the
deterministic layer and position the model as the thing that covers what no rule can express.

## What is left
## What is left

### 1. A defect distribution not authored by us

Still open, still the largest threat to external validity. Every matched-pair result inherits the authoring
bias E34 disclosed, and three independent measurements show our authored files are easier than corpus files
(ownership 4/4 authored vs ~0.19 on corpus). The corpus is itself LLM-seeded. **Neither source is clean and
no current result transfers to private code.** A data-sourcing problem, not an experiment — running things
cannot close it.

### 2. ~~Where the ceiling sits on other code~~ — DONE 2026-07-26 (E49)

A disjoint sample (zero overlap, verified) gave a ceiling of **0.375** against the original **0.417**, with
the same decay signature, while being slightly *easier* per reading. **The ceiling is a property of the
method, not of the first file set.** Artefacts `generative-disjoint{7,8,9}-260726.json`.

### 3. ~~Adjudicate the second specificity breach~~ — DONE (E53/E54)

It **is** a corpus gap: an unbounded `limit` is a real CWE-770 and ground truth labels that class zero
times. But the follow-up test showed the gap does **not** give meaningful headroom — confirmed-but-
unlabelled defects are flagged 2/9 against 2/30 for clean controls (p = 0.22), and `audit.py` itself did
not reproduce at 0/3. Measured precision is a floor; the space above it is not demonstrated to be large.

### 3b. The classifier's presence-class suppressor only looks inside one window

The third clean-arm breach is `aes-encrypt.py`: the model wrote *"No auth. CFB malleable → use AES-GCM"*,
meaning **unauthenticated encryption**. The classifier read it as a missing authentication control. The
presence-class suppressor (`aes|cbc|gcm|cipher|...`) exists precisely for this and did not fire, because
the crypto words sit in the *adjacent* sentence while the suppressor only inspects the matching window.

Fix is a window widening, but it must be validated both ways before adoption — it will remove some genuine
detections too. **Zero model calls to measure.**

### 4. Do test files belong in either arm?

The clean-control arm is defined as "files with no ground-truth entries", which makes it **14% test files**
(8 of 56) while the positive arm has none (0 of 84). A test file has no production controls, so *"is a
required control absent here?"* is ill-posed for it — and the single specificity breach measured so far
came from exactly that subpopulation.

Neither candidate repair works: the prose-level rule removes 2 genuine positive-arm detections and misses
the false positive; the path-level rule removes only the one embarrassing observation, which is a
retraction rather than a fix. **The decision is about the sampling frame, not the classifier.**

**Downgraded in priority — both estimands are now published and they agree.** All clean files: 1/184
[0.0010, 0.0301]. Excluding test files: 0/152 [0.0000, 0.0247]. The intervals overlap almost entirely, so
whichever frame is chosen the claim is "below about 3%", and no conclusion in 0027 turns on it. Still worth
settling for cleanliness — 17% of the clean arm being test files is a design defect — but it is not
blocking anything.

### 4. Where the union curve actually plateaus (open, and the most expensive question here)

Answered partially and revised twice. At k=12 the union is 0.667 and **still climbing**; 8 files remain at
zero. The phrase "unreachable" has been retired — three files so labelled at k=6 fired by k=12.

What is still unknown is where this stops, and it matters because **the commercial number is whatever
coverage the budget buys**. Extending sample A to k=20 is ~320 calls and would either locate a plateau or
push the bound down again. Note the curve goes flat for stretches (k=8–11) and then moves, so **a plateau
may only be claimed from many readings past the last increase**, never from a flat stretch.

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
