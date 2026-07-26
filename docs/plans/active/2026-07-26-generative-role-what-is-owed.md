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
| Reliable core | **none.** 2 files at k=4, 1 at k=6 and k=9, **0 from k=12 through k=18**. Best file 17/18 = 0.944 |
| Union coverage at k=18 | **16/24 = 0.667**; last increase at k=9, **nine flat readings since**; the 8 remaining files are jointly ruled out above ~3% propensity (E57) |
| Never surfaced | **8/24 = 0.333** [0.180, 0.533] at k=18 — after 0.583 (k=6), 0.458 (k=9), 0.333 (k=12) |
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

### 1. A defect distribution not authored by us — the one threat no experiment closes

**What it specifically invalidates.** Not "the results" — these claims, this much:

- **Positive claims do not transfer.** Detection rates, the k=1 rule increment, coverage curves: all
  measured on LLM-seeded defects plus self-authored matched pairs that three measurements show are easier
  than corpus files. Nothing here licenses a number on private, human-written code.
- **Negative claims are far more robust.** CWE-307 being near-invisible, no file reaching reliability, the
  union bounded around two thirds — a defect the model misses on easy seeded code will not appear on harder
  real code. These survive the threat; the selling points do not.
- **Label incompleteness is separate and also real.** CWE-770 is labelled zero times despite ten endpoints
  having it, so precision against these labels is a floor (E53), though E54 showed the headroom is small.

**Named next action, which is not an experiment.** Source an organic, externally-labelled corpus carrying
absence-of-control classes. That was researched rather than guessed — full report with 30+ primary sources
at `plans/reports/researcher-260726-1846-external-vulnerability-corpus-sourcing-report.md`. The two
findings that change the decision:

- **The gap is field-wide, not ours.** Across the datasets that dominate this literature — Juliet/SARD,
  Big-Vul, CVEFixes, DiverseVul, Devign, OWASP Benchmark — memory-safety and injection classes make up
  60–80% of content and **absence-of-control (CWE-306/862) is under 5%**. There is no established
  benchmark for missing-authz/missing-authn. This lab is not behind the field here; the field has not
  built the yardstick either.
- **Label quality is the binding constraint, not volume.** Prior datasets are reported at **20–71% label
  inaccuracy**, so simply acquiring a bigger corpus imports someone else's labelling problem. Any option
  must budget for validation with a stated inter-rater agreement, not just for acquisition.

Costed options, ranked (figures are the researcher's estimates, not quotes):

| option | cost / time | gives us | does NOT solve |
|---|---|---|---|
| **1. NVD-mined CVEs + expert labelling** (recommended) | ~$30–50k, 2–3 months, Cohen's κ > 0.85 target | organic real CVEs, per-file absence-class labels, replicable published pipeline | labeller bias on boundary cases (rate-limit vs access-control), skew toward novel cases |
| **2. Bug-bounty disclosures** (HackerOne/Bugcrowd) | ~$5–10k, 4–6 weeks | ~100–300 confirmed IDOR/access-control bugs, real attacker patterns, cheap | web/API only; disclosure bias toward what bounty hunters look for |
| **3. Hand-built benchmark** | ~$15–25k | full control of class coverage | **repeats exactly the self-authorship bias this lab already measured** (authored files 4/4 vs ~0.19 on corpus) — the researcher flagged this independently |

Option 3 should be rejected on evidence this project already owns. Option 2 is the cheap first move and
its bias is nameable; Option 1 is what a publishable claim would require.

**Who owns it.** Corpus acquisition is a project-level decision (licensing, budget, possibly a data
partnership) and sits above a research session. This file records the requirement and the options; the
choice is not one this lab makes alone.

**If it is never closed.** The work still stands as a negative result and as a methodology: the protocol,
the guards, and every retraction in the log are corpus-independent. What must never be published without
this closed is any positive per-file number presented as applying to a customer's code.

### 2. ~~Where the ceiling sits on other code~~ — DONE 2026-07-26 (E49)

A disjoint sample (zero overlap, verified) gave a ceiling of **0.375** against the original **0.417**, with
the same decay signature, while being slightly *easier* per reading. **The ceiling is a property of the
method, not of the first file set.** Artefacts `generative-disjoint{7,8,9}-260726.json`.

### 3. ~~Adjudicate the second specificity breach~~ — DONE (E53/E54)

It **is** a corpus gap: an unbounded `limit` is a real CWE-770 and ground truth labels that class zero
times. But the follow-up test showed the gap does **not** give meaningful headroom — confirmed-but-
unlabelled defects are flagged 2/9 against 2/30 for clean controls (p = 0.22), and `audit.py` itself did
not reproduce at 0/3. Measured precision is a floor; the space above it is not demonstrated to be large.

### 3b. ~~The presence-class suppressor only looks inside one window~~ — MEASURED AND REJECTED (E55)

The third clean-arm breach is `aes-encrypt.py`: the model wrote *"No auth. CFB malleable → use AES-GCM"*,
meaning **unauthenticated encryption**. The classifier read it as a missing authentication control. The
presence-class suppressor (`aes|cbc|gcm|cipher|...`) exists precisely for this and did not fire, because
the crypto words sit in the *adjacent* sentence while the suppressor only inspects the matching window.

Measured: widening the context to one sentence either side fixes the false positive and **costs 9 genuine
detections to remove 1**. Rejected. The false positive is kept as a named cost, and the clean-arm rate it
feeds (0.96%) is small enough that buying it down at 9:1 is the wrong purchase.

### 5. ~~Do test files belong in either arm?~~ — CLOSED, not load-bearing (E49)

Left open longer than it deserved. Both estimands were already published and they agree: all clean files
**1/184 [0.0010, 0.0301]**, excluding test files **0/152 [0.0000, 0.0247]**. The intervals overlap almost
entirely, so **no conclusion in 0027 turns on which frame is adopted** — the claim is "below about 3%"
either way, and neither frame supports a claim of zero.

The residual is a corpus-construction note, not a blocker: **14% of the clean-control arm is test files**
(8 of 56) because the arms are defined by ground-truth presence and ground truth records production
defects only. A test file has no production controls, so *"is a required control absent here?"* is close
to ill-posed for it. Worth fixing in any future corpus; it changes no published number.

### 4. ~~Where the union curve actually plateaus~~ — ANSWERED as a bound (E57)

At **k=18** the union is 0.667 with the last increase at k=9 — nine flat readings since. Not claimed as a
ceiling (§18), but the flat stretch bounds what remains: if the 8 never-surfaced files shared a propensity
`p`, observing nothing from any of them across 18 readings has probability 0.0124 at p=0.03 and 0.0006 at
p=0.05. **They are jointly ruled out above ~3% and compatible with ~1%.**

Practical consequence: **no realistic reading budget will surface that last third.** Falsifiable — one new
file at k=25 would break it. Cost of knowing: ~720 model calls across 18 readings.

(This section was accidentally deleted while closing item 5 and is restored here with its answer.)

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
