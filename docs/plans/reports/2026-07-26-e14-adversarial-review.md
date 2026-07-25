# E14 — Independent adversarial review (protocol Stage 8)

Reviewer: independent (did not build the instrument). Date: 2026-07-26.
Target: `evaluation/sast-fp-discrimination/rank_grouped.py` and the E14 claim in
`docs/ai-sast-research-log.md` (lines 485-563).

## 1. Reproduction — PASSED

`rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/rank_grouped.py`:

```
reconstruction verified: 1764 rows across 61 repos
leave-one-repo-out AUC:  severity 0.732   cwe_prior 0.826   llm 0.814
PRIMARY: AUC(cwe_prior) - AUC(llm) = +0.012  95%CI=[-0.006,+0.035] -> TIE
EXPLORATORY (row split): +0.069;  leakage gap = +0.057
```

`bash tests/sast-measurement-test.sh` → `PASS=7 FAIL=0`, exit 0.

Every published E14 figure reproduces exactly. Nothing in section 2 disputes the arithmetic;
the attacks are on what the arithmetic *estimates*.

## 2. Findings ranked by whether they change the published conclusion

### F1 — CONFIRMED DEFECT (WOULD CHANGE THE CONCLUSION): the TIE is an artefact of micro-averaging; 98.1% of the ranked pairs are cross-repository

`_auc_by_repo` (rank_grouped.py:89-95) concatenates every repo's LOSO-scored rows and computes **one
pooled AUC**. Of the 358,020 (TP, FP) pairs entering that number, only 6,862 — **1.9%** — are
within-repo. The published ΔAUC is therefore, to 98%, an answer to "can this score rank a true
positive in repo A above a false positive in repo B", not "does this score order a triage queue".

Re-analysing the identical LOSO scores under the per-repo estimand (macro average of per-repo AUC
deltas, same 2000-resample repo bootstrap, seed 1):

| Estimand | ΔAUC | 95% CI | Verdict |
|---|---|---|---|
| Pooled / micro (published) | **+0.012** | [-0.006, +0.035] | TIE |
| Macro (mean of 59 per-repo AUC deltas) | **+0.095** | **[+0.063, +0.128]** | **PRIOR WINS** |
| Within-repo pairs only (pooled) | +0.061 | (not bootstrapped) | prior ahead |

Per-arm within-repo AUC: prior 0.848 vs LLM 0.788. The LLM's parity is bought entirely on
cross-repo pairs; on the ordering a triager actually consumes, the prior is ahead by a margin whose
CI excludes 0 by a wide margin.

Two things make this a defect rather than a taste difference:

1. **The preregistration does not resolve it.** It says only "ΔAUC = AUC(cwe_prior) − AUC(llm),
   evaluated leave-one-repo-out, with a 95% CI bootstrapped over repositories". Pooled-vs-macro is
   an unregistered analytic degree of freedom that flips the headline between TIE and WINS. Under
   the lab's own Stage 2/Stage 5 rules that choice had to be fixed in advance.
2. **The protocol names micro-averaging as the scar being repaired.** `docs/research-protocol.md:99`:
   *"'+44% recall' (0022) and '+0.069 AUC' (0021) were both bare **micro-averaged** point estimates."*
   E14 fixed the split but kept the micro-averaging. It repaired one half of the diagnosed defect
   and inherited the other.

A third, narrower objection to the pooled number: it pools scores produced by **61 different fitted
priors** (one per held-out repo). Within-repo pairs compare scores from a common model; the 98% of
cross-repo pairs compare scores from two different models. That is a known hazard of pooling
cross-validated predictions, and here it is the dominant term.

I am **not** asserting the macro estimand is the correct one — that is a product decision (does the
operator see one global queue across all scanned repos, or one queue per repo?). Per
`.claude/rules/review-audit-self-decision.md` I am putting it back to the author rather than
reversing it. Options:

- **(a)** Keep pooled as primary, but publish the macro/within-repo result in the same breath and
  state that the TIE is specific to a cross-repo ranking task. Minimum acceptable fix.
- **(b)** Switch the primary to macro, with 0021 re-amended: the prior *does* beat the LLM on the
  per-repo triage estimand (+0.095 [+0.063, +0.128]), and E14's "demolished" language withdrawn.
- **(c)** Preregister and run E14b to decide the estimand on deployment grounds before republishing.

Until one of these lands, the sentence *"the withdrawal was right"* (log line 521) and *"the claim
E14 just demolished"* (line 571) are **overstated**: E14 demolished the +0.069, but the qualitative
claim "the prior beats the LLM" survives on the estimand it was arguably always about.

### F2 — CONFIRMED DEFECT (changes a published number, not the headline): "the leakage was worth +0.057" overstates the leak ~3x

`+0.057` is `row_delta − delta` where the two sides differ in **three** ways, not one:
grouping (repo vs row), **training-set size** (row split fits on 882 rows; LOSO fits on ~1,735), and
**evaluation set** (882 rows vs 1,764). Only the first is leakage.

Matched decomposition — 61 folds either way, so train size, fold count and pooled evaluation set are
identical and *only the grouping differs*:

```
grouped (folds = repos)                 delta = +0.0121
row-random folds, same size profile     delta = +0.0314  (sd 0.0041 over 10 seeds)
=> effect attributable PURELY to grouping = +0.019
```

Two further inflations on top of that:

- Holding grouping fixed and shrinking the dev set to 50% raises the grouped delta from +0.012 to
  **+0.039** (mean of 10 seeds, range +0.030..+0.052). More than half of the published gap is a
  training-size/smoothing effect, not leakage.
- `+0.069` is a **single seed** at the high end of its own distribution: over 20 shuffle seeds the
  row-split delta is +0.0585 (sd 0.0094, range +0.037..+0.073). It is quoted with no interval, in a
  log section whose whole thesis is that bare point estimates are how this lab gets burned.

Recommended restatement: *"splitting by row instead of by repository inflates ΔAUC by ≈ +0.019 at
matched training size; the historical +0.069 also benefited from a smaller dev set and a favourable
seed."* SM5's `gap > 0.03` threshold would need re-derivation.

### F3 — CONFIRMED DEFECT (rigor; does not change the conclusion): the bootstrap does not propagate prior-fitting uncertainty

The cluster bootstrap (rank_grouped.py:131-139) resamples repos but reuses **pre-computed** LOSO
scores fitted against the original 61-repo dev set. Resampling therefore perturbs only which rows
are graded, never which rows the prior learned from. This is the reviewer's question 3, and the
answer is: it **understates** the interval.

A fully nested bootstrap (prior refit inside each resample on the sampled repos minus the held one,
400 reps):

```
published : CI = [-0.006, +0.035]
nested    : CI = [-0.015, +0.056]   (~1.7x wider)
```

Direction is safe for E14: the CI still spans 0, so the pooled-estimand TIE survives a correct
bootstrap. But the same shortcut applied to any *positive* claim (E15 is queued with the same
machinery) would manufacture significance. Fix before reuse.

Minor, non-blocking, same block: the percentile CI is not bias-corrected; its bootstrap mean is
+0.0133 against a point estimate of +0.0121 — negligible here. And a repo drawn twice contributes
self-paired rows scoring 0.5 ties; it affects both arms alike.

### F4 — NOT A DEFECT: the row→repo reconstruction is sound (and is stronger than the code proves)

Attacked as instructed; it holds.

- 63 directory entries, 2 of which yield zero Bandit findings (`realvuln-owasp-web-playground`,
  `realvuln-vulnerable-tornado-app`) → 61 non-empty groups. The "~63 repos" in the preregistration
  vs "61" in the result is fully explained.
- All **61 per-repo `(cwe, severity)` sequences are distinct** (61 distinct tuples, 0 duplicates), so
  the "two adjacent repos with identical sequences" failure mode does not exist in this corpus. A
  whole-block permutation cannot satisfy the positional check.
- Independent corroboration the instrument does not perform: replaying `load_gt`/`match` per repo
  reproduces `is_vulnerable` **1764/1764**. Labels are repo-specific (ground truth is loaded per
  slug, claim-once), so agreement on all 1,764 labels is far stronger evidence of correct alignment
  than the `(cwe, severity)` check alone.

Residual, low: 12 of 60 adjacent repo boundaries have `last(A) == first(B)`, so a one-row boundary
shift would pass the `(cwe, severity)` check undetected. Boundaries are derived from the same replay,
so this is only exposed to corpus drift, and a one-row misassignment cannot move a LOSO result.
**Recommendation (cheap, strictly stronger):** extend the abort condition in `reconstruct_groups` to
compare `is_vulnerable` as well as `(cwe, severity)`.

### F5 — NOT A DEFECT: leave-one-repo-out is implemented correctly

`loso_scores` / `main` (lines 72-86, 117-123) build `dev` as strictly `g != held_repo` and fit the
prior only on it; `score_rows` for `cwe_prior` reads only `prior`/`base`, both derived from `dev`,
and touches the held row's label solely to emit the ground-truth flag for AUC. No held-out label can
reach a score. SM1-neg exercises exactly this channel and its numbers are real (held 0.100 vs leaky
0.917). The LLM arm cannot leak by construction: `run_annotate.py:67` memoizes the annotation on
`(rule_id, cwe, severity)`, so it is a fixed lookup independent of the split.

### F6 — NOT A DEFECT: the inherited imports carry no inherited bug

`rank_grouped` imports `auc`, `fit_cwe_prior`, `score_rows` from the module it corrects. Reading
`rank_baselines.py`, the defect lived exclusively in `main()`'s row-level `random.shuffle`
(lines 69-73); the three imported functions are split-agnostic and take the split as input. Executing
`rank_baselines` as a module has no side effects. The independence claim holds. (Cosmetic: `main`
refits the prior 61x3 times because the loop is keyed on arm, though only `cwe_prior` depends on it.)

### F7 — CONFIRMED DEFECT (test quality): SM4 is tautological and SM4/SM5/SM6 can pass vacuously

The suite's own header claims "Every assertion carries a negative control so it cannot pass
vacuously". Three of six do not meet that bar.

- **SM4 is a tautology.** It loads `rank-grouped-260726.json`, recomputes `spans_zero = lo <= 0 <= hi`
  from `ci95`, and asserts `spans_zero and verdict == "tie"`. But `verdict` is *written* by
  rank_grouped.py:159 as exactly `"tie" if (lo <= 0 <= hi)`. The test re-derives a field from the
  field it was derived from, in the same file. It cannot fail on any artefact this instrument
  produces; it only detects hand-editing. It constrains no measurement.
- **SM4 and SM5 read a committed artefact and never regenerate it.** Nothing checks freshness,
  corpus hash, tool versions, or agreement with a live run. A stale or hand-written JSON with the
  right five keys passes both. SM5 additionally compares two numbers *from the same file*, so it
  verifies the file's internal consistency, not that the leakage exists.
- **SM6's win-guard is satisfiable by an unrelated docstring.** The regex is
  `"prior WINS" in src and not re.search(r"lo\s*<=\s*0\s*<=\s*hi|ties", src)`, applied file-wide.
  The token `ties` appears in `rank_baselines.py:30` (`"...ties 0.5"`) and in run_annotate.py's
  docstring. Any file with the word "ties" anywhere in it is exempted from the guard regardless of
  how its verdict is actually computed.
- **SM2 only tests the wrong-length branch.** The interesting failure is an equal-length,
  misaligned replay; that branch (lines 65-68) is never exercised.
- **SM1 asserts only `len(scored) == len(rows)`** — a count, not the "exactly once, by a foreign
  prior" property its label claims. SM1-neg is the only assertion in the file that genuinely
  constrains behaviour, and it is a good one.
- Nothing pins the published +0.012 / [-0.006,+0.035] against a recomputation, and nothing tests
  that `reconstruct_groups` returns the *correct* groups (only that it rejects a bad length).

Suggested minimum: make SM4 recompute the delta and CI from the baseline JSON + corpus and assert
agreement with the artefact; assert `n_rows == 1764` and `n_repos == 61`; add an equal-length
misalignment case to SM2; scope SM6's guard to the verdict expression rather than the whole file.

### F8 — PLAUSIBLE CONCERN (documentation): the exploratory row-split subtraction is otherwise apples-to-apples

Checked as instructed (question 5). `rank_grouped.main` re-derives the row split with the same
`random.seed(0)` and the same `random.shuffle` on the same row list, so it reproduces
`rank_baselines`' split exactly, and the two report the same +0.069 (the point estimate and the
bootstrap mean coincide to 3 dp). Same data, same seed. The subtraction's problem is the confound in
F2, not a seed or data mismatch.

## 3. Verdict

**The published pooled-estimand numbers are correct and reproducible, and the "+0.069, prior WINS"
retraction is justified — but the headline "TIE" does not survive the attack unqualified.** It is
specific to a micro-averaged, 98%-cross-repository estimand that the preregistration never fixed and
that the lab's own protocol names as the scar it was repairing. On the per-repo estimand the same
LOSO scores give +0.095 [+0.063, +0.128] — the prior wins, significantly. E14 must either justify
its estimand or publish both.

Secondary claim "**the leakage was worth +0.057 AUC**" is **overstated by roughly 3x**; the
grouping-only effect at matched training size is +0.019.

Recommended actions, in order:

1. Resolve F1 — choose option (a), (b) or (c) and amend log lines 521-537 and 571 accordingly.
   Blocking for publication.
2. Restate the leakage magnitude per F2 and re-derive SM5's threshold. Blocking for the "+0.057"
   sentence.
3. Fix the bootstrap to refit inside each resample (F3) before E15 reuses the machinery.
   Non-blocking for E14's tie; blocking for any positive claim.
4. Strengthen SM4 (de-tautologise), SM2, SM6 (F7).
5. Add `is_vulnerable` to the reconstruction's abort condition (F4).

## 4. Unresolved questions

1. **Estimand**: does an operator triage one global queue across all scanned repositories, or one
   queue per repository? This single product fact decides TIE vs WINS. E14 cannot be published
   without answering it.
2. Should the pooled AUC even be computed across scores produced by 61 distinct fitted priors, or
   should cross-repo pairs be excluded on comparability grounds?
3. Was the pooled estimand chosen deliberately or inherited from `rank_baselines`' single-split
   `auc()` call? The log records no deliberation.

Files reviewed: `/home/manhquy/Downloads/vinsoc/evaluation/sast-fp-discrimination/rank_grouped.py`,
`rank_baselines.py`, `run_annotate.py`, `run_spike.py`, `annotate-baseline-260725.json`,
`/home/manhquy/Downloads/vinsoc/tests/sast-measurement-test.sh`,
`/home/manhquy/Downloads/vinsoc/docs/ai-sast-research-log.md`,
`/home/manhquy/Downloads/vinsoc/docs/research-protocol.md`.
No repository file was modified.
