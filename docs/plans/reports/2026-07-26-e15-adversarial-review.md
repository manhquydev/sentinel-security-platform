# E15 — Independent adversarial review (protocol Stage 8)

**Reviewer:** independent; did not build the instrument.
**Target:** `evaluation/sast-fp-discrimination/run_multiengine_grouped.py` and decision 0022's
"union recall +44% relative at no precision cost", as re-audited by E15.
**Load-bearing use:** `docs/2026-07-26_NguyenManhQuy_Week12.md` pillar 1, going to company leadership.
**Date:** 2026-07-26.

---

## 1. Reproduction — done first, before any critique

Full re-run of `rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/run_multiengine_grouped.py`
(Bandit + Semgrep over all 63 repos):

```
per-repo totals: {'repos': 63, 'real': 1790, 'bandit_tp': 234, 'semgrep_tp': 212, 'union_tp': 336}
totals reproduce the committed baseline exactly — no environment drift
pooled point estimates: bandit recall=0.1307  union recall=0.1877
H1 relative recall gain = +43.6%  95%CI=[+31.5%,+58.4%]      HOLDS
H2 median per-repo absolute recall gain = +0.0357; 22/63 repos gain nothing   HOLDS
H3 precision delta = +0.0051  95%CI=[-0.0136,+0.0173]        HOLDS
```

Every published number reproduced. The regenerated artefact was **byte-identical to the committed
`multiengine-grouped-260726.json` except the `generated_at` timestamp** — all 63 per-repo rows, the
bootstrap CIs, the median and the zero-gain count matched exactly (the working tree was restored
afterwards; `git status` is clean). The abort condition did not fire, and the totals also match the
committed `multiengine-baseline-260725.json` from decision 0022.

`bash tests/sast-measurement-test.sh` → **PASS=8 FAIL=0**, SM7 included.

Independently re-derived from the artefact's own `per_repo` array (seed 7): relative gain 0.4359,
CI [0.3154, 0.5837]; precision delta +0.0051, CI [−0.0136, +0.0173]; median +0.0357; zero-gain 22.
The reported numbers are the arithmetic the code actually performs. **No reproduction defect.**

---

## 2. Verdict up front

**The +43.6% recall gain survives the attack.** It survived every probe I ran, including two that I
expected to break it. It is robust to matching order, to the CWE-wildcard hole in the matcher, to the
choice of denominator, and to switching from the micro to the macro (per-app) estimand.

**The "no measurable precision cost" clause survives, but only as the *pessimistic* reading.** It is
an artefact of two choices that are defensible but unstated: (a) counting duplicate findings twice in
the union denominator, and (b) taking Bandit — the *worse* of the two engines on precision — as the
baseline. Fix (a) and the same instrument flips to its own "precision measurably IMPROVES" branch.
Look at (b) and the union is **−0.176 precision** against the best single engine. Neither breaks the
business case; both need to be said out loud in a stakeholder document.

**One line in the Week-12 document is not supported by E15** and should be corrected before the
document is presented (§4.1).

---

## 3. Attacks that FAILED — E15 is right and I could not break it

These are reported with their numbers because a genuine attack that fails is the evidence that matters.

### 3.1 Matching order does not affect the union TP count — REFUTED

`run_spike.match()` mutates a shared `claimed` set, and the union arm concatenates `bandit + semgrep`,
so order-dependence was the most promising structural attack. The ground truth is dense enough for it
to bite: **1,245 pairs of ground-truth entries sit in the same file within ±10 lines of each other**,
so claim collisions are possible in principle.

I cached every finding from both engines and recomputed the union both ways:

| concatenation order | union TP | relative gain |
|---|---|---|
| `bandit + semgrep` (published) | **336** | +43.59% |
| `semgrep + bandit` (reversed) | **336** | +43.59% |

**Zero repos out of 63 changed their union TP under reversal.** No ground-truth entry is
double-credited (the shared claim set prevents it) and none is unfairly denied. Attack fails.

### 3.2 The CWE wildcard in `match()` is real but immaterial — CONFIRMED-BUT-NEGLIGIBLE

`match()` skips the CWE check entirely when `finding["cwe"] is None`:

```python
if finding["cwe"] is not None and finding["cwe"] not in g["cwes"]:
    continue
```

A finding with no CWE therefore matches **any** ground-truth entry in the same file within ±10 lines —
a wildcard. Semgrep findings lose their CWE whenever rule metadata omits it, so this could have
inflated `semgrep_tp` and `union_tp` asymmetrically. Measured:

- Semgrep findings with `cwe is None`: **3 of 675**. Bandit: **0 of 1764**.
- Dropping all no-CWE findings: `semgrep_tp` 212→211, `union_tp` 336→335, relative gain 0.4359→**0.4316**.

A latent trap worth a comment, but it moves the headline by 0.4 percentage points. Attack fails.

### 3.3 The `real` denominator cannot bias the relative gain — REFUTED ANALYTICALLY

The concern was that `real` counts all vulnerable ground-truth entries including absence-classes no
engine can detect. It cannot bias the headline, because `real` **cancels exactly**:

```
rel_gain = (union_tp/real − bandit_tp/real) / (bandit_tp/real) = union_tp/bandit_tp − 1
```

Confirmed numerically: `336/234 − 1 = 0.4359`, the published figure to four decimals, and the
cancellation holds inside every bootstrap resample too. The denominator affects only the *absolute*
recall levels (0.131 → 0.188) and H2's per-repo gains. So H1 is precisely the statement *"the union
matches 43.6% more ground-truth entries than Bandit alone"* — denominator-free. That is a cleaner
claim than the write-up gives itself credit for, and it should be stated that way. Attack fails.

### 3.4 The bootstrap is a valid cluster bootstrap — REFUTED

Resampling repos with replacement and re-pooling their pre-computed counts is the standard **cluster
(one-stage) bootstrap** for a ratio of pooled sums. It correctly propagates uncertainty in *both*
numerator and denominator, because both are recomputed from the same resampled clusters — this is the
right treatment for a ratio estimator, not a mean. Repo-level heterogeneity (real vulns per repo range
2–80) is exactly what the resampling captures, which is why the interval is appropriately wide.
Mechanics check out: 2000 draws, `random.seed(7)` (reproducible), percentile indices 50 and 1950 for
n=2000, `random.choice` n times = proper with-replacement resampling. Attack fails.

### 3.5 The micro/macro estimand swap does not change the claim — REFUTED

This was my strongest a-priori attack, because it is the lab's own standing rule from the E14 Stage-8
review ("name the estimand and justify it from the deployment"), and `SM4` *pins*
`primary_estimand == "macro-per-repo"` for the E14 artefact. E15 headlines the **micro** (pooled)
estimand and its artefact has no `primary_estimand` field at all. So I computed the macro one —
average the per-repo recalls first, then take the relative gain:

| estimand | relative gain | 95% CI |
|---|---|---|
| micro (pooled — published) | **+43.6%** | [+31.5%, +58.4%] |
| **macro (per-app)** | **+40.7%** | **[+26.7%, +59.2%]** |

They agree in magnitude and both clear the preregistered +10% floor by a wide margin. **Unlike E14,
the two estimands do not disagree here.** Attack fails on the claim; see §5.1 for the rigor gap.

### 3.6 The 22/63 zero-gain caveat is verified, and its mechanism is the honest one

I checked the three very different meanings this could have:

| mechanism | repos |
|---|---|
| Semgrep's true positives were **genuinely redundant** — every GT entry it hit was already claimed by Bandit | **17** |
| Semgrep produced findings but **matched no ground truth** | 3 |
| Semgrep **found nothing at all** | 2 |
| repo has few/no real vulns (would be the misleading case) | **0** |

All 22 have real vulnerabilities (2 to 37, median ~28), so none of the caveat is a denominator
artefact. 17 of 22 are true redundancy — the strongest, most honest form of the caveat: on those
repos the second engine really does find the same things. The log's phrasing ("the union equals Bandit
alone on those") is accurate. **Also verified: no repo has union_tp < bandit_tp**, confirming the
monotonicity the write-up asserts.

---

## 4. Findings that CHANGE or QUALIFY the published claim

### 4.1 CONFIRMED DEFECT — the Week-12 document claims "high recall" that E15 does not support

`docs/2026-07-26_NguyenManhQuy_Week12.md:174`:

> "Sentinel mua **tần suất**: chạy phần presence-class **liên tục**, chi phí ~compute, **giữ recall cao (+44%)**."

"+44%" is a **relative** gain from **0.131 to 0.188**. The union misses **81% of the corpus's real
vulnerabilities**. Even restricted to presence-classes (1790 − 357 absence-class ≈ 1433), union recall
is ≈ 0.234. There is no reading of E15 under which "giữ recall cao" ("keeps recall high") is true; the
sentence converts a relative gain into an absolute-level claim. Every other mention in the document
(lines 28, 36, 40–42, 83) is correctly labelled "tương đối" and correctly carries the 22/63 caveat —
this one line is the exception, and it is in the section explicitly titled *"nói cho đúng, không thổi"*.

**Impact: changes what leadership will believe.** Fix before presenting. Suggested: *"lấp khoảng mù
giữa hai đợt pentest ở mức recall 18.8% tuyệt đối (+43.6% tương đối so với một engine)"*.

### 4.2 CONFIRMED DEFECT — "no precision cost" is denominator-dependent and flips under a fairer denominator

`union_findings = len(bandit) + len(semgrep)` — a straight concatenation. A vulnerability flagged by
**both** engines contributes **2 findings and 1 true positive**, so the second correct detection is
scored as a false positive by construction. That is not what an analyst sees; a triage queue collapses
duplicates. Deduplicating the union on `(file, cwe, line)`:

| union definition | findings | TP | precision | Δ vs Bandit | 95% CI | instrument's own verdict |
|---|---|---|---|---|---|---|
| raw concatenation (**published**) | 2439 | 336 | 0.1378 | **+0.0051** | **[−0.0136, +0.0173]** | "HOLDS — no measurable cost" |
| deduplicated | 2254 | 336 | 0.1491 | **+0.0164** | **[+0.0014, +0.0274]** | "precision measurably **IMPROVES**" |

185 duplicate findings are inflating the denominator, and **no true positives are lost** to dedup
(336 either way). Under the deployment-realistic denominator the precision CI **excludes 0 upward** and
`run_multiengine_grouped.py:138` would print its *other* branch.

**Direction of the error is favourable**: the published choice is the conservative one, so the
business case is understated, not overstated. But the H3 verdict as written is **not robust to a
defensible change of denominator**, and the write-up presents it as if the interval settled the
question. It settled it *for the raw-concatenation denominator only*. That distinction has to be in
the record, because "no measurable precision cost" and "precision measurably improves" are different
sentences to a stakeholder and the instrument can produce either from the same data.

### 4.3 CONFIRMED — "no precision cost" is true only against Bandit, and the document does not say so

Against the *better* single engine the union is a large precision loss:

| comparison | precision | delta |
|---|---|---|
| union vs **Bandit** (0.1327) | 0.1378 | **+0.0051** |
| union vs **Semgrep** (0.3141) | 0.1378 | **−0.1763** |

Semgrep alone is **2.4× more precise** than the union, at recall 0.118 vs 0.188. So the honest
statement is *"adding Semgrep to Bandit costs Bandit nothing"*, not *"multi-engine is free"*. An
operator who deployed Semgrep alone and then added Bandit would measure a severe precision collapse.

Anchoring on Bandit is legitimate — it was 0022's deployed baseline — but Week-12 line 36 reads
"**không đo được tổn thất precision**" with **no baseline named**, and the one-sentence pitch at
line 26–29 says only "miễn phí". A reader will take that as unconditional. Add "so với Bandit đơn lẻ".

---

## 5. Findings that improve rigor without changing the claim

### 5.1 The primary estimand is never declared, contradicting the lab's own standing rule

The E14 Stage-8 review produced rule 1: *"Name the estimand before measuring, and justify it from the
deployment."* `SM4` enforces exactly this on the E14 artefact (`primary_estimand == "macro-per-repo"`,
"micro is published, ties, and is not headlined"). E15 **headlines the micro estimand**, does not
compute the macro one, and its artefact has no `primary_estimand` key. `SM7` does not check for one.

The claim survives (§3.5: macro = +40.7% [+26.7%, +59.2%]), so this is not claim-changing — but E15 got
the right answer without applying the rule that E14 paid for. Publish both estimands, name the primary,
and justify it from the deployment, or the next experiment will inherit the omission and be less lucky.

### 5.2 H2's median is published as a bare point estimate with no interval

H1 and H3 carry bootstrapped CIs; **H2's +0.0357 does not** — the exact structure ("a bare
micro-averaged point estimate ... with no interval") that E15's own preregistration names as the
defect it exists to correct. Computed: median per-repo absolute gain **+0.0357, 95% CI
[+0.0303, +0.0588]**, 0.9% of resamples ≤ 0. H2 holds comfortably. Add the interval; it costs three
lines and closes a hole in the argument's own logic.

### 5.3 The gain is moderately concentrated — worth reporting alongside 22/63

Of the 102 extra true positives the union contributes: **top 5 repos = 33%**, **top 10 (16% of the
corpus) = 51%**. Combined with 22/63 gaining nothing, the portfolio framing in the document is correct,
but "not driven by a small number of outlier repositories" (H1's wording) is a bit generous — half the
benefit comes from a sixth of the corpus. The CI and the 22/63 caveat already carry the honest picture;
this just makes it explicit.

### 5.4 Percentile bootstrap without BCa on a skewed ratio estimator

Percentile CIs on ratio estimators with 63 heterogeneous clusters have approximate coverage; BCa or
studentised intervals would be tighter-justified. Immaterial here — the lower bound (+31.5%) clears the
preregistered +10% threshold by 3×, and the *minimum* across all 2000 resamples is +23.4%. Informational.

---

## 6. Test-quality findings (protocol §10: "Stage 8 must review the tests, not only the result")

### 6.1 CONFIRMED DEFECT — SM7's `lo > 0` assertion is vacuous

```python
sys.exit(0 if (not drift and lo > 0 and plo <= 0 <= phi and zero_gain_published) else 1)
```

`union_tp >= bandit_tp` holds in **every** repo by construction (the union arm matches Bandit's
findings first against an empty claim set, so it reproduces Bandit's TPs exactly, then can only add).
Therefore *every* bootstrap resample yields a positive relative gain, and `lo > 0` **cannot fail**.
Measured: 0 of 2000 resamples ≤ 0; the minimum is +0.234.

The instrument's own docstring says this ("'is the gain positive' cannot come out false and is not a
hypothesis"), and the preregistration correctly chose the non-vacuous threshold **+10%**. The test then
asserts the vacuous version. Every other assertion in `tests/sast-measurement-test.sh` carries a
negative control by design; this clause has none and is precisely the failure mode the file's own
header warns about. **Fix: assert `lo > 0.10`**, matching the preregistered falsification criterion.

The `plo <= 0 <= phi` clause is **not** vacuous — §4.2 shows a real variant of the analysis that
fails it. That half of SM7 is doing work.

### 6.2 CONFIRMED DEFECT — SM7 has no freshness check, so a stale artefact passes

SM4 checks `os.path.getmtime(artefact) < os.path.getmtime(source)` and fails on stale. **SM7 does
not.** SM7 only `json.load`s `multiengine-grouped-260726.json` and asserts on its contents. It never
re-runs the instrument.

Consequences, in ascending severity:
1. An artefact produced by an **older version** of `run_multiengine_grouped.py` passes indefinitely.
2. A **hand-edited** artefact passes as long as the five totals are preserved. Nothing in SM7 ties
   `relative_gain_ci95` to `per_repo`; I verified the CI *is* derivable from `per_repo` (§1), but SM7
   never performs that check. Someone could widen or narrow the interval by hand and SM7 would pass.

**Fix:** add SM4's staleness check to SM7, and add one cheap non-vacuous assertion that recomputes
`relative_recall_gain` from the artefact's own `per_repo` rows (`sum(union_tp)/sum(bandit_tp) − 1`) and
requires it to equal the published value. That is pure arithmetic on committed data — no engine re-run,
milliseconds — and it makes hand-editing detectable.

### 6.3 CONFIRMED DEFECT — the abort condition does not guard the precision claim

`EXPECTED = {"repos", "real", "bandit_tp", "semgrep_tp", "union_tp"}` — **findings counts are absent**,
yet precision is `tp / findings` and H3 rests entirely on findings counts (1764 / 675 / 2439).

A realistic drift slips straight through: a Semgrep ruleset update that adds rules matching **no**
ground truth changes `semgrep_findings` while leaving all TPs identical. The abort prints "totals
reproduce the committed baseline exactly — no environment drift", and the precision delta silently
moves. Because the union denominator is the larger one, added noise findings push the delta *negative*
— i.e. the drift most likely to occur is the one that would falsify H3, and it is the one the abort
condition cannot see.

The recall half of the claim is properly guarded. The precision half is not.
**Fix: add `"bandit_findings": 1764, "semgrep_findings": 675, "union_findings": 2439` to `EXPECTED`.**
The committed baseline already records all three, so this is free.

---

## 7. Ranked actions

**Changes what a stakeholder would believe — fix before the Week-12 presentation:**

1. **§4.1** Correct `docs/2026-07-26_NguyenManhQuy_Week12.md:174` — "+44%" is a relative gain from
   0.131 to 0.188, not "high recall". Absolute recall belongs next to it.
2. **§4.3** Name the baseline wherever "không đo được tổn thất precision" appears (lines 26–29, 36).
   The clause is true against Bandit only; against Semgrep alone the union loses 0.176 precision.
3. **§4.2** Record that H3's verdict is denominator-dependent: deduplicating the union moves the delta
   to +0.0164 [+0.0014, +0.0274] and flips the instrument to "precision measurably IMPROVES". The
   published reading is the conservative one — say so rather than presenting the interval as settled.

**Closes real holes in the guard rails (no number changes):**

4. **§6.3** Add the three findings counts to `EXPECTED`. The abort condition currently cannot see the
   drift most likely to falsify H3.
5. **§6.1** SM7: assert `lo > 0.10`, not `lo > 0`. The current clause cannot fail.
6. **§6.2** SM7: add SM4's staleness check, plus a recompute-from-`per_repo` assertion so a
   hand-edited or stale artefact is detectable.

**Rigor, for the record:**

7. **§5.1** Publish `primary_estimand` and both estimands (macro +40.7% [+26.7%, +59.2%]), per the
   standing rule E14 produced. **§5.2** Attach H2's interval ([+0.0303, +0.0588]).
   **§5.3** Note the concentration (top 10 repos = 51% of the gain). **§3.2** Comment the CWE-`None`
   wildcard in `run_spike.match()` before a future engine with sparser metadata makes it matter.

---

## 8. Unresolved questions

- **Is `union_findings` meant to be a queue or a raw log?** The answer decides §4.2 outright. If the
  product ships a deduplicated triage queue, the dedup denominator is the correct one and H3 should be
  restated as an improvement.
- **Which single engine is the real deployment baseline?** If a client already runs Semgrep, E15 says
  nothing favourable — the union costs them 0.176 precision for 0.070 absolute recall. E15 measures
  "add Semgrep to Bandit"; the reverse direction is unmeasured and is a plausible client situation.
- **Does the 17/22 genuine-redundancy result predict anything?** If Semgrep is redundant wherever
  Bandit already fires, a cheap pre-screen might identify zero-gain repos in advance and turn the
  portfolio-only promise into a per-app one. Unmeasured, and out of E15's scope.

---

Status: DONE_WITH_CONCERNS
Summary: Every E15 number reproduced byte-identically, and the **+43.6% recall gain survives the attack intact** — it is robust to matching order, the CWE-wildcard matcher hole, the denominator, and the micro→macro estimand swap (macro = +40.7% [+26.7%, +59.2%]); the 22/63 caveat is verified and is genuine redundancy, not a denominator artefact. The **"no measurable precision cost" clause survives only as the conservative reading**: it flips to "precision measurably improves" under a deduplicated union denominator, and it holds against Bandit only — against Semgrep alone the union loses 0.176 precision.
Concerns/Blockers: One line in the stakeholder document (`Week12.md:174`, "giữ recall cao (+44%)") states an absolute-level claim E15 does not support and should be fixed before presentation. Three guard-rail defects: the abort condition omits findings counts and so cannot see the drift most likely to falsify H3; SM7's `lo > 0` assertion is structurally vacuous (should be `> 0.10`, the preregistered threshold); SM7 has no freshness check and would pass a stale or hand-edited artefact. No file was modified except this report; the working tree is clean.
