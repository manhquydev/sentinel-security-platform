# Next-direction synthesis: what to run, what to close, and the ninth correction

Date: 2026-07-26. Read-only synthesis over E1–E68, the protocol, decisions 0023/0027 and the active plan.
Numbers are cited to an E-number or re-derived here from the committed corpus and artefacts.

---

## 0. P0 — a ninth correction, found while checking the ledger. Do this before any new experiment.

**The free layer's three headline numbers are wrong by ~2x, in the flattering direction, and the lab
already owns the corrected figures without having reconciled them.**

`detect_absent_auth.py` emits **two findings per site** (`for cwe in (306, 862)`) and scores them against a
denominator of `real_306 + real_862`. Verified against the corpus on disk (63 repos):

- **48 ground-truth entries carry BOTH 306 and 862.** Distinct entries = **289**; the published denominator
  is **337**. Those 48 are counted twice. (Re-derived via `run_spike.load_gt` over all repos.)
- `run_spike.match` claims by ground-truth **index**, so the duplicate emission can never match the same
  entry twice — it is booked as an unmatched finding, i.e. **a false positive by construction**.
- Arithmetic tell: E61's `1130 findings` is exactly **2 × 565**, and E60/E64's own
  `rank-absent-auth-260726.json` records `sites = 565`, `real_defects = 70`, **`site_precision = 0.1239`**.

| figure | published (E56/E61, 0023 amendment, plan doc) | re-derived |
|---|---|---|
| recall, CWE-306+862 | 76/337 = **0.226** | 76/289 = **0.263**, or 70/289 = **0.242** site-level |
| precision | 76/1130 = **6.7%** | 70/565 = **12.4%** |
| the product sentence | "**1,130** route handlers with no visible access control" | **565** |
| route ceiling (E67) | 132/289 = **0.457** | on the *published* denominator, 132/337 = **0.392** |

1. **E67's own table mixes the two denominators.** It prints `76/289 = 0.263` labelled *"corpus, published
   denominator (all labelled entries)"* — the published figure is 0.226 on 337. The 0.457 ceiling and the
   0.226 headline are computed on different populations, one row apart. That is the §22 / E62 error class:
   a denominator no reader can reconstruct, quoted as canonical.
2. **The precision repairs were aimed at a number that was half real.** E55 rejected a 9:1 trade, E61 bought
   +0.33pp, E60 found ordering inverted — and a one-line accounting fix moves precision 6.7% → 12.4%,
   more than every measured repair combined. §10.2 applies to *where you look*, not only to what you fix.
3. **It breaks the ledger's proudest line.** "Every quantified correction moved against this lab's own
   headline" is now false. It survived 13 experiments because the lab's scepticism is asymmetric: §12.3
   warned about the mirror case, and an error making the work look *worse* faced no scrutiny at all.

Cost: hours. Fix the denominator, dedupe emission or scoring, re-run, then §4-grep `0.226`, `6.7%`, `6.4%`,
`1130`, `337` across `docs/`. Nothing else here is worth doing first.

## 1. Highest-value next direction: **organic PRECISION via a free negative oracle**

**The one number the product needs that nobody has measured.** Every organic result (E66, E67, E68) is
**recall on files already known to contain a defect**. Nothing measures what the detector does to a
production repository it has no reason to fire on. The product is an inventory, an inventory's cost is its
size, and its size on real code is unknown.

**Why the corpus figure cannot stand in.** E65/§22 established that effort-at-recall is a joint property of
method and defect concentration. Precision is the same kind of quantity, and the lab has not applied its own
rule to it. This corpus has **38% of files defective** (E65); production code does not. E66 shows the
direction of the danger: one organic file produced **98 findings**.

**Design, and why it is free.** E66's insight was *the fix commit is the positive label*. The symmetric move
has not been made: **a route with no control before the advisory fix that still has none at HEAD — in a repo
since put through a security fix for this exact class — is a presumptive negative.** The maintainer had the
class, the context and years of opportunity, and left it public.

Unit of analysis: **repository** (Stage 5/7), ≥15 repos, 8 already in hand from E68. Preregistered
primary outcome: **items per repository** and **lower-bound precision** = maintainer-fixed sites ÷ all sites
reported on the pre-fix tree. It is a *lower* bound by construction — a still-unprotected route may be a live
undiscovered defect, so mislabelling only pushes precision down, the direction this lab prefers (§14).
Preregistered falsification check: hand-read 20 presumed negatives; if many look like real defects the oracle
is void. Zero model calls; data already cached by `probe_organic_absence_corpus.py`.

**What it decides.** Organic precision near 1–3% kills the inventory as a shipped product regardless of
recall. At 20–40% — plausible, since production repos protect most routes and the detector fires only where
no marker exists — the product is *stronger* than the benchmark suggests and the headline stops being a
recall claim. Genuinely uncertain both ways, which is the point.

**What would make it worthless:** fewer than ~12 repos with a resolvable HEAD counterpart; the 20-file check
finding the presumed negatives are mostly real defects; or reporting a per-site binomial instead of a
repo-clustered interval — E68's mistake repeated (§4.5).

### Alternatives rejected

**A — extend the detector to the ~54% off-route population (E67's named lead).** The prize is mis-measured:
the 45.7% ceiling is 132/**289** while the headline recall is on **337** (§0), so its size is unstable until
P0 lands. And E56 showed recall is cheap while precision does not yield; adding recall to an inventory adds
*decisions*, whose cost E64 left unmeasured. **Value conditional on the recommended experiment** — sequence
it after, not against.

**B — widen the organic corpus to more ecosystems for repo-level n.** E68 just proved this pipeline
manufactures flattering selection effects, and E66 states a *second, unfixed* one: only fixes written in a
vocabulary `detect_absent_auth` already knows are counted — selection on a variable plausibly correlated with
the outcome, the same family E68 fixed for route shape (§10.2 again). Growing n through an uncorrected filter
multiplies bias. Cheap correct move first: sample fixes whose added marker is *not* in the vocabulary.

**C — any further model readings, prompts, or generative-role experiments.** See §2.1.

## 2. CLOSE these

1. **The LLM layer in the shipped product.** Not because it adds nothing — E62 measures +0.103 [0.042,
   0.125] on positive-arm files and +0.157 [0.062, 0.200] on eligible files at k=1, at the independence
   expectation, so the capability is real. Close it because **its output is not reproducible and the chosen
   product is an attestation artefact.** E42: two runs name six files each, overlapping in **zero**. E43: no
   file above 0.667 propensity. E51/E57: **0 of 24 files flagged in every reading at k=12 and k=18**. E63:
   the union needs **k=9**, and readings 10–18 burn **51% of the budget for nothing**. You cannot sign a
   compliance inventory whose items change between runs. Keep the generative role as a published research
   result (0027 stands) and at most an interactive second opinion — never part of the artefact, the coverage
   claim or the price. **At the only budget with a defensible cost story the model buys about a sixth of a
   file per file, on a set that will not reproduce.**
2. **Prioritisation, ranking, reviewer-in-the-loop learning.** E60 (worse than chance, p = 0.9975; line
   number beats the designed ranker 6.5×), E64 (no per-finding prioritisation), E65 (oracle 30.4% vs density
   37.0% — **6.5 points of headroom**). E65's "may still be live on production code" keeps a dead item alive
   with no path. **Gate it:** do not reopen until a file-level organic corpus of ≥30 repos exists, and then
   only if measured defect concentration is below ~10%.
3. **Precision repairs by markers, heuristics or filtering.** E56 (no recurring public-route shape), E61
   (+0.33pp), E55 (9:1 trade rejected), 0018/0020/DD1 (filter is the falsified gate role). P0 supersedes them.
4. **More readings of the 24- and 53-file sets.** E57 (nine flat readings), E46 (union at 58–70% of the
   independence projection). Already "not worth doing"; make it closed.
5. **Per-class prompting for CWE-307.** E40 abandoned at the canary twice; E41 found no recovery (1/16 vs
   1/53, p = 0.41) on all the corpus holds. Not open — unanswerable with this instrument. Record it so.
6. **"$30–50k corpus purchase" as the route to a first organic check.** E66/E68 demonstrate a free path;
   keep the paid options only against a *publication* decision.

## 3. Is the product right? The strongest argument against

Stated product: *deterministic inventory of route handlers with no visible access control, plus an LLM layer
that finds what rules cannot express.* The first half is right; the second should be cut (§2.1). The
strongest argument against is not the one the log defends against:

> **Every number that makes the inventory look viable is a benchmark artefact of defect concentration, and
> the product's real cost has never been measured on code that is mostly correct.**

Precision of 12.4% (corrected) is measured where **38% of files carry a defect** (E65). E65/§22 already voided
a cross-corpus comparison on exactly this logic. On production code, absence defects are rare while route
handlers are not, so the same instrument plausibly returns similar volume with an order of magnitude fewer
defects inside it. E66's single organic file returning **98 findings** is the only datum available and it
points the wrong way.

- **The unit of value is a decision, and decisions are what a customer pays in.** E64 measured 92 decisions
  across 32 repos; per-decision cost is unmeasured and E64 found **no published source** for it. The 60–80%
  "not applicable" closure rates it cites come from CSPM/SBOM tools whose items carry machine-checkable
  context; a route handler's intent does not live in the file.
- **The failure mode is silent.** A too-large inventory does not error — it gets ignored while the coverage
  claim stays technically true. That is the shape of the HARMLESS abandonment narrative E64 could not verify:
  unverified, and still the right thing to fear.
- **Simplest viable option:** ship the free layer alone — 60 lines, no model, no k, no network — as a
  route-handler access-control inventory scoped to route-level absence (0.576 on the population it targets,
  E67). Least complexity that still meets the requirement, and P0 makes it look better.

## 4. Where this lab is fooling itself

1. **The double-counted denominator and doubled findings (§0).** 337 vs 289; 1130 = 2 × 565; and
   `site_precision = 0.1239` sat in a committed artefact unreconciled with the 6.7% quoted everywhere.
2. **E59's contamination arms are mapped to the wrong variable.** The `human_authored` half is
   `damn-vulnerable-*`, `dsvw`, `vampi`, `vulpy`, `djangoat`, `lets-be-bad-guys`, `owasp-web-playground` —
   exactly the category protocol **§5** names as memorisation-maximal (*"Juice Shop, WebGoat, public CVE
   corpora"*). The `llm_generated` half is 40 repos generated in 2026 by Claude/Codex/Kimi *for this
   benchmark*, plausibly under-represented in training data. Under §5's own definition E59 measured **higher
   detection on the higher-contamination arm** (0.519 vs 0.316, p = 0.062) — the direction memorisation
   predicts. It tested the narrower "an LLM recognising another LLM's defect", yet the result was propagated
   to 0027's bound, §5 and the plan as *"no evidence for the feared direction"*. **That weakening is not
   supported; withdraw it to the narrow claim actually tested.**
3. **E57's bound assumes reading independence that three of the lab's own experiments falsify.**
   `((1-p)^18)^8` requires independent readings. E37 states readings are positively correlated (union 0.170
   where independence predicts 0.242); E46 puts the union at **70%** of that projection at k=5, E48 at **58%**
   at k=6. At an effective k of ~9–13, "ruled out above ~3%" relaxes to roughly ~5%. Same family as E30: a
   model contradicting a measurement already held.
4. **E66's "two thirds of absence fixes are not route-shaped" is stale and self-contradicting.** The
   committed `organic-absence-probe-260726.json` reads `add_auth_marker = 44`, `marker_on_route = 7`,
   `labelled_sites_in_sample = 35` — 7 route-landings and 35 extracted route sites in one artefact. The log's
   E66 table still prints `11/137 = 8.0%` and `20 sites across 6 repositories`. The 8% came from the
   extractor **E68 proved defective** and was never recomputed, yet E67 cites it as one of *"two independent
   measurements agreeing on where this detector's scope ends"*. That agreement is unsupported and the scope
   may be materially larger than published. **Guard gap:** SM17 checks artefact-vs-instrument freshness,
   `rescore_artefacts` checks stored verdicts, SM25 requires a citation — **nothing checks log prose against
   artefact fields**, which would have caught this and §0.
5. **E68's interval uses the wrong unit.** `organic_ci = [0.330, 0.644]` is a Wilson interval over **35
   sites**, while the artefact's own `projection_caveat` says *"sites cluster by repository so the independent
   unit is the repository"* and Stage 7 requires bootstrapping over the grouping unit. With 8 clustered repos
   the true interval is materially wider, so **p = 0.22 is not evidence of similarity, it is a study with no
   power** (§11.4). "Does not measurably degrade on production code" — the strongest transfer sentence in the
   repo — is licensed only as "this design could not have detected degradation smaller than ~25 points".
6. **Corpus independence is overstated: 63 repos ≈ 33 independent applications.** 40 of 63 are **10 app
   specifications × 4 generators** (`crm-saas-django`, `fintech-lending-fastapi`, … under
   `claude-code`/`codex`/`codex-high`/`kimi-code`), sharing domain, framework and many route shapes. Every
   grouped bootstrap treating repo as the unit (E15, E60's 20-repo `llm_generated` arm, E64's 32 repos, E65)
   counts four correlated draws as four independent ones. Not fatal; it narrows intervals that should be
   wider, and it is checkable in ten minutes.
7. **E61's ENFORCEMENT vocabulary was read off the population it is evaluated on**, then scored on those
   same findings; self-tests are authored, not held out (§10.3). Stakes are low at +0.33pp — but the method
   must not be reused for a larger lever without a held-out split.

## Sequence, and open questions for the user

**P0 (hours, mandatory):** fix the double-count, re-run, §4-propagate. **P1:** organic precision via the
still-unprotected-at-HEAD negative oracle, repository as the unit, ≥15 repos. **Conditional on P1:**
off-route extension (if the inventory is affordable), time-per-decision (if it is close), ecosystem widening
(only after the vocabulary selection bias is measured).

- Is the product an attestation artefact (forbids the non-reproducible LLM layer) or an advisory tool
  (tolerates it)? Everything in §2.1 turns on that; it is a product decision, not a research one.
- Does "does not measurably degrade on production code" (E68) get quoted externally? If yes, §4.5 first.
- Who owns re-deriving the ~8 downstream figures P0 touches (0023/0027 amendments, plan, E56/E61/E64/E67)?
