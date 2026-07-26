# Counsel: product fork — free layer alone vs free layer + LLM generative layer

Date: 2026-07-26. Author: kongming (autonomous counsel, run on `fable`). Advisory only.
Evidence base: `docs/ai-sast-research-log.md` ledger + E56–E74 read in full; decision 0027 (with E72
addendum), decision 0022 (with E73 re-clustering); `docs/plans/active/2026-07-26-generative-role-what-is-owed.md`;
`docs/plans/reports/2026-07-26-next-direction-synthesis.md`. The ledger is treated as authoritative
throughout; every empirical claim below carries its E-number.

---

## TL;DR

Lead with **shape A — the free deterministic layer alone in the shipped artefact; the LLM leaves the
runtime product** — but state it precisely: A is the only shape that *could* ship on current evidence,
and whether it ships at all is still gated on the one unmeasured number (organic decision volume /
precision on code that is mostly correct). Cut the LLM from the artefact not because it adds nothing
(E62/E63 measured a real, independent addition) but because its addition is simultaneously
non-reproducible per file (E42, E51, E57), carries a live memorisation caveat with both directional
tests leaning the wrong way (E72), and is measured only on a corpus whose 38% defect concentration
inflates every operating number (E65 logic). There is a **third shape** neither A nor B: the LLM as a
**build-time rule author** — model proposes candidate deterministic detectors for the measured 54%
off-route blind spot, humans + self-tests + held-out data dispose — which keeps the model's one proven
strength (proposing, 0027) while touching none of the falsified roles.

---

## Reframed problem

The question as posed — A vs B — presupposes the inventory product is viable. The evidence does not yet
license that presupposition: every viability number (12.4% precision, 92 decisions, 3× compression) is
measured where **38% of files carry a defect** (E65), and the only organic datum on volume is one file
producing 98 findings (E66). So the real decision stack is:

1. **Does any inventory ship?** — gated on organic volume/precision (unmeasured; synthesis P1).
2. **If yes, what is in the artefact?** — this fork. A vs B.
3. **What role, if any, does the model keep?** — runtime layer (B), advisory sidecar, build-time
   author (third shape), or research-result-only.

Requirements the product shape must satisfy: reproducible artefact items (it is attestation-shaped),
honest coverage claims (no "vulnerability list" language — E61), a cost story a buyer can check, and
nothing that re-enters the falsified roles (gate: E2/0018/0020/DD1; ranker: E3/E14; prioritisation on
this corpus: E65).

---

## Q1 — Which shape leads, and what flips it

### Recommendation: A, stated as "the LLM leaves the artefact", not "the LLM is worthless"

The case for A is that every property an attestation artefact needs, the free layer has and the model
lacks:

| property | free layer | model layer |
|---|---|---|
| reproducible items | deterministic, no k (E56) | 0/24 files flagged in all 18 readings (E57); two runs give **disjoint** worklists (E42); best file 17/18 (E57) |
| marginal cost | ~0, offline | ~$0.23 per file the rule missed; union saturates at k=9 and readings 10–18 burn 51% of budget (E63) |
| transfer evidence | organic 0.486 vs corpus 0.576, indistinguishable (p = 0.22, E68), robust to repo clustering (E69) | **none post-cutoff**; detection is *higher* exactly on memorisation-maximal repos (0.519 vs 0.316, E72), fame split leans the same way (0.600 vs 0.333, E72) |
| memorisation exposure | none — a regex cannot memorise (E72) | live caveat, mildly *supported* by both available directional tests (E72; 0027 addendum) |
| headline standing | corrected **upward** by E71 (0.263 recall, 12.4% precision, 565 handlers) | every coverage number budget-dependent; may not be quoted without its k (plan, standing constraint) |

The synthesis report's §2.1 argument is decisive for the artefact and I endorse it: **you cannot sign a
compliance inventory whose items change between runs.** E72 then adds the second, independent
disqualifier: until an organic post-cutoff measurement of the *model* exists, no generative-role number
may be presented as free of memorisation (0027, corrected bound). A product cannot carry a coverage
claim its own decision record forbids presenting.

### The honest argument against my own recommendation

Steelmanned, B's case is stronger than the "cut it" framing admits:

- **The addition is large relative to the base.** +0.50 strict over a free-layer baseline of
  0.125–0.208 on absence files (E63); on the files the rule can reach, the rule delivers only ~57% of
  what the model delivers (E62). Cutting the model discards the majority signal on that population.
- **The model is the only instrument that reaches anything off-route.** The free layer has a structural
  ceiling of 0.457 — 54% of labelled entries never sit on a route (E67) — and it can never distinguish
  public-by-design from forgotten, because intent is not in the syntax (E56). The model reads semantics.
- **Its clean-code FP rate (~0.6–1%, E52/E54) is the single precision-shaped capability in the whole
  toolbox**, against the free layer's 12.4%.
- **Complementarity is real and measured**: overlap sits at the independence expectation (E58, E62), so
  running both is genuinely additive, not redundant.

Why this does not flip the recommendation today: every one of those numbers is a corpus number, measured
where 38% of files are defective, under a live memorisation caveat (E72), on an instrument where 60–77%
of files carry zero propensity at any k (E45) and the class coverage is effectively ownership/authn only
(CWE-307 at 1/53, E39; no recovery, E41). The addition is real; what is missing is any evidence it
survives contact with post-cutoff production code, and any artefact shape that can hold a
non-reproducible item. Both are testable, cheaply. Until then B's marginal layer cannot be sold, signed,
or priced honestly.

### The flip threshold, concretely

B returns to the product only if **all three** hold:

1. **The in-progress organic post-cutoff model eval comes back non-collapsed.** Preregister the
   criterion before results exist — suggestion: file-level union at k≤3 over the ≥9-repo paired
   pre-fix set, repo-clustered interval, with "collapse" defined as the point estimate falling below
   half the corpus figure at matched k, and HEAD/clean-arm flags consistent with the ≤~3% specificity
   bound (E52/E54). With 9 clustered repos this has power only for collapse-vs-non-collapse — say so in
   advance, or the null will be over-read exactly as E68's was (synthesis §4.5).
2. **The user decides the product is an advisory tool, not an attestation artefact.** This is the
   synthesis's open product question and it is a user decision, not a research one. Non-reproducibility
   is disqualifying for a signed inventory *regardless* of (1). Recommended default: attestation-shaped
   inventory — it is what the measured shape supports (E61, E64) and what the compliance-workflow
   precedent runs on. Present the fork; evidence that would flip the default is a real buyer whose
   workflow is interactive review, not attestation.
3. **A buyer-checkable cost story at k≤3** (~$0.23/file-missed scale, estimate per E63; call counts
   exact), with the k=9 saturation and the 51%-waste tail disclosed.

Even then: the model ships as a **second independent channel presented to a human** (E56/E58's licensed
arrangement), never as a filter over the free layer (gate role, falsified: E2, 0018, 0020, DD1) and
never as an orderer (E3/E14; ordering closed on this corpus anyway, E60/E64/E65).

---

## Q2 — The third shape: LLM as build-time rule author, runtime stays deterministic

Yes, and it is the strongest unplayed move on the board. Shape C: **the model proposes candidate
deterministic detectors; humans, self-tests, and held-out measurement dispose; the shipped scanner
remains 100% deterministic.**

Why this is not a falsified role:

- E2/0018/0020 falsified the model holding a **runtime verdict over findings** (gate). E3/E14 falsified
  the model **ranking against a prior**. Rule authoring is neither: the model's output is *code*,
  disposed at build time by review + self-tests + measured recall/precision on data it did not author.
  No model is reachable from the verdict path at runtime — DD1 stays intact structurally, not just
  nominally.
- Non-determinism becomes harmless. A rule proposed on reading 3 of 10 is kept on its measured merits;
  nobody cares whether a re-run would propose it again. The k-problem, the per-scan cost, and the
  reproducibility problem all vanish from the artefact.
- Memorisation mostly stops mattering. A memorised pattern that compiles into a rule which validates on
  held-out/organic data is a good rule regardless of provenance. Contamination threatens *capability
  claims about the model* (E72); it does not propagate into a self-tested regex.

Why the evidence says it might work:

- The cheapest real security value this project produced came from ~40–60 lines of hand regex: the E53
  shadow detectors found 10 real unlabelled defects at zero marginal cost; the E56 detector reaches
  0.576 on the population it targets (E67). The bottleneck was never rule execution — it was that
  **nobody had written the rule** (E56's own conclusion).
- The target is named and measured: the **54% off-route population** (E67) — middleware,
  service-layer, class-based views — which is also where organic fixes actually land (E68/E70: the
  binding filter on the free advisory path is that fixes are not route-decorator-shaped).
- The model's one measured strength is proposing (0027). This uses exactly that strength at the one
  point in the lifecycle where its weaknesses are free.

The trap to design against, named in the ledger: **E61's ENFORCEMENT vocabulary was selected on the
population it is scored on** (flag carried into E74's close-out). A model that reads the corpus and
"proposes" rules is laundering in-sample fit into shipped code. Disposal must therefore be: author on a
split (or on the off-route *characterisation*, not the labels), validate recall/precision on a held-out
split, and confirm on the organic set before anything ships. If a proposed rule cannot survive that, it
is not a rule, it is overfit with syntax highlighting.

A second third-shape worth recording, one level up: **the corpus and methodology may be worth more than
the scanner.** The sourcing research found no established benchmark carries absence classes above ~5%
(owed item 1, plan doc), and the E66 fix-commit-is-the-label pipeline is novel, validated, and free
where an advisory exists. A 60-line detector is trivially copyable the day it is published; the
organic-labelled corpus, the evaluation practice, and this log are not. That is a business-scope call
above this session, but the moat is the research asset, not the regex.

---

## Q3 — The concentration-artefact argument: how much weight, and the cheap resolution

**Weight: the heaviest of any open threat — near-decisive, and it applies to shape A as much as B.**
Three reasons it deserves that weight:

1. **It is the lab's own convicted error class, §22, applied to the one number nobody applied it to.**
   E65 voided the HARMLESS comparison on exactly this logic: effort-at-recall is a joint property of
   method and defect concentration. Precision and decision volume are the same kind of quantity, and
   every published figure for them comes from a corpus where 38% of files carry a defect (E65).
2. **The only organic datum points the wrong way** — one production file, 98 findings (E66).
3. **The failure mode is silent**, and this ledger's own history shows silent failures are the
   long-lived ones: E71 survived thirteen experiments precisely because no alarm ever fires on a number
   that merely *misleads* (asymmetric-scepticism lesson). An ignored inventory raises no error while the
   coverage claim stays technically true.

One partial mitigant, so the weight is honest rather than maximal: per-finding precision is partly the
wrong metric for an attestation product. The unit a customer pays in is the **decision** (E64: 92
file-level decisions, 6.1 findings each, 3× compression), and attestation workflows normally run at
60–80% not-applicable closures (E64's external practice review, the verified half). The kill condition
is therefore not "precision is low" — that is already known and priced into the framing — it is
**decision volume per repository × time per decision exceeding what the attestation is worth**. Both
factors are unmeasured; E64 found no published source for the second.

**The cheap measurement that resolves it** (near-zero cost, zero model calls, mostly cached data):

- **Volume census — needs no labels at all.** Run the detector at HEAD over every real production repo
  already identified by the advisory pipeline (137–191 fix-commit repos, E66/E70; the fetch machinery
  exists) and over any convenient set of post-cutoff Python web repos. Report the distribution of
  findings/repo and **file-decisions/repo**, repository as the unit. Hours of work. If a mid-size
  production app yields hundreds of decisions, the inventory is dead regardless of precision, for A and
  B alike.
- **Lower-bound precision via presumptive negatives** (synthesis P1, endorsed as designed): on the
  labelled repos, precision-LB = maintainer-fixed sites ÷ all sites reported on the pre-fix tree; the
  preregistered 20-item hand-read as the oracle-validity check; repo-clustered intervals only (E69's
  lesson — a per-site binomial here would repeat E68's mistake).
- **A self-timed decision sample** (time yourself on 20–30 file decisions). Weak evidence, admitted as
  such — but E64 established that *no* measurement of per-decision cost exists anywhere, so a crude
  bound beats a load-bearing unknown.

Decide the go/no-go rule **before** running it (the lab's own preregistration discipline): e.g. ship
only if median file-decisions/repo and the timed sample imply a review cost credibly below the
attestation value for the repo class the product targets.

---

## Q4 — Sequencing: next three pieces of work by information value per unit cost

**1. (b) + (e) folded together: organic volume census + presumptive-negative precision at HEAD.**
Highest information per unit cost of anything on the table and it is not close: zero model calls, data
largely cached, hours-to-a-day of engineering, and it is the only experiment that decides whether *any*
product ships. It gates the value of every other candidate — (c) adds recall, which adds decisions,
whose cost this measures; (d) authors rules whose findings land in this same inventory; (a) only
matters commercially if there is a product for B to return to (though (a) retains research value
regardless). This is the synthesis's P1 with the volume census added; the census is the cheaper and
more decisive half.

**2. (a) Finish the organic post-cutoff model eval (in progress).** The setup cost is sunk and the
marginal cost is small (~35 paired files × k≤3 ≈ ~100 calls). It is the only measurement that can close
E72's live caveat either way, it decides B's flip condition 1, and it determines whether 0027's
positive claims ever become transferable. Preregister the collapse criterion and the clustered-interval
reporting now, before results exist; with 9 repos it is a collapse-vs-non-collapse test, not an effect
estimate, and the report must say so or the null will be over-read (synthesis §4.5 precedent).

**3. (c) + (d) merged into one experiment: characterise the off-route population, then have the model
propose deterministic rules for it, disposed on held-out + organic data.** Run the characterisation
first (what do the corpus's 157 off-route entries and E68's non-route organic fixes actually look like —
middleware, class-based views, service layers; unquantified per E73's close-out). That characterisation
is the prompt corpus for the authoring experiment and keeps the model away from the labels. Disposal:
self-tests per rule (E53 pattern), recall/precision on a held-out split, confirmation on the organic
set. This is conditional on (1) showing the inventory is affordable — recall added to an unaffordable
inventory is negative value — which is why it is third despite being the most interesting.

Explicitly **not** on the list, per settled evidence: more readings of any existing file set (E57 —
nine flat readings; E46), prioritisation/ranking in any form on this corpus (E60, E64, E65 — 6.5pp
oracle headroom), precision repairs by markers or heuristics (E55, E61 — +0.6pp was the best available),
per-class prompting for CWE-307 (E40 twice, E41), and the paid corpus purchase — the free path
delivered the first organic check (E66) and saturates at ~9 repos (E70); the paid options return only
against a publication decision or a transfer claim that (1) and (2) first justify.

---

## What to avoid

- **Re-entering falsified roles under new names.** "Model triages the inventory" is the gate
  (E2/0018/0020/DD1). "Model orders the inventory" is the ranker (E3/E14) and ordering is closed here
  anyway (E60: worse than chance; E65: 6.5pp total headroom).
- **Any per-file model claim.** What replicates is a rate, not a detection (E42, E43). No sentence of
  the form "the model finds the vulnerability in this file".
- **Quoting any coverage number without its k** (standing constraint, learned three times), or any
  corpus precision/volume figure as a production expectation (E65/§22).
- **Shipping before the volume census.** The silent-failure shape means no feedback will correct an
  oversized inventory after launch.
- **Letting the authoring experiment validate on what it read** — the E61 in-sample trap, still flagged
  open in E74.
- **Calling E68's null a transfer guarantee.** It licenses "no measurable degradation" at a design that
  could not detect degradation smaller than ~25 points (synthesis §4.5); it does not license "transfers".
- **The word "vulnerabilities" anywhere in the product sentence** (E61). It is an inventory of route
  handlers with no visible access control, confirmed public-by-design or fixed.

## Alternatives & trade-offs (summary)

- **B now (free + LLM runtime):** buys +0.50 strict corpus coverage (E63) at the cost of an
  unsignable artefact, a live memorisation caveat (E72), an unpriceable per-file claim, and a cost tail
  that wastes half its budget past k=9 (E63). Weaker than A on current evidence; revisit on the flip
  threshold above.
- **A + advisory sidecar (B-lite):** model as clearly-labelled interactive second opinion, outside the
  artefact and the coverage claim — the synthesis's "at most" position. Acceptable *after* (a) comes
  back non-collapsed; before that it markets a capability with no post-cutoff measurement.
- **Shape C (build-time rule author):** keeps the model's proven strength, discards its weaknesses;
  risk is in-sample laundering, controlled by held-out disposal. Cheap to test; my recommended home for
  the model.
- **Corpus/methodology as the product:** the defensible moat; a business-scope decision above this
  session, recorded here so it is not lost.

## Work checklist

1. Preregister and run the volume census (findings/repo, decisions/repo at HEAD, repo-clustered) over
   the already-identified production repos. Write the go/no-go rule first.
2. Run the presumptive-negative precision lower bound on the labelled repos, with the 20-item hand-read
   check; repo-clustered intervals only.
3. Time 20–30 file decisions by hand; record as a crude per-decision bound with its weakness stated.
4. Finish the organic post-cutoff model eval with a preregistered collapse criterion and clustered
   reporting; propagate the result into 0027's memorisation bound either way.
5. Decide (user decision) attestation vs advisory; record it — everything about the model's runtime
   role turns on it.
6. If (1)–(2) pass: characterise the off-route population; then the model-authors-rules experiment with
   held-out + organic disposal.
7. Keep the paid-corpus options parked against a publication decision.

## Success metrics

- Decision-volume distribution and precision lower bound exist with repo-clustered intervals over ≥10
  production repos, and the pre-written go/no-go rule has been applied.
- E72's caveat is resolved by measurement in either direction; no generative-role number is published
  without the outcome attached.
- Either ≥1 model-proposed rule survives held-out + organic validation at precision ≥ the current
  detector while adding off-route recall, or the authoring shape is closed with a recorded negative.
- The shipped sentence (if shipping) names 565-scale inventories correctly, never says
  "vulnerabilities", and every published number carries its denominator and its k.

## Assumptions (made in place of questions)

- **The product's target workflow is attestation/compliance-shaped** (confidence: medium-high; basis:
  E61/E64 framing and the plan doc). If the user declares it advisory, B-flip condition 2 is satisfied
  and the sidecar option moves earlier — the artefact-reproducibility objection falls, the E72 and
  concentration objections remain.
- **The in-progress model eval uses the E66/E68 paired pre-fix files at small k** (high; stated in the
  tasking).
- **~9 labelled organic repos is the ceiling for the precision half without new spend** (high; E70);
  the volume census is not so limited because it needs no labels (medium-high; needs only HEAD
  checkouts).
- **E63's dollar figures are estimates, not measurements** (high; the log says so — token counts
  reconstructed; call counts exact).
- **No pilot customer exists to measure real time-per-decision** (medium). If one exists, replace the
  self-timed sample with a pilot measurement and weight Q3 accordingly.
- **Runtime note:** this counsel ran on `fable` (claude-fable-5) per the agent definition.
