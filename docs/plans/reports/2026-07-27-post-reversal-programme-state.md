# Post-reversal state of the programme (advisory synthesis, 2026-07-27)

Commissioned from a `brainstormer` agent after four published conclusions reversed in one session. Returned
as text by the harness and saved here verbatim-in-substance by the commissioning session. **Its factual
claims about the ledger were spot-checked, not fully re-derived**; the two recommendations acted on
(E80 re-scoping, E81 global-auth negative control) were verified from data before use.

## What survived every correction
Bandit+Semgrep emit zero absence-class findings (0027/E56). Detector 0.263 recall / 12.5% precision
(E56→E71→E78). 45.7% structural route ceiling (E67). Organic recall does not degrade (E68/E69) — the
most-attacked surviving claim. The unit of work is the file (E64, E76/E78). No prioritisation exists here
(E60/E65, 6.5pp oracle headroom). **The model is not reproducible per file** (E22/E29/E42/E57) — untouched
by every reversal. Free advisory path saturates at 9 repos (E69/E70). Fix-commit oracle is recall-only (E77).

## Now unresolved
Memorisation (E78 killed the corpus evidence; E79 inconclusive). Model transfer. **Free-layer precision on
production code.** The model's off-corpus specificity. H2 (E73). E61's in-sample vocabulary. The 54%
non-route population.

## Retracted this session
E75 collapse (→E79). E59 "no contamination" and E72 "memorisation supported" (→E78). E76 magnitudes (→E78).
E71's published 0.226/6.7%/"1,130 handlers". Earlier: E50, E67's 0.722, E66's 0.850, E77's 0.987 instrument,
E74's could-not-fail check.

**One asymmetry named:** of every correction, exactly one (E71) moved a number *in the lab's favour* — and it
survived thirteen experiments precisely because it was unflattering. The audit function fires on good news.

## Strongest argument against shipping the deterministic layer
Production precision is plausibly an order of magnitude worse than 12.5%, for a structural reason:
**real applications enforce authentication globally** — `before_request`, app/router `dependencies=`,
Django/Starlette middleware, DRF `DEFAULT_PERMISSION_CLASSES` — none of it visible at a route decorator.
The blindness that puts 54% of labelled defects out of reach also puts an unknown fraction of *protected*
routes into the flag list.

**Cheapest decisive test — the global-auth negative control:** production apps whose auth is verifiably
app-wide; every flag is then a false positive by construction. No labels, no adjudication, no model calls.
This is the *negative* half of the oracle E77 proved the fix commit cannot supply: per-route negatives are
unobtainable, whole-application negatives are not. **Acted on — see E81.**

## Memorisation: demote, do not fund
The product decision no longer touches it (non-reproducibility removes the LLM regardless), and resolving it
costs the corpus debt ($5–50k, 9 repos against ~127–142). Keep it as a publication constraint: every
generative-role figure labelled corpus-only; re-opens only if the model is proposed for a paying surface.

## On the 20% reversal rate
The rigour is entirely in **detection**, none in **production**. Every reversal was caught by a
discretionary, unscheduled review — never by a standing guard. Three facts make "this is just rigour"
untenable: the union-over-k confound that caused E50's retraction was then committed **twice more**
(E59, E72); §17 was violated in the entry that closed the synthesis list (E74); two of four defects were
ordinary bugs catchable by one self-test.

Recommended (concrete, and one is a deletion):
1. **Executable §17** — every pooling/bound script ships a self-test driving the falsifying branch.
2. **Executable union ban** — any two-group comparison asserts equal k per group before a union is reported.
3. **One instrument review before ledger status, not after** — E78's recipe hit 4/4; the correction cost more
   than the review would have.
4. **Add no more protocol prose.** The protocol is past §23 and its rules were violated while in force.

Plus, free: publish the reversal rate in the ledger header, and **no bespoke instrument on n<30 earns a
status word other than INCONCLUSIVE until exercised on a negative control from the same population.**

## Unresolved questions for the caller
1. Is the lab willing to block the inventory product on a bad global-auth result, or is it decorative?
2. Does the detector inspect anything outside the route file? (It does — `APP_LEVEL`/`PROTECTED_ROUTER` —
   but **per file**, which E81 shows is the gap.)
3. Owed item 1 has been deferred through four sessions. Who decides, and by when?
