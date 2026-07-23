# 0002 CWE category map accepts semantic equivalents

Date: 2026-07-23

## Status

Accepted

## Context

The benchmark scores a finding against an OWASP Benchmark test case by mapping the
finding's CWE to the case's expected category (`benchmark/scoring/cwe_category_map.py`).
The map's docstring stated that matching must go through category rather than raw
CWE-integer equality, "because a tool may report a CWE that's semantically the same
vulnerability class but a different specific number than BenchmarkJava's pick."

The map did not do that. It contained exactly the 11 CWE values BenchmarkJava itself
uses — an identity map of the ground-truth CSV. Independent review (2026-07-23) found
that 52% of the winning tier's findings carried an off-map CWE, and that correct
detections reported under a *more specific* CWE were scored as misses:

- All 60 `weakrand` false-negatives were CWE-338 reports (the child of CWE-330).
- 41 of the `hash` false-negatives were CWE-916/759.

The published recall was therefore understated, and precision correspondingly
overstated, across every arm.

## Decision

The map accepts CWEs that are semantically the same weakness as the category's own CWE:

| Added | Category | Relationship |
|---|---|---|
| 338 | weakrand | child of CWE-330 (weak PRNG) |
| 916, 759, 760 | hash | weak/unsalted password hashing |
| 73 | pathtraver | sibling of CWE-22, external control of path |

**Admission rule**, recorded in the source so later edits are held to it: only a CWE in
a direct parent/child or sibling relationship with the category's CWE, describing the
*same* weakness. Score improvement is not a justification.

Explicitly rejected, with reasons in the source:

- **CWE-1004** on `weakrand` cases (42/run) — a different vulnerability the model found
  in the same file, not a weakrand detection. Admitting it would be score-gaming.
- **CWE-200, CWE-20** — too generic to attribute to any category.
- **CWE-134** on xss, **CWE-15** on cmdi, **CWE-915/472** on trustbound — distinct classes.
- **CWE-327** on `hash` cases — already maps to `crypto`. Weak-hash and risky-algorithm
  genuinely overlap in the CWE taxonomy, so remapping it would trade hash
  false-negatives for crypto ones rather than fix anything.

## Alternatives Considered

1. **Leave the map as-is and document the limitation.** Rejected: the map contradicted
   its own stated contract, and the error was large enough to change conclusions.
2. **Score CWE-agnostically only.** Rejected: it counts any finding on a case as a
   detection, which over-credits a tool that flags the wrong vulnerability class.
3. **Admit every CWE observed on false-negative cases.** Rejected as fitting the metric
   to the model — the definition of benchmark-gaming.

## Consequences

Positive:

- Recall is no longer penalised for correct detections filed under a more precise CWE.
  sol recall 0.8624 → 0.9329; every arm improved.
- The metric now matches its documented contract.

Tradeoffs:

- **Every published figure changed.** sol precision 0.7689 → 0.7503, and with it the
  headline verdict: sol now sits *on* the ≥0.75 "production-viable" line rather than
  above it, with a 95% t-CI of [0.7394, 0.7611] that spans the threshold. The
  arm ordering is unaffected.
- Two metric versions now exist in the repository. `runs/scorecard-v0-final.json` and
  the per-category table in `runs/index.md` are preserved under the **original** map as
  the historical record; `runs/model-comparison.md` carries corrected-map figures for
  all four arms. Figures must not be mixed across the two.
- Scoped precision still counts a wrong-category alert on a benign file as a true
  negative. That is a separate property of the metric, not addressed here: measured at
  alert level, sol precision is 0.5733 rather than 0.7503.

## Follow-Up

- Decide whether ≥0.75 *scoped* precision is the right production bar, given that an
  operator triaging alerts experiences the alert-level number instead.
- A future OWASP Benchmark version may introduce multiple CWEs per category; the map is
  pinned from the real CSV and must be re-derived, not assumed.
