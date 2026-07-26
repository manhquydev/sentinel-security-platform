# Instrument review: the organic-eval chain (E78/E79 source)

Adversarial review of the session's load-bearing instruments, run by a `code-reviewer` agent and then
**independently verified from data** before any correction was applied (agent claims are checked, not
adopted — two other external claims failed verification earlier the same day). This file records what was
verified and what was done; it is the citation target for log entries E78 and E79.

## Findings, verified and acted on

| # | instrument | defect | verified how | action |
|---|---|---|---|---|
| C1 | `run_organic_paired.py` | two advisories shared one fix commit + file (`jupyterlab/tests/test_extensions.py`), measured twice; test-file and mock-decorator "routes" padded the denominator | reproduced: 15 rows → 14 distinct `(repo,file,commit)`; 3 test-file rows | dedup by `(repo,file,commit)`; exclude test files; pinned by **SM28** |
| ROUTE | `detect_absent_auth.py` | `det.ROUTE` matched `@patch`/`@mock.patch` (unittest.mock shares the `patch` verb) | 9-case regex test; corpus findings on mock lines = 0, so anchor unmoved; production census inflated ~2× | two negative lookaheads reject the mock family, keep `@app.patch(`/`@router.patch(`; two self-test cases |
| 2a/2b | `run_volume_census.py` | counted `@patch` mocks and test-dir routes; `firefighter-incident` scored 124 sites from mocks alone | re-ran on the clones: web-app medians halve | ROUTE fix + exclude `tests/`/`test_` files; medians 62→27, 421→246 |
| C2 | `pool_bound_dependence.py` | the "bound weakened" branch was mathematically unreachable (Jensen on mean-1 weights) — a check that could not fail (§17) | 20,000 weight vectors: `dep/flat ≤ 1.0` always | rewritten with random-effects mixture `E_w[(1-p·w)^n]^k`; branch now fires at CV≈1.3; E57 conclusion stands |
| 3a | `probe_fame_memorisation.py` + E59 | the fame split (0.600 vs 0.333) and the authorship split (0.519 vs 0.316) are **union-over-k artefacts** — famous/human files were read ~2× more often | per-reading rate: 0.215 vs 0.214 (p=0.61); 0.204 vs 0.233 (p=0.81) | both withdrawn; corpus gives no memorisation signal either way |
| 1a | `run_organic_paired.py` | claimed to use the corpus prompt but used `_RUBRIC`; the corpus rate came from `_BINARY_RUBRIC`/160 tokens/redaction | read `run_generative.main` | replicated the corpus path exactly; re-ran (E79) |
| H1/H2/H3 | `run_organic_paired.py` | Fisher on paired data (should be McNemar); window could cut trailing routes; non-answers deflate toward collapse undisclosed | reconstructed all sites offline | exact sign test; window records contained routes and scores only those; effective-k and non-answer direction persisted |
| M1/M4 | `probe_organic_absence_corpus.py`, `pool_spec_clustered.py` | `wilson` imported inside a block (crash path); artefact `question` said "36 units" vs data's 33 | read | imports hoisted; 33/23 corrected everywhere |

## Net effect on published conclusions

- **E76 (inventory viable)** — survives; magnitudes corrected down ~2×.
- **E74 (E57 bound)** — conclusion stands under the corrected model; the evidence is now a check that can fail.
- **E59/E72 (memorisation)** — the corpus authorship evidence is **null** once the union confound is removed.
- **E75 (organic collapse)** — **reversed** to inconclusive once the instrument matched the corpus.
- **E73 (spec clustering)** — sound, no change.
- **Core corpus anchor** (0.263 recall, 561 sites, 12.5% precision) — essentially unchanged (565→561).

## Unresolved

- Whether any E75/E79 reading was format-compliant in a way `classify_prose` mis-scored — the pre-E79 prose
  was not persisted, so those specific verdicts are unauditable. E79's run persists what it scores.
- **M2 (not fixed):** `protected_route_lines` does not reset `route_at` at `def` boundaries, so a hunk
  spanning two handlers can attribute the second's added marker to the first's route line. Affects the
  exact `route_lines` in E67/E68, not their qualitative conclusions (wide CIs, "indistinguishable"). Left
  as a known residual because fixing it means re-running the whole organic probe chain; recorded so it is
  not silent.
- Model training cutoff is assumed, not verified; the post-cutoff subset is keyed to advisory publication
  date, which bounds but does not prove the fix postdates training.
