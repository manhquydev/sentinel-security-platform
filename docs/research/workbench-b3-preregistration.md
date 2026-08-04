# Workbench B3 preregistration v1

Date frozen: 2026-08-04
Applies to digest-bound `sentinel-workbench-experiment/v1` runs only.

## Estimand and selection

The sole inferential result is the paired repository-level `B3−B2` difference
in `recall_at_12`. B1 is a predeclared descriptive control and must never
render generic “AI wins” language.

B3 has exactly three independently dispatched readings. Each eligible unit is
sent once per reading, in stable unit-ID order, as one canonical redacted unit
plus no more than 8 KiB sealed dependency context. No batch prompts, adaptive
follow-ups, hidden context, changed stratum or post-dispatch retry is allowed.
Empty replies are retained non-answers. Proposals recurring in at least two
readings are retained, ordered by recurrence then stable unit ID; the first 12
`consensus_at_k3` units are reviewed.

## Resources and decoding

Every arm receives 12 blinded verification packets per repository at 90 seconds
per packet against the same checklist. This is equal *human-review* budget
only. The run persists every arm's information inputs; B3 additionally
persists request count, source bytes, input/output tokens, cost and worker
time.

B3 is chat-only, tools disabled, `temperature=0`, `top_p=1`, capped at 2,048
output tokens. It cannot modify the B0 baseline.

## Population, inference and claims

Before any arm, freeze and digest one redaction-admitted eligibility mask and
candidate-truth denominator. All arms score on that exact mask. A mask failure
is coverage-limited/non-comparative.

Inference is a paired repository-cluster percentile bootstrap: 10,000
resamples, seed `20260804`, two-sided 95% interval. Missing required arm or
reading, fewer than 12 admissible units in any arm, mismatch of spec/control/
mask, or lower than required corpus is `instrument-invalid`, not a zero or tie.

Twenty eligible paired repositories and at least 80% power for delta `0.02`
are required. Power is estimated by 10,000 Monte-Carlo paired simulations from
a separately catalogued, non-confirmatory B3 calibration corpus run only after
model, prompt and selection are frozen. Its digest, per-repository deltas,
variance/covariance inputs, seed and output are retained. Absent/mismatched
calibration is `underpowered/descriptive`.

For the named `B3−B2` contrast only: win when lower interval bound is `>+0.02`;
loss when upper bound is `<-0.02`; tie when the complete interval is within
`[-0.02,+0.02]`; otherwise inconclusive. There is no stopping after an observed
effect: every admitted repository and terminal attempt is reported.

## Truth and claim bounds

Truth is versioned against the candidate snapshot and contains vulnerability
ID, class, precondition, canonical unit, allowed alternatives, provenance,
licence, a complete adjudicated negative universe and an independent
outcome-blind control audit. Matching claims a vulnerability at most once;
unadjudicated proposals are `not-measured`.

Corpus outcomes are exactly `case-study-only`, `rejected`,
`underpowered/descriptive`, `contamination-bound` or `corpus-only`. V1 never
claims private-code capability. Every rendering carries the corpus outcome.

## Candidate-corpus inventory

`scripts/workbench-corpus-inventory.py` records candidate metadata only from a
locally pinned OpenSSF CVE Benchmark checkout and an already-present local
repository cache. It requires the exact benchmark revision, does not fetch,
scan, seal or transmit source, and refuses to replace a prior record:

```bash
PYTHONPATH=. python3 scripts/workbench-corpus-inventory.py \
  --benchmark /path/to/ossf-cve-benchmark \
  --expected-revision <full-40-character-git-revision> \
  --repository-cache /path/to/owner--repository-cache \
  --output /path/to/new-candidate-inventory.json
```

An inventory stays `not-admitted` and blocks comparative work even when it
finds local TypeScript at both referenced commits. Frozen truth, licence and
authorship evidence, contamination screening, independent control audit,
calibration and the 20 independent-repository requirement are separate gates.
Malformed benchmark metadata is recorded as `metadata-invalid`; abbreviated
commit IDs are never expanded or treated as pinned evidence.
