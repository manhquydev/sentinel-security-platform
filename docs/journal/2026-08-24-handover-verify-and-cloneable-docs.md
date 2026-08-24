# 2026-08-24 — Handover verify, then cloneable docs instead of a hidden talk track

Verified the six-week handover list against the repo, independently
cross-audited the first tick-file, then closed only the gaps a teammate can
clone. Coordinated over Herdr (`handover-orch`, `verify-*`, then
`docs-refresh`).

## What happened

The first pass looked complete. Source was 8/8. The demo walkthrough, facade,
and live runbook existed. The brief had the six required headings. The
checklist said "hướng dẫn chạy demo" and "scan → final report" were done.

The second pass, reading someone else's slice plus `git ls-files`, found two
real errors:

1. **`docs/operations/sentinel-charter-demo-runbook.md` is gitignored.**
   `git ls-files` is empty. The nộp demo was a personal 15-minute talk track
   on the operator machine. Citing it as the public demo was the same class
   of lie as a check that never opens the file it names.
2. **`artifacts/week1.aggregate.jsonl` is not the input to
   `docs/reports/artifacts/week3-sample-report.jsonl`.**
   `scripts/generate-week3-sample-artifacts.py` fabricates four rows
   (`aaaa…` / `bbbb…` / `cccc…`). Claiming week-1 scan → week-3 sample as
   one chain was false.

A third count error followed: the checklist tóm tắt did not match its own
tables after those downgrades.

## Decision

Close cloneable gaps. Do not un-gitignore the personal talk track. Do not
fake a live Kong send or a `live_run:true` scorecard.

Chosen path: new **tracked** public docs (cheap to abandon) plus one
deterministic week-1 report:

- [`docs/operations/install.md`](../operations/install.md) — grader / facade / live
- [`docs/operations/charter-demo.md`](../operations/charter-demo.md) — 7 scenes;
  scene 5 stops if Kong is absent
- [`docs/reports/handover-results.md`](../reports/handover-results.md)
- [`scripts/analyze-week1-aggregate.py`](../../scripts/analyze-week1-aggregate.py)
  → [`week1-aggregate-report.jsonl`](../reports/artifacts/week1-aggregate-report.jsonl)
  (36 rows, input sha `d7717e70…`, `live_run: false`)

README now requires `sentinel-live-preflight.sh base` (bare invocation exits 2).

## Docs refresh (same day)

Older operator pages still pointed at the hidden runbook as the nộp door:
week-06 §6, the live-deployment guide, and the completion self-assessment.
Those now point at `install.md` / `charter-demo.md`. `AGENTS.md` Current State
and the docs map table follow. Historical completed plans were left historical.

`ak journal create` was not used as the source of truth: this repository's
journal owner is `docs/journal/`, not `plans/journals/`. AgentWiki publish
skipped.

## Lessons worth keeping

- **A path that is not in git is not a handover artifact.** `ls` on a working
  tree is not `git ls-files`. The talk track can stay local; the cloneable
  demo cannot.
- **Sample generators are not provenance.** Four fabricated digests do not
  inherit a 36-row aggregate just because both files say "week 3" nearby.
- **Fail-closed on schema is still the live FP/FN story.** Vertex flash-lite
  / free-form models that ignore the enrichment schema must not be "fixed"
  by weakening the validator. Scene 5 has no offline path; facade HITL stays
  `sent: false`.

## State after this session

Cloneable handover surface exists and is linked from README, `docs/README.md`,
and week-06. Live 9-step HITL + Kong + a schema-honoring `live_run:true`
scorecard remain operator-gated. The personal 15-minute talk track stays
gitignore. Do not mix Workbench evidence into Charter.
