# Journal

Chronological record of how work actually went — what broke, what misled us, and what
the failure taught. Journals preserve working history; they do not replace current truth.

Read them for method, not for status:

- **Current product and architecture truth** lives in `docs/product/`, `docs/decisions/`,
  and the repository's code and tests.
- **Work in progress** lives in `docs/plans/active/`.
- **Journals** record the path taken, including the wrong turns, so a later reader can
  recognise a failure mode they are about to repeat.

A journal entry earns its place only when it carries something the plan and the decision
records cannot: a diagnostic pattern, a misleading symptom, or a mistake worth not
repeating. Entries are never edited to look better in hindsight.

## Entries

- [2026-07-23 — DefectDojo standup: two checks that could not fail](2026-07-23-defectdojo-standup-checks-that-could-not-fail.md)
  — a restore drill and a smoke suite that both passed while proving nothing, and the
  broker defect hiding behind healthy-looking diagnostics.
