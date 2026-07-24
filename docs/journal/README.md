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
- [2026-07-23 — Native scanners: routing around a dead registry](2026-07-23-native-scanners-routing-around-a-dead-registry.md)
  — registry blob throughput defeated image pulls, and the local-binary fallback that kept
  the scanners running instead of blocked.
- [2026-07-23 — Checks that passed because they checked nothing](2026-07-23-checks-that-passed-because-they-checked-nothing.md)
  — one recurring failure across shipped code, review tooling, tests, and the verification of
  those tests: a check reporting a pass without examining the thing it names.
- [2026-07-24 — The guard that read the wrong lake](2026-07-24-the-guard-that-read-the-wrong-lake.md)
  — reconciling the 11 WebGoat rows in place, and the locator-scheme probe whose ignored
  filter read every scan type and reported a confident wrong answer.
- [2026-07-24 — A configured interface is not a working one](2026-07-24-a-configured-interface-is-not-a-working-one.md)
  — the `embed` alias that was a chat model and the chat gateway that refused unlabelled
  requests; both legible, both dead until probed. Legibility is not liveness.
