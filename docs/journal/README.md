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
- [2026-07-24 — Weeks 6–8: the AI-attack phase and its hardening](2026-07-24-weeks-6-8-agent-phase-and-hardening.md)
  — the syndicate, IPI defense, and the HITL gate; the red-team re-scoping a broken maximal task
  three weeks running, and structure-over-detection as the durable control.
- [2026-07-24 — Week-9: the PII surface that had to be built, then measured](2026-07-24-week9-pii-redaction-the-surface-that-had-to-be-built.md)
  — the charter's DB-dump surface didn't exist, so Week-9 built a simulated one and scrubbed it at
  capture; the plan's sink inventory was two-thirds wrong until the code was read; measurement over
  an absent corpus is the same lie as no measurement.
- [2026-07-26 — The night the lab audited itself](2026-07-26-the-night-the-lab-audited-itself.md)
  — turning the research protocol on our own work; a withdrawn AUC claim that
  the code never heard, and the cost of treating prose as a patch.
- [2026-08-20 — Charter goes to production, and the lab audits its own cloud](2026-08-20-production-deploy-and-hardening.md)
  — local completion to a gated GCP DefectDojo; the honest live-scorecard
  refusal; metadata-guard after a red-team found the default compute SA.
- [2026-08-24 — Handover verify, then cloneable docs instead of a hidden talk track](2026-08-24-handover-verify-and-cloneable-docs.md)
  — cross-audit caught a gitignored demo runbook and a fake week-1→week-3
  chain; closable path was tracked install/demo plus a deterministic week-1
  report.
