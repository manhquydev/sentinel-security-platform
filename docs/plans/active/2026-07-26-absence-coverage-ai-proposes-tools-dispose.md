# Execution Plan: Absence-class coverage — "AI proposes, tools dispose"

Date: 2026-07-26

## Status

**v2, red-team-reconciled — NOT yet cleared for cook.** Two adversarial lenses ran
(`plans/reports/redteam-260726-0006-absence-coverage-oracle-validity.md` +
the safety/scope lens): **both NOT-CLEAN, 8 blocking findings**. v1 was substantially wrong; this
version is rebuilt around what survived. Basis: advisory report
`plans/reports/advise-260725-2205-sentinel-identity-and-ai-central-direction-report.md`;
evidence in decisions 0020–0024 and `docs/ai-sast-research-log.md`.

## What the red-team destroyed (and what it cost)

1. **The prober was probing AROUND the control.** `/rest/admin/application-version` → **200** direct,
   **401 through Kong**, which is where authorization is enforced (0010). **E8's only finding was an
   artefact; corrected result: zero real vulnerabilities.** Fixed in code + research log (`c8fb026`).
2. **Persisted evidence had no redaction** and probe artefacts were git-tracked — harmless today (a
   version string) but identity-bearing under this plan. Fixed (`0518940`).
3. **The 0% baseline was rigged.** Bandit is Python-only; Juice Shop is TypeScript — it *cannot* run
   there. Semgrep never ran on Juice Shop. And this lab's own log calls Nuclei's Juice Shop findings
   "100% absence", contradicting the headline. **The comparison was invalid.**
4. **Ground truth was circular** — label `expected_auth` from source, derive it from source, then score
   one against the other = inter-annotator agreement, not recall.
5. **Phase 1 could not start**: Juice Shop source is not vendored (only a pinned commit ref); the image
   is distroless so it cannot be read out of the container either.
6. **Phase 4 silently un-deferred decision 0016** (whose gate is simulation-only, with five named
   prerequisites unaddressed), and the target has no volumes — a write survives restart, while the only
   reset destroys the ground truth. Rollback and measurement integrity were mutually exclusive.
7. **Auth failure would read as "clean"** (every probe 401 → control-present → exit 0) — E11's silent
   failure reproduced in our own design.
8. **Criterion 4 ("zero LLM veto paths") was unprovable** as written — the project's own journaled
   failure mode.

## Outcome (v3 — reframed at the validate gate, user decision 2026-07-26)

**Validate found the v2 outcome unachievable on this target:** the enforcement point routes only 8
endpoints, of which **2 are non-public**, and Kong protects **both correctly**. Absence-recall could
only ever measure 0/2 — you cannot detect *missing* authorization on routes that *have* it.

**Reframed outcome — the defence-in-depth posture is the finding.** Measure, per routed endpoint,
**where authorization is actually enforced**:

| gateway | app origin | verdict |
|---|---|---|
| 401/403 | 401/403 | defence in depth — control at both layers |
| 401/403 | **2xx** | **gateway-only enforcement → FINDING** (single point of failure: an SSRF, a misrouted internal call, or any direct-to-app path defeats all authorization) |
| **2xx** | 2xx | missing control entirely (the classic case; none observed here) |

This is a genuine pentest report item, it is measurable **today** with the already-corrected prober,
and it needs no new target and no change to the system under test. The **AI generates hypotheses only**;
deterministic code executes and judges; **no LLM output may remove a finding**.

**Preliminary measurement (already observed while fixing the oracle):** both non-public routed
endpoints — `/rest/user/whoami` and `/rest/admin/application-version` — return **401 at the gateway and
200 at the app origin**, i.e. **100% of this app's non-public routes rely solely on the gateway for
authorization**. That is the headline result this plan must confirm rigorously and report.

## The independent oracle (replaces the circular one)

Juice Shop **self-reports** challenge completion: `/api/Challenges` exposes a `solved` boolean the
application itself flips, including **12 `Broken Access Control` challenges** (verified live). That is
ground truth **the prober cannot influence and did not author** — it breaks the circularity that
invalidated v1. Scoring: probe → observe which access-control challenges flip `solved` → recall over
that set.

## Constraints (non-negotiable; the new ones came from the red-team)

- **Judge at the enforcement point.** Every verdict is taken where the control lives (Kong, 0010). An
  unreachable enforcement origin **errors**; it never judges from the app origin. *(F2)*
- **No LLM veto.** Findings are append-only w.r.t. LLM output; a hostile model reply
  (`{"drop":true}`) must leave the count unchanged — asserted by test. *(structural restatement of M3)*
- **All persisted evidence through `agent.trace.redact_persisted`**; probe artefacts gitignored;
  negative-control test with a synthetic JWT+email that must come back redacted. *(B2)*
- **Identities are operator-provisioned throwaway accounts only.** No probe authenticates as, or reads
  the data of, a pre-existing or real user. *(H2)*
- **Per-identity session canary** before any probing: each identity must prove a live session against a
  known endpoint, else the run aborts non-zero. A 401 from an unverified session is `error`, never
  `control-present`. *(H1)*
- **Synthetic canary**, not a real finding — a correct extractor would stop flagging a real one and
  break the run permanently. *(F6)*
- Read-only, loopback/allowlisted, fail-closed; provenance discipline; measured-not-trusted.

## Non-goals

State-changing probes (deferred: needs a new ADR answering 0016's five prerequisites); generalising to
a second application (separate plan, gated on an authorisation record + allowlist unification);
black-box discovery; OWASP-Benchmark scores; any claim of a "0% baseline" without a re-run.

## Acceptance criteria (v3 — falsifiable, and achievable on this target)

1. **A defence-in-depth map** for every gateway-routed endpoint: enforcement at gateway / at app / at
   neither, with the request-response evidence for each. Complete coverage of the routed set.
2. **The gateway-only-enforcement count is reported** with its security consequence stated plainly
   (single point of failure). Preliminary observation to confirm: 2/2 non-public routes.
3. **Per-identity session canary + synthetic finding canary pass in 100% of runs**; either failing
   exits non-zero. An unreachable enforcement origin errors, never "clean".
4. **No LLM path can remove a finding** — hostile-reply test (`{"drop":true}`) leaves the count
   unchanged.
5. **Coverage bound reported honestly**: how many of the app's endpoints the gateway routes (8 of a
   much larger surface), so the result is never read as whole-app coverage.
6. Offline-reproducible from committed artefacts, except the live probe run.
7. Zero regressions across W1–W11.

**Withdrawn from v2:** absence-recall against the challenge oracle (denominator is 0 real positives
here) and the ≥0.9 precision gate. Both are re-openable only on a target with genuinely broken authz.

## Risks & rollback

Ground-truth work is the bottleneck; the enforcement point routes few endpoints (may cap recall at
zero — an honest possible outcome); the LLM may refuse target-derived source (measure, never downgrade
provenance). All phases additive; no W1–W11 behaviour change — **except** the attack-surface schema,
which pins `coverage.mode` to `anonymous-locator-only` and has no `evidence_source` slot for
hand-labelled/LLM-proposed rows; extending it is explicit work, not a silent edit. *(F9)*

## Open questions (for validate)

1. Is the Kong-routed endpoint set large enough for a meaningful denominator, or must Kong's route
   config be extended first (which changes the system under test)?
2. Do the 12 Broken Access Control challenges correspond to endpoints the gateway routes?
3. Who provisions the throwaway identities, and does registration perturb the oracle's `solved` state?
4. Is Week-12's PRD still due, and should this plan be its roadmap?
