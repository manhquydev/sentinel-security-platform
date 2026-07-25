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

## Outcome (v2 — narrowed to what is defensible)

Determine, with an **independent oracle**, whether a runtime differential prober can detect
absence-of-control vulnerabilities on a target where the enforcement point is known — and quantify
honestly how far the technique reaches. The **AI generates hypotheses only**; deterministic code
executes and judges; **no LLM output may remove a finding**.

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

## Acceptance criteria (falsifiable, and honest about the comparator)

1. **Recall > 0 against the independent oracle** — at least one `Broken Access Control` challenge
   flipped `solved` by the prober. If zero, the technique is falsified on this target and that is the
   reported result.
2. **Precision measured and reported**, not asserted. v1's ≥0.9 target is withdrawn: five verified
   false-positive classes exist (SPA fallback, 200-with-empty-body, 500-not-404, healthcheck-invoked
   endpoints, gateway-only enforcement). Precision is an output of this work, not a gate.
3. **Per-identity session canary + synthetic finding canary pass in 100% of runs**; either failing exits
   non-zero.
4. **No LLM path can remove a finding** — hostile-reply test leaves the count unchanged.
5. **LLM hypothesis yield** reported as a signed delta against a *frozen* deterministic baseline, with
   the deterministic arm fixed first so it cannot be weakened to flatter the LLM. Zero is a valid result.
6. Offline-reproducible from committed artefacts, except the live probe run.
7. Zero regressions across W1–W11.

## Phases (trimmed to the smallest honest increment)

### Phase 0 — Prerequisites (BLOCKING, no detection code)
- **Fetch the pinned Juice Shop source** (gitignored, SHA-pinned, fail-closed) — the RealVuln
  `fetch.sh` pattern. Nothing in Phase 1 can start until this exists. *(F1)*
- Enumerate which endpoints the **enforcement point actually routes** (Kong config): the oracle can
  only judge those. Record the coverage bound honestly. *(new limit found while fixing F2)*
- Provision two throwaway identities out-of-band; add per-identity session canaries + a synthetic
  finding canary.
- Record the authorisation/scope artefact: hosts + resolved IPs, owner, expiry, permitted classes and
  verbs — **machine-checked and fail-closed**, not prose. *(M2)*

### Phase 1 — Deterministic route + expected-auth extraction (NO LLM yet)
Extract routes and auth guards from the fetched source; produce `expected_auth` deterministically.
The LLM is deliberately excluded so the headline result cannot depend on it. *(T2)*

### Phase 2 — Differential prober at the enforcement point
Identity matrix (anonymous + 2 throwaway) × routed endpoints; verdicts per the corrected oracle.
Extends the hardened prober (SPA-fallback guard, nonexistent-path control, no redirects, confidence
gate, gateway-first judging). Non-mutating requests only; login POST is the only permitted write and
is explicitly in scope of "read-only".

### Phase 3 — Score against the independent oracle
Run, then read `/api/Challenges` for flipped `solved` flags; report recall, precision, and the coverage
bound. Re-run the SAST/DAST comparators **on the same endpoints** before any comparative claim, or make
none. *(F5)*

### Phase 4 — LLM hypothesis layer (AI-central, measured against the frozen baseline)
Only after Phases 1–3 produce a frozen number: the LLM proposes `expected_auth` for ambiguous routes and
business-logic abuse hypotheses; code tests each. Report the signed delta. *(T1/T2)*

**Deferred to their own decisions:** state-changing probes (0016's five prerequisites); generalisation
to a second app (authorisation record + allowlist unification, M1).

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
