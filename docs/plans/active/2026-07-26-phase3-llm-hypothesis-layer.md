# Execution Plan: Phase 3 — LLM hypothesis layer, measured against a frozen baseline

Date: 2026-07-26

## Status

**Draft (v1, pre-red-team).** Continues
`docs/plans/active/2026-07-26-absence-coverage-ai-proposes-tools-dispose.md` (v3, Phase 3) after
Phases 0–2 shipped (decision 0025). Requires four-lens-style red-team + validate before cook.

## The opening this builds on (measured, decision 0025)

Phases 0–2 proved: **2/2 non-public gateway-routed endpoints have no authorization of their own** —
the app answers 200 directly while Kong correctly returns 403. Kong is the sole authorization control.

The direct consequence, and this plan's thesis:

> If the app enforces nothing itself, then **any sensitive endpoint that is NOT routed through the
> gateway is unprotected by construction** — there is no control in front of it at all.

The gateway routes **8** endpoints. The application's real surface is far larger. Every endpoint in
that gap is, by the measured result, defended by nothing.

## Outcome

Determine — with a **frozen deterministic baseline** as the comparator — whether an LLM proposing
candidate endpoints finds **unrouted-and-reachable** endpoints that deterministic enumeration did not,
and report the signed delta honestly, including zero or negative.

**AI is central and bounded:** the LLM only **proposes candidate paths**. Deterministic code decides
existence, routing, and sensitivity. No LLM output can create, suppress, or alter a verdict.

## THE VALIDITY THREAT (stated first, because it decides whether this means anything)

**Juice Shop is one of the most famous deliberately-vulnerable apps in existence.** An LLM proposing
`/api/Users` or `/rest/admin/application-configuration` may simply be **reciting memorised training
data**, not reasoning about an application. If so, the measured "AI contribution" would be an artefact
that **would not transfer to a client's private application** — which is the actual use case
(advisory: VinSOC pentest team, company-owned apps).

This plan therefore measures the LLM under **two conditions** and reports both:

| condition | what the LLM is given | what a hit means |
|---|---|---|
| **A — named target** | told it is Juice Shop | may be memorisation; upper bound, NOT evidence of generalisation |
| **B — blinded** | given only observed evidence (the 8 routed paths, response shapes, framework fingerprints) with the app's identity withheld | a hit is genuine inference from evidence and **is** the transferable signal |

**The headline number is condition B.** Condition A is reported only as the memorisation ceiling. If
B ≈ 0 while A is large, the honest conclusion is "the model recognised the app", and the AI layer does
not generalise — a valid and publishable negative result.

## Constraints (inherited + new)

- **No LLM in the verdict path.** The LLM emits candidate *strings*; a deterministic verifier decides.
  A structural test asserts the verifier imports no model surface (as `tests/defence-in-depth-test.sh`
  DD1 already does for the mapper).
- **Read-only.** GET only, loopback only, fail-closed; no state change, so no HITL needed (0013).
- **Provenance.** Observed target evidence sent to the model is `target-derived`; the rubric is
  `operator`. Expect refusals; measure them, never downgrade trust to force an answer (0018/0020/E11).
- **Fail-closed canaries** as in Phase 1–2: session canary (identity liveness) and synthetic canary,
  plus a **new** proposal canary (below).
- **Bounded probing.** A hard cap on candidate paths per run; each candidate probed once at each
  origin; evidence redacted at capture; artefacts gitignored.

## Oracle (deterministic)

For each candidate path, probe **both** origins as the live agent identity:

| gateway | app | classification |
|---|---|---|
| 404 (not routed) | **2xx, non-HTML** | **UNROUTED-AND-REACHABLE → finding** (no control in front of it) |
| 404 | 404 / HTML-SPA fallback | does not exist — discard (not a miss, not a finding) |
| 2xx / 403 | any | already routed — outside this plan's gap class |

The SPA fallback is the dominant false-positive risk: this app answers **200 + index.html** for unknown
paths, which is why the content-type guard from Phase 1 is mandatory here, not optional.

## Acceptance criteria

1. **Signed delta reported for condition B** — findings from LLM-proposed candidates that the
   deterministic baseline did not produce. **Zero is a valid, reportable result.**
2. **Condition A reported separately** and explicitly labelled a memorisation ceiling, never as the
   contribution.
3. **Deterministic baseline frozen before any LLM run** — a committed enumeration (the 8 routed paths
   plus any paths already observed in the lake/attack-surface baseline). It must not be weakened
   afterwards to flatter the LLM.
4. **Precision reported** per condition: verified findings ÷ candidates probed.
5. **Proposal canary:** a known-existing, known-unrouted path is planted in the verification set every
   run and must be classified `unrouted-and-reachable`; if it is not, the verifier is broken and the
   run exits non-zero. (Distinct from the LLM — it tests the *oracle*, not the model.)
6. **Refusal rate recorded** — how often the model declines under `target-derived` provenance.
7. Zero regressions; offline-reproducible scoring from committed artefacts.

## Phases

### 3a — Freeze the deterministic baseline (no LLM)
Commit the enumerated known-path set (routed 8 + attack-surface baseline paths + any lake-observed
paths), and the verifier with its proposal canary. Run it on the frozen set; record the findings count.
This number is the comparator and is immutable afterwards.

### 3b — Condition B (blinded) LLM proposals
Give the model only observed evidence — routed paths, response shapes/headers, framework fingerprints —
with the target's identity withheld. Cap candidates. Verify deterministically. Report delta + precision.

### 3c — Condition A (named) LLM proposals
Same pipeline, target named. Report as the memorisation ceiling. The A−B gap is itself the measurement
of how much of the "AI contribution" is recall rather than reasoning.

### 3d — Record
Decision doc with both numbers, the refusal rate, the coverage bound, and an explicit statement of
whether the AI layer generalises. If B ≈ 0, say so plainly.

## Risks

- **Memorisation confound** — the central threat; addressed by the A/B design, which cannot fully
  eliminate it (the model may recognise the app from fingerprints alone in condition B; that is itself
  worth reporting).
- **SPA fallback false positives** — mitigated by the content-type guard; a candidate answering HTML is
  never a finding.
- **Model refusal** under correct provenance — likely (three prior precedents); recorded as data, and
  condition B is not retried under downgraded trust.
- **Probing unrouted paths touches the app directly** — read-only GET on a local throwaway target,
  inside 0013; no writes, no HITL trigger.

## Open questions (for validate)

1. Is condition B genuinely blind if the response headers fingerprint the app (`X-Recruiting`,
   Juice-Shop-specific banners)? Should those be stripped from the evidence given to the model?
2. What candidate cap is honest — enough to give the LLM a fair chance, bounded enough that "spray many
   guesses" is not the mechanism?
3. Should a candidate that exists but is *not sensitive* (e.g. `/favicon.ico`) count against precision,
   or be excluded as trivially uninteresting?
