# 0025 Authorization is measured at the enforcement point; the finding is the defence-in-depth posture

Date: 2026-07-26

## Status

Accepted. Implements the validate-reframed plan
`docs/plans/active/2026-07-26-absence-coverage-ai-proposes-tools-dispose.md` (v3) after two NOT-CLEAN
red-team lenses. Supersedes the E8 result (which was an artefact — see the correction in
`docs/ai-sast-research-log.md`).

## Context

Decisions 0022–0024 measured that SAST detects the *presence* of bad patterns far better than the
*absence* of controls, and that no standard benchmark measures the absence half at all. The obvious
next step — detect *missing* authorization at runtime — was planned, red-teamed, and then found
**unachievable on this target**: the enforcement point routes 8 endpoints, only 2 are non-public, and
Kong protects **both correctly**. Absence-recall could only ever measure 0/2.

Worse, the first attempt (E8) reported a "missing authz finding" that did not exist: the prober was
hitting the app's direct publish port and therefore probing **around** the control it was testing
(decision 0010 puts authorization enforcement at Kong).

## Decision

**Take every authorization verdict at the ENFORCEMENT POINT, and report the defence-in-depth posture
as the finding.**

- **Enforcement-point judging.** Verdicts come from the gateway, with a **live authenticated identity**
  (`agent-recon` OAuth2). The app origin is consulted only to refine severity. If the enforcement
  origin is unreachable the run **errors** — it never judges from the app origin. This makes E8's class
  of error structurally impossible.
- **The posture is the finding**:

  | gateway | app origin | verdict |
  |---|---|---|
  | 403 (ACL denies a live identity) | 403 | defence in depth |
  | 403 | **2xx** | **gateway-only enforcement → FINDING** — single point of failure: SSRF, a misrouted internal call, or any direct-to-app path defeats all authorization |
  | 2xx | 2xx | authorization missing entirely (none observed here) |

- **Two independent canaries, both fail-closed.** A **session canary** (an endpoint the ACL is known to
  permit) must return 2xx with the minted token before any verdict is trusted — without a live identity
  every reply is 401 and every endpoint would look protected, the silent-failure mode observed in a
  third-party tool (E11). A **synthetic canary** (an unrouted path) must classify `not-routed` every
  run — synthetic on purpose, because a canary that is a real finding stops firing the moment the system
  is fixed.
- **No LLM in the verdict path.** The mapper imports no model surface and makes no model call; a test
  asserts this structurally. That is the enforceable form of "no LLM may remove a finding" — a component
  that never consults a model cannot be argued out of a finding by one.
- **Evidence is redacted at capture** (`agent.trace.redact_persisted`) and artefacts are gitignored.

## Measured result

Against the pinned Juice Shop through Kong, as `agent-recon`, both canaries passing:

- 4 public routes: gateway **200** — the ACL permits the identity, as intended.
- 1 route (`/api-docs/swagger.json`): HTML/SPA fallback → **inconclusive**, never counted as evidence.
- **2 of 2 non-public routes** (`/rest/user/whoami`, `/rest/admin/application-version`): gateway **403**
  (the ACL correctly denies a live identity) but the app answers **200** directly →
  **gateway-only enforcement**.

**Finding: 100% of this application's non-public gateway-routed endpoints have no authorization of
their own.** Kong is a single point of failure for authorization; any path that reaches the app
directly — SSRF, a container-network foothold, a misconfigured route — bypasses it entirely.

**Coverage bound (stated, not buried):** 8 routed endpoints out of a much larger application surface.
This result describes the gateway-fronted slice only and must never be read as whole-app coverage.

## Consequences

- The project has a genuine, reproducible pentest finding produced by its own tooling, with the
  evidence, the identity, and the coverage limit all recorded — and with the two canaries making a
  vacuous "clean" run impossible.
- Zero regressions (7 suites green); the change is additive (`evaluation/absence-detection/` + one test).
- **Deferred, each behind its own decision:** state-changing probes (decision 0016's five prerequisites
  are unaddressed; the Week-8 gate is simulation-only); true absence-recall (needs a target with
  genuinely broken authorization reachable through an enforcement point — Juice Shop's
  `/api/Challenges` `solved` flags are the right independent oracle when such a target is adopted);
  the LLM hypothesis layer (propose endpoints that *should* be routed but are not — measured against
  this frozen deterministic baseline); generalisation to a second application.
