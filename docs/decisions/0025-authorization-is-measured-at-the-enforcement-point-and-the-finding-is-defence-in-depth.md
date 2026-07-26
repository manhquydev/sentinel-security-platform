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
  (the ACL correctly denies a live identity) but the app answers **200** directly. On direct-to-app inspection:
  * `/rest/admin/application-version` discloses a real value (`{"version":"20.1.1"}`) → **gateway-only enforcement** (**FINDING**)
  * `/rest/user/whoami` discloses an empty structure (`{"user":{}}`, 11 bytes, no protected data) → **app-withholds-payload** (not a bypass; control exists)

**Finding: 1 of 2 non-public gateway-routed endpoints discloses protected data without authorization of
its own.** `/rest/admin/application-version` is a real gateway-only enforcement gap; `/rest/user/whoami`
is protected by the gateway but the app withholds sensitive data if reached directly, so no bypass exists
on that path. Kong is a single point of failure for the one genuine case; any path that reaches the app
directly — SSRF, a container-network foothold, a misconfigured route — on that endpoint bypasses all
authorization.

**Coverage bound (stated, not buried):** 8 routed endpoints out of a much larger application surface.
This result describes the gateway-fronted slice only and must never be read as whole-app coverage.

## Correction (2026-07-26, same day) — "read-only" was false, and the reserved oracle is contaminated

A second red-team lens proved that **GET is not side-effect-free on this target**. Juice Shop writes a
`solved` flag to its database when certain endpoints are merely fetched, and this project's own probes
had already flipped three:

| challenge flipped | triggered by |
|---|---|
| `securityPolicyChallenge` | our GET `/.well-known/security.txt` (in the routed surface) |
| `exposedMetricsChallenge` | our GET `/metrics` (in the routed surface) |
| `errorHandlingChallenge` | the E9 verbose-error probe |

Two consequences, both corrected rather than argued away:

1. **The "read-only, nothing mutated" claim in the probers was false** and is retracted in the source.
   The honest statement: the runs are **state-perturbing**, bounded by the target's *disposability*,
   not by the HTTP verb. HEAD-first is explicitly rejected as a mitigation — Express runs the same
   handler for HEAD, so it would be safety theatre.
2. **The `/api/Challenges` oracle this decision reserved for future absence-recall work is already
   contaminated** — it is ground truth the prober did not author, but not one it cannot influence. Any
   future use must restart the container first (Juice Shop re-seeds on start) and snapshot the
   solved-set around each run.

The mapper now **measures** this instead of denying it: the solved-set is captured before and after
every run and the diff published (`target_state_change.flipped_by_this_run`). The latest run flipped
nothing new and reported the 3 pre-existing flags on entry.

## Correction (2026-07-26) — the "100% disclose" claim overstated by not measuring response substance

An independent code review + re-measurement revealed the classifier had measured response *status* alone,
never checking whether a 2xx response actually *carried* protected data or was an empty shell:

**Original claim:** "100% of this application's non-public gateway-routed endpoints have no authorization
of their own."

**What was actually measured:** Two endpoints both answered 200 when the gateway answered 403:
- `/rest/admin/application-version` → `{"version":"20.1.1"}` (real data disclosed)
- `/rest/user/whoami` → `{"user":{}}` (empty structure; no protected data in the payload)

**Why the instrument produced the wrong claim:** the classification logic treated any non-HTML 2xx response
as "app open", without checking whether the response body had any substance. Empty responses were counted
as bypasses when they should have counted as "app withholds by returning emptiness instead of 401".

**Corrected finding:** 1 of 2 non-public routed endpoints discloses protected data to a direct-to-app
path. The second is defended at *both* layers — the gateway denies it and the app itself returns nothing —
so it is the opposite of the single-point-of-failure the original claim asserted. The
`gateway-only-enforcement` verdict for `/rest/admin/application-version` stands and is a genuine finding.
`/rest/user/whoami` is now correctly classified as `app-withholds-payload`: the control is real, it just
signals refusal through emptiness rather than through a 401 status.

**Instrument fix:** The mapper now applies the `_has_substance()` structural check (parse JSON, search for
any non-empty leaf value) before classifying a 2xx response as disclosure — see `_has_substance` in
`evaluation/absence-detection/map_defence_in_depth.py`, with the empty-shell and real-payload cases both
asserted by `tests/defence-in-depth-test.sh` (DD9) so this cannot silently regress.

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
