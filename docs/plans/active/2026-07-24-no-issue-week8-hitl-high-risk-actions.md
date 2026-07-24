# Execution Plan: Week-8 Human-in-the-Loop (HITL) for High-Risk Actions (TDD)

Date: 2026-07-24

## Status

Active — red-team done (4/4 lenses, unanimous NOT CLEAN → real-execution scope broken on 5+ axes);
user RE-SCOPED to a genuine HITL gate over a SIMULATED action with out-of-process approval. Remaining
before cook: reconcile the body to the re-scope (below), validate. The Outcome/Scope/TDD/Design
(W8-D1…D6) sections below are the PRE-red-team maximal draft — SUPERSEDED by "Re-scoped PR1" +
the Red Team Review; the re-scope is authoritative.

## Re-scoped PR1 (accepted by user 2026-07-24 — authoritative)

**Deliverable:** a real, non-theater HITL approval gate on the existing `interrupt_seam`, over a
SIMULATED (dry-run) state-changing action. Satisfies the charter's "cannot execute without approval"
without the broken real-execution machinery (no runnable payload exists; approvable≠write endpoints;
Kong OSS has no OPA; reversibility illusory — all deferred to a future resolved-blockers cycle).

- **RD1 — Approval is enforced OUT of the agent's runtime (fixes self-approval, red-team F4).** The
  approval token is **asymmetrically signed**: the human/approver holds the private signing key
  (supplied out-of-band, never written to an agent-readable path); the agent/graph holds only the
  **verify** key. The `state_change_node` verifies the token's signature — it physically cannot mint
  one. Honest residual (documented): on a single shared-user host a fully-compromised agent runtime
  could scrape an interactively-supplied secret; the durable production answer is a separate approval
  service/user (recorded, not solved here). A separate approval CLI (`approve.py`, human-run) mints
  the token; the agent never runs it.
- **RD2 — The action is SIMULATED.** On a valid approval the `state_change_node` performs a dry-run
  (records "would execute <proposal>", NO target mutation, NO gateway/network call). So no
  payload-provenance, endpoint-disjoint, 401, or reversibility problem exists.
- **RD3 — Fail-closed via the token + seam.** The graph pauses at `interrupt_seam`; resume requires a
  valid, single-use, proposal-bound, signed token. No token → refuse. No OPA, no new IAM identity,
  no real write route (all deferred).
- **RD4 — Exactly-once + audit (red-team C3/H1/H4).** The token is single-use, consumed atomically;
  the `state_change_node` is separate + idempotent (LangGraph re-runs a node on resume); the audit
  (proposal→approver→decision→simulated-action) is append-only and written so a crash cannot leave an
  action unrecorded. Token binds to the proposal id + content hash + a TTL; replay/tamper/stale refused.
- **RD5 — Minimal deps, loopback only (red-team M1/H3).** No FastAPI/OPA; the approval CLI + a
  file/SQLite store on loopback; no external egress. ONE vetted new dep: `cryptography==49.0.0` (for
  the Ed25519 verify-only token, RD1) — validated 2026-07-24 to resolve against `rag/.venv` pins with
  no conflict (pulls only cffi/pycparser).

### Re-scoped invariants (HA1–HA5; tests-first)
- **HA1** resume WITHOUT a valid signed token → refused (fail-closed); with a valid token → proceeds to
  the simulated action (negative control).
- **HA2 (anti-self-approval)** using ONLY what the agent runtime holds (the verify key + env), a forged
  token is rejected — the agent cannot mint approval. 
- **HA3** token is single-use (replay refused), proposal-bound (tampered proposal refused), TTL-bounded
  (stale refused).
- **HA4** the action is simulated (assert NO target mutation / no network from the node); the
  decision+approver+timestamp are audited append-only before the simulated action.
- **HA5** the approval surface is out-of-process + loopback; no external egress; existing suites green.

Deferred to a future cycle (explicit decisions required first): a runnable-payload schema field
(reverses E3/D3), the write topology + Juice Shop app-session, recreate-based reversibility + the
lake/CI side-effect, and OPA-or-fallback infra-layer enforcement.

## Outcome

The Exploit agent can perform a **real state-changing action against the loopback target ONLY after a
recorded human approval**, enforced structurally (fail-closed) — the charter's "cannot execute
without approval." A self-hosted approval surface drives the LangGraph `interrupt()`/`Command(resume)`
already built in Week 6; a new scoped IAM identity + policy gate refuses any unapproved state-change;
every action is audited and reversible. Observable when:

- an unapproved state-changing action is **refused by construction** (no valid approval token → the
  policy gate + scoped identity deny it; negative control: an approved one proceeds);
- the graph pauses at the seam with the `ExploitProposal` (payload + justification), a human
  Approve/Reject is recorded via the self-hosted endpoint, and only then does `Command(resume)`
  release exactly the approved action — nothing else;
- the approved action executes via a **new, fail-closed, scoped `agent-exploit` identity** (write-*
  groups) — NOT `agent-recon`'s read-only scope — against the loopback deliberately-vulnerable target;
- every proposal→approver→decision→action→result is written to an **immutable audit trail**, and a
  **reversibility rehearsal** (rollback script / container teardown) restores target state;
- nothing (payload, justification, approval) egresses off-host (air-gap preserved);
- every invariant has a behavioural test with a negative control; existing suites stay green.

## Context

- Charter: `docs/Project_Sentinel_VinUni_x_VinSOC_12-week.md` (Week 8; skill S8). "Slack/Teams bot" is
  an example — the air-gap posture makes it a Week-11+ option, not Week 8.
- Ready seams: `agent/supervisor.py` `interrupt_seam_node` (tested, inert, gated on
  `pending_state_change`); `agent/exploit.py`/`agent/schema.py` `ExploitProposal`
  (`verdict="suspected-needs-hitl"` — the object a human approves).
- Decisions this inherits/triggers: 0013 (state-change RESERVED for Week-8 HITL — crossed here,
  gated), 0009 (Agent IAM: `write-*` groups defined but UNGRANTED — granted here to a new identity),
  0010 (OPA is triggered at Week 8 for conditional auth), 0006 (provenance), 0012.
- Kong app-ingress gateway `infra/kong/` (currently GET-only via `agent/gateway.py`); a state-changing
  action goes through Kong with the new identity + the policy gate.
- Research: `plans/reports/researcher-260724-1643-week8-hitl-state-and-options-report.md`.

## User decisions (advise, 2026-07-24)

1. Execution = **REAL** state-changing payload against the loopback target, reversible, behind the gate.
2. Approval channel = **self-hosted endpoint** (local FastAPI + SQLite → `interrupt()`/`Command(resume)`);
   no external SaaS.
3. Enforcement gate = **OPA per decision 0010, Phase-0 spike-gated**; fallback = scoped identity +
   in-agent capability gate.

## Design decisions (research + brainstorm, 2026-07-24)

- **W8-D1 — Approval is a structural precondition, not a prompt.** The state-changing node cannot run
  without a valid, single-use approval token bound to that exact `ExploitProposal` (id + payload
  hash). No token → fail-closed refusal at the policy gate AND the scoped identity. An LLM/agent
  cannot self-approve.
- **W8-D2 — A new fail-closed scoped identity `agent-exploit`.** Distinct from `agent-recon`
  (read-only): its own OAuth2 client + the `write-*` ACL groups (0009), granted ONLY the specific
  state-changing routes the approved action needs, loopback-only. `agent-recon` is never widened.
- **W8-D3 — OPA at Kong (0010), spike-gated.** Phase 0 proves OPA+Kong runs air-gapped + fits the
  shared infra; OPA authorizes the state-changing route ONLY with a valid approval token
  (defense-in-depth over the ACL). On spike failure: an in-agent capability gate + the scoped
  identity + a Kong route-scoped ACL provide the fail-closed control (the durable invariant holds
  either way; the mechanism is what the spike decides).
- **W8-D4 — Self-hosted approval service, loopback-bound.** FastAPI + SQLite approval store on
  127.0.0.1; presents the proposal, records Approve/Reject + approver + timestamp, mints the
  single-use token, and drives `Command(resume)`. Auth on the endpoint; no external egress.
- **W8-D5 — Immutable audit + reversibility.** Append-only audit of every proposal/decision/action/
  result (redacted per Week-6). Real execution is bounded (loopback, one approved payload, scoped
  identity) and reversible: a rollback script or disposable-container teardown, REHEARSED in a test.
- **W8-D6 — Payload provenance stays honest.** The approved payload is the human-reviewed
  `ExploitProposal` content; the state-change node sends exactly that, no LLM re-generation between
  approval and execution (the human approved a specific action, not a class).

## Scope (phased PRs)

- **Phase 0 (spike, hard gate):** OPA+Kong air-gap/fit + the state-changing route topology; confirm a
  disposable/reversible execution target. On OPA misfit → the fallback gate (W8-D3).
- **PR1 — Approval workflow, no real execution yet.** Self-hosted approval service (W8-D4) + the HITL
  gate on `interrupt_seam` (proposal → endpoint → recorded decision → `Command(resume)`); single-use
  token bound to the proposal; audit trail. The resumed action is a SIMULATED stub. Proves the gate +
  workflow structurally before any real payload flies.
- **PR2 — Real scoped execution behind the gate.** The `agent-exploit` identity (W8-D2) + OPA policy
  or fallback gate (W8-D3); a state-change node that sends the approved payload to the loopback target
  via the new identity ONLY with a valid token; reversibility (W8-D5).
- **PR3 — E2E + air-gap audit + reversibility rehearsal + measurement + docs/decision record.**
Out of scope: production targets, non-loopback egress, Slack/Teams (Week 11+), Week-9 PII, vLLM.

## TDD Approach (tests-first; per PR; each through implement → code-review → STRIDE audit → fix → re-verify)

- **PR1 (HA1–HA4):** HA1 a state-changing resume WITHOUT a valid single-use token bound to the exact
  proposal is refused (negative control: with a valid token it resumes); HA2 the token is single-use
  (replay refused) + bound to the proposal's payload hash (a tampered payload refused); HA3 the
  approval decision + approver + timestamp are recorded immutably before resume; HA4 the approval
  endpoint is loopback-bound + no external egress.
- **PR2 (HB1–HB4):** HB1 the `agent-exploit` identity can reach ONLY its granted write route(s), and
  `agent-recon` still cannot (scope isolation); HB2 the state-change node executes ONLY the approved
  payload (payload-hash match) and nothing on reject; HB3 the policy gate (OPA or fallback) denies the
  route without a valid approval token even if the identity is presented (defense-in-depth); HB4 a
  reversibility rehearsal restores target state (proven, not asserted).
- **PR3 (HC1–HC2):** HC1 full E2E — proposal → human approve → scoped real execution → audited →
  rolled back — over loopback; HC2 an air-gap audit asserts no payload/justification/approval left the
  host. Consolidated measurement (unapproved-refused rate, approved-only-after-decision).

## Risks And Recovery

- **REAL exploitation blast radius (the crux).** Contained: loopback-only + deliberately-vulnerable
  DISPOSABLE target; a NEW scoped fail-closed identity (never `agent-recon`); the policy gate + token
  are fail-closed (no token → no action); one approved payload per token; reversibility REHEARSED in a
  test (rollback/teardown), not merely claimed. Recovery: teardown restores the pinned target; the
  audit trail reconstructs what ran.
- **A gate bug = unapproved mutation.** Two independent controls (scoped identity + policy gate/OPA),
  both fail-closed; HA1/HB3 assert refusal from each side; the token binds to the exact payload hash.
- **OPA infra misfit / air-gap.** Phase-0 hard gate before any OPA code; fallback preserves the
  invariant without OPA.
- **Approval endpoint as a new attack surface.** Loopback-bound + authenticated; no external egress;
  approval is single-use + proposal-bound so a stale/forged approval can't release an action.
- **Additive**: new approval service + scoped identity + state-change node + policy + audit; Weeks 1–7
  unchanged except the interrupt_seam gains its real consumer (backward-compatible: no token ⇒ inert).

## Progress

- [x] Scout Week-8 state + research synthesis.
- [x] Advise decisions (real execution / self-hosted channel / OPA spike-gated) — user, 2026-07-24.
- [x] Plan red-team (4/4 lenses, unanimous NOT CLEAN) → user re-scoped → validate + consistency → CLEAN.
- [x] Re-scoped PR1 (HITL gate over a SIMULATED action; out-of-process Ed25519 approval; HA1–HA5) —
  DONE. Implement (agent stalled mid-run → recovered: ran the tests it never reached, diagnosed the
  one real defect HA1 = a LangGraph empty-`Command(resume={})` gotcha, fixed via `resume_state_change`)
  → code-review SHIP-READY + STRIDE audit 0-Crit/0-High (anti-self-approval verified SOUND) → fixed
  (bind `expected_impact`; audit infra-error refusals; document the key-scrape + ledger-rewrite
  residuals). Suites: week8-hitl 9/0, syndicate 30/0, recon 10/0, egress 12/0. Decision 0016.
- [ ] PR1 commit.
- [ ] DEFERRED (future cycle, explicit decisions first): real execution — payload artifact
  (reverses E3/D3), write topology + Juice Shop app-session, recreate-based reversibility + lake/CI
  side-effect, OPA-on-Kong-OSS-or-fallback infra enforcement.

## Decisions

- 2026-07-24: User decisions 1–3 + design W8-D1…D6.

## Validation

- Focused: HA1–HA4, HB1–HB4, HC1–HC2, each with a negative control.
- Integration/e2e: bounded live approve→scoped-execute→audit→rollback over loopback.
- Repo-required: existing suites green; target state restored after each run.

## Red Team Review

### Session — 2026-07-24 (3 of 4 lenses; Failure-Mode pending, adds reversibility/atomicity detail,
does not change the verdict). **Verdict: NOT CLEAN — the real-execution scope is broken on five
independent axes.** Reports: `plans/reports/redteam-260724-1647-week8-{scope-complexity,security-adversary,assumption-destroyer}.md`.

| # | Finding (converged across lenses) | Sev | Disposition |
|---|-----------------------------------|-----|-------------|
| 1 | **No runnable payload to approve/execute.** `ExploitProposal` has no payload field; `technique` is scrubbed of runnable content (E3/D3, `schema.py:158-168`, `exploit.py:63-91`). "Approve+send the payload" is impossible without reversing E3/D3 or post-approval synthesis (breaks W8-D6; human approves a description, not the concrete payload). | Crit (unanimous) | **Accept** — blocks real execution |
| 2 | **Approved-endpoint vs write-route disjoint.** Proposals come from read-only GET fuzz findings; the only write route is `POST /rest/basket`. No proposal can target it → the Recon→Fuzz→Exploit→Execute loop can't produce an approvable executable action (degrades to a hand-scripted demo). | Crit | **Accept** — blocks real execution |
| 3 | **Fail-closed is single-control + self-approvable.** Kong ACL is a static unconditional allow (one control, not two); the loopback approval endpoint runs IN the agent's runtime → a prompt-injected agent can POST its own Approve + self-resume (F4). HITL = theater without OUT-OF-PROCESS approval + OPA-deny-on-error. | Crit | **Accept** — even the simulated gate must fix this |
| 4 | **OPA doesn't fit Kong OSS air-gapped.** Kong OSS has no OPA plugin (Enterprise-only); community Lua plugin needs baking into the pinned image + an OPA sidecar. The chosen enforcement (OPA-at-Kong) is blocked on this stack. | High | **Accept** — drop OPA; the control is the out-of-process token + interrupt seam |
| 5 | **The write POST likely 401s** (needs a Juice Shop app session, not the Kong identity); **reversibility is coarse** (only `down && up` teardown; no per-action undo; identity grant/revoke needs a full rebuild). | High/Med | **Accept** — real execution needs an app-session + accepts coarse teardown |
| 6 | Real execution reverses the exploit agent's structural non-execution guarantee (E1), unflagged; FastAPI/audit are gold-plating (stdlib + Kong file-log suffice). | High/Med | **Accept** — needs an explicit decision record; use stdlib/CLI + scope the audit |

**Verified holds:** LangGraph `interrupt/Command(resume)` works (keep `state_change_node` separate +
idempotent — resume re-executes top-down); `write-basket` grantable; loopback posture intact; the
`interrupt_seam` is ready (~80% of the honest deliverable already built).

### Honest re-scope (proposed, pending user Decision)
Week-8 deliverable = **PR1: the HITL approval workflow + a fail-closed gate over a SIMULATED action**,
with the non-negotiable fix that **approval is enforced OUT of the agent's runtime** (a separate
process / human-only secret the agent can't read) so it can't self-approve. The fail-closed control
is the out-of-process single-use token + the interrupt seam (the agent physically cannot resume
without an externally-minted token) — no OPA. This satisfies the charter ("cannot execute without
approval") with a genuine, non-theater gate. REAL execution is deferred to a separate cycle that
first resolves, as explicit decisions: the payload artifact (a new schema field — reverses E3/D3),
the write topology + app-session (finding-2/5), and coarse teardown-only reversibility.

## Validation Log

### Session — 2026-07-24
Validated the re-scoped PR1 (RD1–RD5) after the user's re-scope. Findings, resolved:

| # | Checked | Result | Resolution |
|---|---------|--------|------------|
| V1 | RD1 anti-self-approval needs asymmetric (verify-only) crypto | `cryptography` NOT in `rag/.venv`; stdlib has no asymmetric primitive (HMAC verify implies sign) | add `cryptography==49.0.0` — resolver-verified to coexist with rag pins (cffi/pycparser only) |
| V2 | langgraph `interrupt`/`Command(resume)` available | VERIFIED importable (langgraph 1.2.9) | keep `state_change_node` separate + idempotent (resume re-executes top-down) |
| V3 | anti-self-approval on a single shared-user host | PARTIAL — a fully-compromised agent runtime could scrape an out-of-band-supplied private key on a single-user host | documented honest residual (RD1); durable production answer = separate approval user/service; the Ed25519 verify-only design is the right architecture + best available on this host |

**Consistency:** the pre-red-team maximal Outcome/Scope/TDD/W8-D* sections are explicitly marked
SUPERSEDED by "Re-scoped PR1"; the re-scope is authoritative. No unresolved contradictions.

## Result

**Plan CLEAN** (red-team 4/4 → user re-scoped → validate + consistency, no contradictions). Cleared
to cook **PR1 only**: the HITL approval gate over a SIMULATED action, out-of-process Ed25519 approval
(RD1), fail-closed via token+seam (RD3), single-use/idempotent/audited (RD4), stdlib+`cryptography`
loopback (RD5). Invariants HA1–HA5, tests-first, through the cook loop. Real execution + its
prerequisites (payload artifact, write topology/app-session, reversibility, OPA/fallback) stay
DEFERRED to a future cycle with explicit decisions.
