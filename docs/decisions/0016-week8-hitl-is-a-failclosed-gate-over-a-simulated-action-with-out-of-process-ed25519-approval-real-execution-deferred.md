# 0016 Week-8 HITL is a fail-closed gate over a simulated action with out-of-process Ed25519 approval; real execution is deferred

Date: 2026-07-24

## Status

Accepted (Week-8 PR1 shipped — the gate + approval workflow; real state-changing execution deferred)

## Context

Week 8 is "HITL for High-Risk Actions": the Exploit agent must not execute a state-changing payload
without human approval. A four-lens red-team of the first plan (unanimous NOT CLEAN) proved the
naive "approve and execute the real payload" scope rested on five independent broken axes, verified
in code:

- **No runnable payload exists to approve.** `ExploitProposal` has no payload field; its narrative is
  scrubbed of runnable content by design (decisions 0013 / Week-7 E3). "Send exactly the approved
  payload" is impossible without reversing that containment.
- **Approvable ≠ executable endpoints.** Proposals come from read-only GET fuzz findings; the only
  wired write route is `POST /rest/basket` — disjoint. And that write needs a Juice Shop app session
  the gateway identity isn't, so it would 401.
- **The approval was self-forgeable.** A loopback approval endpoint in the agent's own runtime lets a
  prompt-injected agent POST its own Approve — the exact Week-7 threat.
- **Kong OSS has no OPA plugin** (Enterprise-only), so the chosen conditional-auth mechanism doesn't
  fit this stack.
- **Reversibility was illusory** (Juice Shop is `restart: unless-stopped`, no volume; only a full
  recreate resets; a mutation scanned before rollback would persist into the lake and break the CI
  gate).

## Decision

**Week-8 PR1 ships a genuine, non-theater HITL approval gate over a SIMULATED (dry-run) action;
real state-changing execution is deferred to a separate cycle with named prerequisites.**

- **The gate is structural + fail-closed.** The graph pauses at the `interrupt_seam`; the
  `state_change_node` runs only with a valid approval token and otherwise RAISES + AUDITS a refusal.
  The approved "action" is a dry-run (`SIMULATED: would execute …`, no gateway/network call, no
  target mutation) — so none of the five broken axes apply.
- **Approval is enforced OUT of the agent's runtime (anti-self-approval).** The token is
  Ed25519-signed; the agent/graph side (`agent/approval.py`) holds ONLY the public verify key — it
  has no private-key loader and no `.sign()` path, so a compromised runtime gains a verifier, not a
  signer. Minting lives solely in the human-run `agent/approve.py`, which the graph never imports and
  which takes the private key via a required `--key-file` supplied out-of-band. No private key is on
  any agent-readable path or committed.
- **The token binds the exact reviewed proposal** (id from code-derived facts + a content hash over
  every human-visible field), is single-use (atomic SQLite-nonce), TTL-bounded, and audited
  append-only BEFORE the action. An unapproved/forged/expired/replayed/tampered/mismatched token, and
  any approval-infra error, are all loud audited fail-closed refusals.
- **No OPA, no new IAM write identity, no write route** — deferred with real execution.

Honest residuals (documented, not solved — production answer = a separate approval user/service +
a WORM audit sink): on a single shared-user host a fully-compromised runtime could scrape an
out-of-band private key or rewrite the same-process SQLite audit ledger. Neither lets an unapproved
action RUN; the Ed25519 verify-only split is the right architecture on this host today.

**Deferred to a future real-execution cycle, each an explicit decision first:** a runnable-payload
artifact (reverses the E3/0013 non-execution containment), the write topology + a provisioned app
session, recreate-based reversibility + the lake/CI side-effect, OPA-on-Kong-OSS-or-fallback
infra-layer enforcement, and constraining the resume path to `resume_state_change` (the bare
`Command(resume={})` empty-map LangGraph quirk is fail-safe but must be closed by the real driver).

Full record + red-team/validate history:
`docs/plans/active/2026-07-24-no-issue-week8-hitl-high-risk-actions.md`.
