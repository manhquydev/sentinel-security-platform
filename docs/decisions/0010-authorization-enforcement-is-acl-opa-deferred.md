# 0010 Authorization enforcement is Kong ACL; OPA is deferred until policy becomes conditional

Date: 2026-07-24

## Status

Accepted

## Context

The research brief for Week 2 recommended Kong + an external policy engine (OPA) for
fine-grained authorization. OPA is a real, durable capability: Rego policies are reviewable in
git and can encode conditional rules (environment, template whitelists, HITL) that a static
allow-list cannot. The question was whether to adopt it now.

The Week-2 requirement is exactly "consumer may reach route A, not route B" — a static,
per-consumer, per-route allow decision. Kong's ACL plugin expresses that natively and
fail-closed, and it is proven doing so ([decision 0009](0009-agent-iam-is-oauth2-identity-with-acl-authorization.md)).
OPA's value appears only when the decision becomes **conditional** on request content or
runtime state, which no Week-2 endpoint requires. Adopting OPA now would add a second policy
engine and its sidecar for a rule ACL already enforces — speculative complexity against YAGNI.

## Decision

**Authorization enforcement is the Kong ACL plugin. OPA is deferred, and adopted only when a
policy decision must be conditional — not on a schedule.**

The adoption trigger is explicit so the deferral is a decision, not an omission: introduce OPA
when the first authorization rule cannot be expressed as a static per-consumer/per-route allow.
Concretely, that is expected at:

- **Week 5 (LLM-guided fuzzing)** — bounding *which* payloads/templates a scan scope permits,
  not merely which route.
- **Week 8 (HITL)** — a state-changing call is allowed only *after* a human approval exists,
  a runtime condition ACL cannot represent.

Until then, ACL groups are the whole enforcement surface, and the group vocabulary already
mirrors the attack-surface auth taxonomy.

## Alternatives Considered

1. **Adopt OPA now.** Rejected: no Week-2 rule needs a conditional decision; it would add an
   engine for a policy ACL already enforces. Recorded with a trigger rather than dropped, so the
   capability is adopted deliberately when its first real use arrives.
2. **A custom Kong plugin for scope/path checks.** Rejected: reinvents ACL for the static case
   and OPA for the conditional case, with none of either's review story.

## Consequences

Positive:

- The smallest enforcement surface that satisfies the requirement, fully tested and fail-closed.
- OPA arrives with a concrete first policy to justify it, not as scaffolding.

Tradeoffs:

- When the conditional case lands, both Kong wiring and a Rego policy layer must be introduced
  together; the ACL groups become the coarse layer beneath OPA's conditional rules.

## Follow-Up

- At the Week-5/Week-8 trigger, add OPA as a Kong plugin, keep ACL as the coarse allow layer,
  and record the policy-versioning location (same repo as the Kong policy).
