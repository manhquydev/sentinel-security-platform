# 0008 Kong fronts the app; LiteLLM fronts the model

Date: 2026-07-24

## Status

Accepted

## Context

Week 2 of the brief requires routing all staging-application traffic through an API Gateway
(it names Kong and Tyk) and giving AI agents a scoped identity. The repo already has a gateway
— the LiteLLM proxy from Week 1 — and the tempting shortcut is to treat "the gateway" as one
thing and bolt agent authorization onto LiteLLM.

That conflates two planes that answer different questions. LiteLLM sits on the **egress** path
to the model: it labels provenance, redacts secrets, and audits what this host sends to a
third-party router ([decision 0006](0006-the-gateway-labels-provenance-it-does-not-detect-injection.md)).
The Week-2 gateway sits on the **ingress** path to the app: it decides whether an agent has
earned access to a given endpoint. The data each sees is disjoint — LiteLLM sees prompts and
model choices; the app gateway sees HTTP method, path, consumer identity. Coupling them would
entangle their failure modes: a broken ACL rule (agent cannot reach the app, fail-closed, safe)
and a broken redaction rule (agent leaks PII to a model, a data breach) are different severities
that must be reasoned about independently.

Gateway product choice was researched (Kong / Tyk / Envoy+ext_authz / APISIX) against this
repo's constraints: self-hosted, loopback-only, docker-compose, declarative/reviewable-in-git,
per-consumer path/method authorization, and audit logging that fits the redaction posture.

## Decision

**Two orthogonal gateway planes. Kong OSS is the app-ingress plane; LiteLLM remains the
LLM-egress plane. They share no data and no failure mode; they may later share a central audit
sink.**

Kong OSS specifically, over the alternatives:

- **vs Tyk** — Kong's declarative-config tooling and deployed base in security-critical systems
  are stronger; Tyk's native per-route policy is cleaner out-of-box but the ecosystem is smaller.
- **vs Envoy + ext_authz** — Envoy is the lowest-lock-in option but pushes all authorization
  into a separate authz service to build and operate; too much setup tax for Week 2's boundary,
  which is expressible natively.
- **vs APISIX** — technically comparable (native OPA plugin, clean declarative CLI); Kong wins
  on maturity and troubleshooting references for a substrate later phases depend on.

Kong runs in DB mode (the `oauth2` plugin is stateful), loopback-only, TLS-only proxy, managed
by a committed declarative policy rendered from env secrets.

## Alternatives Considered

1. **Extend LiteLLM to authorize app calls.** Rejected: LiteLLM is not on the app path and does
   not see app requests; it would require reimplementing a reverse proxy inside the egress plane.
2. **One unified gateway for both planes.** Rejected: entangles disjoint concerns and failure
   modes, per Context.

## Consequences

Positive:

- Each plane is independently reasoned about, tested, and failed-closed.
- The app-ingress substrate is standard and well-documented for the later fuzzing/exploit work.

Tradeoffs:

- A second stack (Kong + its Postgres) to run and keep pinned.
- Two audit streams to eventually converge on a shared sink.

## Follow-Up

- Converge Kong's audit stream and LiteLLM's egress audit onto one sink when the HITL gate
  (Week 8) needs a single view of agent behavior.
