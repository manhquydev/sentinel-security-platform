# 0009 Agent IAM is OAuth2 identity with ACL authorization; scopes are not enforced by Kong OSS

Date: 2026-07-24

## Status

Accepted

## Context

The brief asks for "Agent IAM ... not standard user tokens ... strictly scoped permissions
(e.g., allowed to query `/api/users` but not `/api/admin`), using MCP/A2A." Two things had to
be pinned down without building on a misconception.

**What MCP/A2A actually mandate.** Research against the specs (MCP authorization finalized
Apr 2025; A2A under the Linux Foundation, Jun 2025) shows neither defines an authorization
engine. MCP defers to OAuth 2.1 for transport-level auth (RFC 9728 resource metadata + token
acquisition) and treats scopes as opaque strings whose meaning is the resource server's job.
A2A is capability discovery (Agent Cards) + JSON-RPC routing and leaves credential/permission
enforcement to implementers. So "Agent IAM using MCP/A2A" means: OAuth2 for identity, and a
gateway for the authorization those specs deliberately do not provide.

**What Kong OSS actually enforces.** The obvious reading — issue each agent a scoped JWT and let
the gateway enforce the scope per route — does not hold on Kong OSS. Its `oauth2` plugin lets
any authenticated client mint a token for any scope in the service's `scopes` list, and it does
not re-check a token's scope against the route it hits. Verified live: `agent-recon` could mint
a token labelled `read:admin` even though it must never reach the admin route. A scope claim
here would therefore advertise a permission the gateway does not enforce.

## Decision

**Agent identity is OAuth2 client-credentials; agent authorization is Kong ACL groups per route.
No OAuth2 scopes are declared, because Kong OSS does not bind them to a consumer.**

- Each agent is a Kong Consumer with an `oauth2` credential. It mints a **5-minute** bearer
  token via the client-credentials grant — a per-agent, expiring identity, not a shared static
  token. `hide_credentials` keeps that token off the proxied request and out of the audit log.
- Authorization is the **ACL plugin, fail-closed**, attached to every resource route; a Consumer
  reaches a route only if it is in that route's `allow` group. The token mint route carries no
  ACL so a token can be obtained.
- **The ACL group names are the scoping vocabulary**, and they mirror the Week-1 attack-surface
  auth taxonomy (`read-public`, `read-authenticated`, `read-admin`, `write-basket`) so Week 2
  authorizes exactly the boundaries Week 1 mapped. `agent-recon` holds only `read-public`.

Proven live from a clean boot: `agent-recon` read = 200, admin = 403, state-change = 403;
`probe-admin` admin = 200 (positive control proving the route is live); no/bogus token = 401.

## Alternatives Considered

1. **Scoped JWTs enforced at the gateway.** Rejected on Kong OSS: scopes are not consumer-bound
   and not re-checked per route, so the claim would be unenforced and misleading. Revisit if the
   auth server moves to a dedicated AS that mints consumer-bound scoped tokens.
2. **Static per-agent API keys.** Rejected: no expiry, no standard scoping, higher blast radius —
   exactly the "standard token" the brief says to replace.
3. **mTLS client certs.** Deferred: strong for long-lived services but heavy cert lifecycle for
   agents that spawn per task; revisit for long-running agents.

## Consequences

Positive:

- Enforcement is a single, auditable, fail-closed mechanism (ACL membership) that actually holds.
- Nothing in the system advertises a permission it does not enforce.
- The authorization boundary is traceable back to the Week-1 attack-surface artifact.

Tradeoffs:

- The token is an opaque bearer identity, not a self-describing scoped JWT. When a dedicated auth
  server arrives, scope-in-token can be reintroduced **with** enforcement.
- Adding a new capability means editing both the route's ACL and the consumer's group membership.

## Follow-Up

- On moving to a dedicated auth server (trigger: >5 agents or Week 7), reintroduce consumer-bound
  scoped tokens and enforce scope per route, keeping ACL as defense in depth.
- Week 8 HITL gate consumes the `write-*` groups, which are defined here but granted to no agent.
