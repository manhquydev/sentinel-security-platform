# Execution Plan: Week-2 API Gateway + Agent IAM

Date: 2026-07-24

## Status

Active

## Outcome

All agent→staging-app traffic is forced through a self-hosted API gateway that gives every
AI agent a **scoped, non-human identity** instead of a shared static token. An agent can reach
exactly the endpoints its scope permits and no others — proven both ways: a read-scoped agent
reaches a public read endpoint and is refused an administrative one, with no token refused
outright.

Completion is observable when, against the live digest-pinned Juice Shop:

- every request to the app is reachable only via the gateway (the app is not independently
  published for agents to bypass);
- an agent authenticates with the OAuth2 client-credentials grant and receives a short-TTL
  bearer token carrying its granted scope;
- a `read:public`-scoped token is granted `GET /rest/products/search` (200) and refused
  `GET /rest/admin/application-version` (403);
- a request with no token, an expired token, or a tampered token is refused (401);
- the gateway config is fully declarative and reviewable in-repo (no click-ops), and applying
  it from a clean state reproduces the same policy;
- gateway access logs record who called what, with agent secrets/tokens never written in
  clear; and
- a behavioral test suite asserts each of the above with a negative control proven to fail.

## Non-goals (this cycle)

- No production/company replica — Juice Shop stays the staging target.
- No live agent code (Recon/Fuzz agents are Week 4+). Week 2 delivers the identity+authz
  substrate and proves it with a scripted client, not an LLM.
- No OPA policy engine yet (see decision on deferral); no external auth server (Keycloak/Dex).
- No HITL approval gate (Week 8); state-changing scopes are defined but granted to no agent.
- WebGoat is not fronted (no pinned runtime — same asymmetry disclosed in Week 1).

## Context

- Predecessor: Week-1 lake + AI-security foundation (complete, verified live this session —
  see `plans/reports/scout-260724-0139-week1-state-vs-charter.md`).
- The LiteLLM gateway (Week 1) fronts **model calls** (egress), not the app. This plan adds
  the **app-ingress** plane. The two are orthogonal (decision 0006 framing; new decision
  records the separation).
- Grounding artifact: the Week-1 **attack-surface baseline**
  (`attack-surface/baselines/juice-shop-df1b6bbd8bce.json`) already classifies each endpoint
  by `auth_class` (public / authenticated / administrative / hypothesis) and `state_change`
  (read-only / state-changing). **Agent scopes derive from that taxonomy** rather than being
  invented — Week 2 authorizes exactly the boundaries Week 1 mapped.
- Research brief: `plans/reports/researcher-260724-0139-week2-api-gateway-agent-iam.md`
  (Kong + OAuth2 client-credentials + scoped identity; MCP/A2A are discovery/delegation
  frameworks, not authorization engines — enforcement is the gateway's job).
- Live constraints: loopback-only, fail-closed posture; Juice Shop on network `juice-net`
  (service `juice-shop:3000`), published only on `127.0.0.1:13000`. Free host ports confirmed.

## Decisions (recorded on proof, not before)

To be promoted to `docs/decisions/` once validated live:

- **Kong OSS is the app-ingress gateway.** Declarative (decK) config, Docker-Compose, huge
  operational base, no control-plane lock-in. Runner-up APISIX is technically close; Kong's
  maturity/reference base wins for a security-critical substrate later phases build on.
- **Agent IAM = OAuth2 client-credentials grant + scopes derived from the attack-surface
  auth taxonomy.** Standards-aligned (MCP/A2A defer to OAuth 2.1); short TTL bounds blast
  radius; identity is a real issued token, not a shared secret.
- **Authorization enforcement = Kong ACL groups per route, OPA deferred.** The Week-2
  requirement ("reach path A not path B") is exactly consumer→route authorization, which Kong
  ACL expresses natively and reviewably. OPA is adopted only when policy becomes *conditional*
  (environment / template-whitelist / HITL) — recorded with that explicit trigger so the
  deferral is a decision, not an omission.

## Approach

**Scope model (from the attack-surface auth taxonomy):**

| auth_class / state_change | ACL group | OAuth2 scope | Granted to a scanner agent? |
|---|---|---|---|
| public, read-only | `read-public` | `read:public` | yes |
| authenticated, read-only | `read-authenticated` | `read:authenticated` | later (needs app session) |
| administrative, read-only | `read-admin` | `read:admin` | **no** |
| state-changing | `write-basket` (example) | `write:basket` | **no** (HITL, Week 8) |

**Phase 1 — Gateway stands up, loopback-only, in front of the app.**
Kong (DB mode — the `oauth2` plugin is stateful) on `juice-net`, proxying to `juice-shop:3000`.
Proxy on `127.0.0.1` only; admin API on `127.0.0.1` only (never `0.0.0.0`). Proxy served over
TLS (self-signed, loopback) because Kong's oauth2 plugin refuses plaintext — and "route all
traffic through the gateway" should mean an encrypted edge. Declarative config via decK.

**Phase 2 — Identity + scopes.**
Consumers: one per agent (`agent-recon`) plus a `probe-admin` consumer that *does* hold
`read-admin`, so the boundary is proven from both sides. oauth2 credentials per consumer;
client-credentials token endpoint enabled. ACL membership assigns each consumer only its
granted groups.

**Phase 3 — Routes + per-route authorization.**
A service for Juice Shop; routes for the representative endpoints from the baseline, each
carrying (a) the `oauth2` plugin (authenticate) and (b) the `acl` plugin (`allow` = the group
that endpoint requires). Fail-closed: unknown/no token → 401; authenticated-but-wrong-group →
403.

**Phase 4 — Audit logging.**
Kong `file-log` (or http-log) capturing method, path, consumer, status. Assert tokens and
client secrets are not emitted in clear — consistent with the redaction-first posture.

**Phase 5 — Prove it.**
`tests/gateway-authz-test.sh`: token issuance; read-public→200 on a read route; read-public→403
on the admin route; no-token→401; expired-token→401; and a negative control (a deliberately
mis-scoped grant) observed failing first. A `scripts/`/`infra` helper reproduces config apply
from clean.

**Phase 6 — Review, audit, fix, document.**
Code review + a security audit (STRIDE on the new ingress plane: token leakage, admin-API
exposure, SSRF via the proxy, bypass by direct app access). Apply findings. Promote the three
decisions once proven. Update README/AGENTS/scanners docs where user-visible. Move the four
completed Week-1 plans to `docs/plans/completed/`.

## Risks And Recovery

- **Kong oauth2 plugin requires HTTPS / DB.** Mitigated by loopback TLS + Kong-DB in compose;
  if the image is unpullable on this host (a known residual class — decision 0005), fall back
  to a pinned mirror or document the block rather than fake it.
- **App-bypass risk:** Juice Shop is still published on `127.0.0.1:13000`, so an agent on this
  host could bypass the gateway. For Week 2 the gateway is the *sanctioned* path and the test
  proves enforcement on it; fully removing the direct publish is noted as a follow-up (it would
  break the existing DAST harness that targets `127.0.0.1:13000`). Disclosed, not hidden.
- **Self-signed TLS** means clients skip verification locally; acceptable loopback-only, noted.
- **Recovery:** the stack is additive (new `infra/kong/`, new test, new docs). Nothing in the
  Week-1 lake/scanner path is modified, so Week-1 suites must stay green as the regression net.

## Validation

- Focused: `tests/gateway-authz-test.sh` with the negative control failing first.
- Regression: the Week-1 suites stay green (lake, redaction, allowlist, gateway-guardrails).
- Live proof recorded in the Result section: the exact 200/403/401 transcript.

## Progress

- [x] Phase 1 — gateway up, loopback-only, fronting the app over TLS (Kong 3.9.3 + Postgres,
      TLS-only proxy on `127.0.0.1:18443`, joins `juice-net`, boots against a seeded DB).
- [x] Phase 2 — consumers (`agent-recon`, `probe-admin`), oauth2 client-credentials, ACL membership.
- [x] Phase 3 — routes + per-route oauth2 (authn) + acl (authz). Boundary proven live.
- [x] Phase 4 — audit: file-log JSON to stdout; `hide_credentials` keeps token/secret out (asserted).
- [x] Phase 5 — `tests/gateway-authz-test.sh` (29/0), static checks proven non-vacuous, clean
      `down -v && up` reproduces the policy deterministically.
- [x] Phase 6 — two-reviewer pass (correctness + STRIDE), fixes applied and re-verified,
      decisions 0008–0010 promoted, docs written, Week-1 plans archived.

## Result

**Complete, verified live from a clean boot.** `tests/gateway-authz-test.sh` = **29 passed /
0 failed**, stable across two runs; Week-1 suites unchanged (redaction 43, allowlist 9,
workflow-safety 17, litellm-gateway 31, verify-lake 12). Proven behaviours on the running
gateway: `agent-recon` reaches `GET /rest/products/search` (200), is refused
`GET /rest/admin/application-version` (403) and `POST /rest/basket` (403); `probe-admin`
reaches admin (200, positive control proving the route is live); no/bogus token = 401; the
audit stream carries no bearer token, provision key, or client secret.

### Review findings that changed the build (provenance)

Two parallel reviewers ran the cook pipeline's review+audit. A self-run adversarial probe and
the STRIDE audit **independently found the same critical defect**:

- **CRITICAL — ACL escape via the token route (fixed).** The token route matched a broad
  `/oauth` prefix with no ACL on the app's service, so an authenticated agent could proxy
  arbitrary paths past every per-route ACL (`POST /oauth/rest/basket` and
  `/oauth2/token/rest/basket` reached Juice Shop). Fixed by anchoring the route to a regex
  matching *only* the mint endpoint (`~/oauth/oauth2/token$`); the bypass paths now 404 while
  mint still works. A negative regression probe was added to the suite.
- **HIGH — unauthenticated admin API (closed).** Kong OSS's admin API returns the provision key
  and client secrets in cleartext and has no auth. It was published on host loopback where a
  local uid or an SSRF pivot from a `0.0.0.0`-bound neighbour could reach it. Now bound to the
  container's own loopback and **not published**; verified unreachable from the host.
- **HIGH — `db_import` is upsert-only, not a "full reconcile" (fixed docs).** Re-importing never
  deletes, so it cannot revoke a grant. The false compose comment was corrected and the README's
  change workflow is now `down -v && up`, the only path that applies revocations.
- **MEDIUM ×2 — two static test assertions passed vacuously** (loopback-port grep skipped
  `0.0.0.0` bindings; the token-route ACL check grepped a string that never existed). Both
  rewritten to parse YAML and **proven to fail on bad input**.
- **MEDIUM — direct upstream bypass (disclosed residual).** Juice Shop is still on
  `127.0.0.1:13000` for the Week-1 DAST harness; an on-host process can skip the gateway. The
  gateway is the sanctioned path and enforcement on it is proven; network-isolating the upstream
  behind Kong is a follow-up before the adversarial-agent phases.

Full audit: `plans/reports/security-audit-260724-0139-week2-kong-gateway.md`. Research that
grounded the design: `plans/reports/researcher-260724-0139-week2-api-gateway-agent-iam.md`.

Move to `docs/plans/completed/` once the direct-upstream residual is either closed or formally
accepted for the cycle.

## Open questions

- Remove the direct `127.0.0.1:13000` publish once DAST is re-pointed through the gateway?
  (Follow-up; would tighten bypass posture but touches the Week-1 harness.)
- Move to a dedicated auth server (Keycloak/Dex) — trigger recorded at >5 agents or Week 7.
