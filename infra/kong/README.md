# Kong app-ingress gateway (Week 2)

The plane that gives AI agents a **scoped identity in front of the staging app**. Kong
fronts the digest-pinned OWASP Juice Shop; an agent authenticates with the OAuth2
client-credentials grant, receives a short-TTL bearer token, and reaches only the app
endpoints its ACL group permits.

This is **orthogonal to `infra/litellm`** (the LLM-egress plane). Kong answers *"did this
agent earn access to this app endpoint?"*; LiteLLM answers *"does this model call leak PII
or carry injection risk?"*. They share no data and no failure mode
([decision 0006](../../docs/decisions/0006-the-gateway-labels-provenance-it-does-not-detect-injection.md)
frames the split).

## Authorization model

- **Authentication** — OAuth2 client-credentials. Each agent is a Kong Consumer with an
  `oauth2` credential (`client_id` + secret). It mints a 5-minute bearer token. No shared
  static token; the identity is per-agent and expiring.
- **Charter testing-tool key** — the two dedicated Charter gateway paths require
  `X-Sentinel-API-Key` as well as the executor's OAuth2 identity. A high-priority
  route guard verifies and removes the header before OAuth, proxying, or audit
  logging; this also covers requests that fail OAuth. The exact executor paths
  are `/sentinel-charter/rest/products/search` and
  `/sentinel-charter/rest/basket`; Kong rewrites them to Juice Shop's normal
  `/rest/...` paths only after both credentials and ACLs pass. Other agent
  identities cannot use this key.
- **Authorization** — Kong **ACL groups per route**, fail-closed. A Consumer reaches a route
  only if it belongs to that route's `allow` group. This is the whole enforcement surface.
- **The ACL group names are the scoping vocabulary**, mirroring the Week-1 attack-surface
  auth taxonomy so Week 2 authorizes exactly the boundaries Week 1 mapped:

  | ACL group | Endpoints (from the attack-surface baseline) | `agent-recon` holds it? |
  |---|---|---|
  | `read-public` | `/rest/products/search`, `/.well-known/security.txt`, `/api-docs/swagger.json`, `/metrics`, `/robots.txt` | yes |
  | `read-authenticated` | `/rest/user/whoami` | no (needs an app session — later) |
  | `read-admin` | `/rest/admin/application-version` | **no** |
  | `write-basket` | `POST /rest/basket*` | **no** (HITL, Week 8) |

- **No OAuth2 `scopes`.** Kong OSS does not bind a scope to a consumer — any authenticated
  client can mint a token for any listed scope, and the plugin does not re-check a token's
  scope against the route. A scope claim would advertise a permission the gateway does not
  enforce, so scoping lives entirely in the ACL groups, which *are* per-consumer and *are*
  enforced.

`agent-recon` is the Week-4 Recon agent's identity (public read only). `probe-admin` is a
deliberately privileged consumer used only as the test's positive control — it proves the
admin route is live, so `agent-recon`'s 403 is a real authorization decision, not a dead route.

`sentinel-charter-executor` is a separate local operator consumer with `charter-read` and
`write-basket`. Its OAuth secret and `SENTINEL_CHARTER_EXECUTOR_API_KEY` belong only to
`scripts/sentinel-charter-executor.py`, never an agent or supervisor. Kong authenticates that
trusted executor and enforces routes; the executor's SQLite state plus an Ed25519 human-decision
envelope enforce approval. Kong is not an approval-capability service.

## Bring-up (local)

Prerequisites: the Juice Shop harness up (it owns the `juice-net` bridge Kong joins), Docker
Compose, and Kong secrets set in the git-ignored `infra/.env` (see `infra/.env.example`:
`KONG_DB_USER/PASSWORD`, `KONG_PROVISION_KEY`, `AGENT_RECON_SECRET`, `PROBE_ADMIN_SECRET`,
`SENTINEL_CHARTER_EXECUTOR_SECRET`, and `SENTINEL_CHARTER_EXECUTOR_API_KEY`).

```bash
# 1. Juice Shop harness (publishes 127.0.0.1:13000, creates juice-net)
docker compose -f infra/harness/juice-shop.compose.yml up -d

# 2. Render the declarative policy from the template + infra/.env (secret-bearing, gitignored)
bash infra/kong/render-config.sh

# 3. Bring up the gateway (db -> migrations -> config-import -> kong)
docker compose --env-file infra/.env -f infra/kong/docker-compose.yml up -d

# 4. Prove the authorization boundary
REQUIRE_KONG=1 bash tests/gateway-authz-test.sh
```

Mint a token and call the app:

```bash
set -a; . infra/.env; set +a
TOKEN=$(curl -sk -X POST https://127.0.0.1:18443/oauth/oauth2/token \
  -H 'Content-Type: application/json' \
  --data "{\"client_id\":\"agent-recon\",\"client_secret\":\"$AGENT_RECON_SECRET\",\"grant_type\":\"client_credentials\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl -sk https://127.0.0.1:18443/rest/products/search?q=apple -H "Authorization: Bearer $TOKEN"      # 200
curl -sk https://127.0.0.1:18443/rest/admin/application-version -H "Authorization: Bearer $TOKEN" -o /dev/null -w '%{http_code}\n'  # 403
```

## Changing the policy

Edit `kong.declarative.yml.tmpl` (the reviewable source of truth), then rebuild from a clean
DB:

```bash
bash infra/kong/render-config.sh
docker compose --env-file infra/.env -f infra/kong/docker-compose.yml down -v
docker compose --env-file infra/.env -f infra/kong/docker-compose.yml up -d
```

The full `down -v && up` is deliberate, for two independent reasons:

1. **`db_import` is upsert-only — it never deletes.** It adds and updates entities but leaves
   ones absent from the file in place, so it *cannot revoke*: dropping a consumer's group or a
   route from the template and re-importing leaves the old grant live. Only a rebuild on an
   empty DB applies removals.
2. **A live `db_import` does not propagate to a running node** — it writes straight to the DB
   without the cache-invalidation events an Admin-API write emits — which is why Kong is booted
   against an already-seeded DB rather than reconfigured in place.

A partial `up --force-recreate kong-config kong` can *add* policy but silently fails to revoke,
and re-importing into a populated DB is not exercised; treat `down -v && up` as the only
supported change path.

## Ports and security posture

- **`127.0.0.1:18443`** — TLS proxy (the only sanctioned app path for agents). TLS-only; the
  plaintext `:8000` listener is deliberately absent.
- **Admin API — not published.** It binds the container's own loopback (`127.0.0.1:8001`
  inside the container) and is reachable only via `docker exec sentinel-kong curl
  http://127.0.0.1:8001/...`. Kong OSS has no admin auth and the API returns the provision key
  and client secrets in cleartext, so it is kept off the host entirely rather than exposed on
  host loopback where a local uid or an SSRF pivot from a `0.0.0.0`-bound neighbour could reach
  it.
- The Kong database publishes no port; it is reachable only over `kong-net`.
- Images pinned by `@sha256`. Secrets come from `infra/.env`; the committed template holds
  only `${PLACEHOLDER}`s, and the rendered file is git-ignored.
- **Audit trail** — the `file-log` plugin emits one structured JSON line per request to the
  container stdout (captured by the Docker logging driver). `hide_credentials` strips the
  bearer token before proxy and before logging, so no token or provision key reaches the
  audit stream (`tests/gateway-authz-test.sh` asserts their absence).

### Disclosed residuals (not deferred silently)

- **Direct app bypass.** Juice Shop is still published on `127.0.0.1:13000` for the Week-1
  DAST harness, so an on-host process can skip the gateway. The gateway is the *sanctioned*
  path and enforcement on it is proven; removing the direct publish is a follow-up that would
  touch the DAST harness.
- **Self-signed TLS.** Kong auto-generates its default cert; clients use `--insecure` on
  loopback. No private key on the host filesystem.
- **Auth server is Kong itself** (oauth2 plugin issuing tokens), not a dedicated AS. Migration
  trigger: >5 agents or Week 7. Kong OSS's unauthenticated admin API is the main reason to move
  to a dedicated AS with real admin authz for any multi-tenant deployment.
