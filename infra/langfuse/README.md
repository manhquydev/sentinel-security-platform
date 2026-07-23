# Langfuse v3 — tracing backend for the Sentinel LLM gateway

Self-hosted Langfuse v3, standing up as the tracing sink the [LiteLLM
gateway](../litellm/README.md) already at `127.0.0.1:4000` will forward calls
to. Not yet wired into the gateway's callback config — this is the backend
definition and its validation. Bringing the stack up, and pointing the
gateway at it, is a separate, deliberate step.

Verified against **Langfuse `3.224.1`** (upstream's current `3` release as of
2026-07-23).

## Why six containers

Langfuse v3 split its v2 all-in-one Postgres into four stores with different
jobs, plus the two app processes that use them:

| Service | Job |
|---|---|
| `postgres` | Projects, users, API keys, config — low volume, transactional |
| `clickhouse` | Every trace/observation/score event — the high-volume analytical store |
| `redis` | The ingestion queue (BullMQ) between the API and ClickHouse writes |
| `minio` | S3-compatible store for large event and media payload bodies |
| `langfuse-web` | UI + API the gateway's SDK/callback talks to |
| `langfuse-worker` | Drains the Redis queue, runs ClickHouse migrations, writes events |

That footprint was presented to the operator and accepted knowingly before
this file was written — it is not a default that crept in.

## Bring-up and teardown

```bash
docker compose --env-file ../.env -f infra/langfuse/docker-compose.yml up -d
docker compose --env-file ../.env -f infra/langfuse/docker-compose.yml ps
curl -s http://127.0.0.1:3001/api/public/health
```

```bash
docker compose --env-file ../.env -f infra/langfuse/docker-compose.yml down
# add -v to also drop the five named volumes and lose all traces permanently
```

**Resource cost, stated plainly:** six containers, one of them (ClickHouse)
memory-hungry even at rest and slow to become ready on first boot (its
healthcheck allows a 60s start period). Expect on the order of 1–2 GB RSS
across the stack once warmed, more under sustained trace ingestion, plus disk
growth in `langfuse-clickhouse-data` and `langfuse-minio` proportional to
scan volume — this store is designed to keep every prompt/response body, not
sample them. Budget against the host's ~19 GB RAM / ~57 GB disk headroom
before bringing this up alongside the other ~20 containers already running.

## Environment contract

All required variables use `${VAR:?message}` — the stack refuses to start
with a message naming the missing variable rather than booting half-secured.
Report these to whoever owns [`infra/.env.example`](../.env.example); this
file does not add to it directly.

| Variable | Required | Purpose |
|---|---|---|
| `LANGFUSE_DB_USER`, `LANGFUSE_DB_PASSWORD` | yes | Bundled Postgres (projects/users/keys). Discrete, so the password never rides inside a DSN — same reasoning as `infra/litellm`. |
| `LANGFUSE_CLICKHOUSE_USER`, `LANGFUSE_CLICKHOUSE_PASSWORD` | yes | ClickHouse account for the event store. |
| `LANGFUSE_REDIS_PASSWORD` | yes | Auth for the ingestion queue. Must not point at a cluster-mode Redis — see *Known operational hazards*. |
| `LANGFUSE_MINIO_ROOT_USER`, `LANGFUSE_MINIO_ROOT_PASSWORD` | yes | MinIO root credential, reused as the app's S3 access key/secret (matches upstream's own default of the two being equal). |
| `LANGFUSE_SALT` | yes | Password-hashing salt. Generate with `openssl rand -hex 32`. |
| `LANGFUSE_ENCRYPTION_KEY` | yes | Encrypts stored API keys and integration secrets at rest. Must be 64 hex chars (32 bytes) — `openssl rand -hex 32`. Rotating without escrowing the old value makes anything encrypted under it unreadable. |
| `LANGFUSE_NEXTAUTH_SECRET` | yes | Signs the web UI's session cookies. `openssl rand -hex 32`. |
| `LANGFUSE_NEXTAUTH_URL` | no, default `http://localhost:3001` | Must agree with whatever URL the operator's browser uses to reach the UI. |
| `LANGFUSE_TELEMETRY_ENABLED` | no, default `false` | Upstream defaults this `true`; flipped here — see *Security posture*. |

## Security posture

This store holds the gateway's traces: every prompt and completion body sent
through `infra/litellm/`, which by construction includes source code and
attacker-controlled content pulled from scanned targets. It is treated the
same as the gateway's own key store: **it never leaves the host.**

- Every service except `langfuse-web` publishes **no port at all** — Postgres,
  ClickHouse, Redis, and MinIO are reachable only over this stack's own
  `langfuse-net` compose network, from `langfuse-web` and `langfuse-worker`.
  This is a deliberate departure from upstream's own reference compose, which
  publishes ClickHouse (`8123`/`9000`), Redis (`6379`), and MinIO
  (`9090`/`9091`) on loopback "for convenience." That convenience is not worth
  it for a store built specifically to hold attacker-controlled content.
- `langfuse-web` binds `127.0.0.1:3001` only. Nothing outside this host can
  reach the UI or the API it exposes to the gateway's SDK.
- **Consequence of the MinIO decision:** media/image attachment previews in
  the Langfuse UI are fetched by the *browser* directly from MinIO via a
  presigned URL. With no MinIO port published, there is no such URL the
  browser can resolve, so those previews will not load. Trace text — the
  prompts and completions that matter for this gateway's use case — is
  unaffected: it flows through the web API and ClickHouse, never
  browser-to-S3 directly.
- `LANGFUSE_TELEMETRY_ENABLED` defaults `false` here (upstream default:
  `true`). Usage telemetry is not trace content, but a store built to keep
  target-derived data local has no reason to phone home from a stack you
  cannot see the payload of before it leaves.

## A Langfuse outage must never fail an LLM call

Tracing is best-effort, not a dependency. Wire the LiteLLM callback so a
Langfuse ingestion failure — connection refused, 5xx, timeout — is logged and
swallowed, never raised back into the gateway's request path. The gateway's
job is serving the LLM call; observability of that call is secondary and
must not be able to take the primary path down with it. This is a property
the gateway operator can rely on once the callback is wired, not an
aspiration — verify it as part of that integration, not here.

## Obtaining the public/secret key pair

The LiteLLM callback needs a **project** API key pair (`pk-lf-...` /
`sk-lf-...`), which does not exist until a project exists:

1. Bring the stack up and open `http://127.0.0.1:3001`.
2. Sign up the first user (this is a fresh instance — there is no seeded
   admin). Create an organization, then a project (e.g. `sentinel-gateway`).
3. **Project → Settings → API Keys → Create new API keys.** The secret key
   is shown once at creation; store it the same way `infra/.env` values are
   stored, not in a ticket or chat log.
4. Feed `pk-...` / `sk-...` into the LiteLLM callback config as its own
   variables when that integration is wired — they are separate from every
   variable in the table above, which only configures Langfuse's own
   infrastructure.

For unattended re-provisioning (e.g. after a `down -v`), Langfuse supports
headless init via `LANGFUSE_INIT_ORG_ID`, `LANGFUSE_INIT_PROJECT_ID`,
`LANGFUSE_INIT_PROJECT_PUBLIC_KEY`, `LANGFUSE_INIT_PROJECT_SECRET_KEY`, and
related `LANGFUSE_INIT_USER_*` variables read by `langfuse-web` at boot. Not
wired into this compose file — YAGNI until a re-provisioning workflow
actually needs it — but available upstream if that changes.

## Known operational hazards

Upstream's own self-hosting guidance calls these out as the most common
compose-deployment problems. What to check for each, against this stack:

**ClickHouse read-only mode.** ClickHouse marks a table read-only when it
cannot complete a write — most commonly the data volume filling up. Single
node here, so there is no Keeper/ZooKeeper quorum to lose either.
Check `docker exec sentinel-langfuse-clickhouse df -h /var/lib/clickhouse`
and the container's logs for `Table is in readonly mode` before assuming an
application bug. The `user: "101:101"` pin in the compose file exists because
a mismatched UID between the container process and the mounted volume is the
next most common cause — the account can not write to its own data
directory. Do not run this service as root to "fix" a permission error; fix
the volume ownership instead.

**Redis cluster errors.** Langfuse's queue issues multi-key BullMQ
operations that require every key to land in the same hash slot, which only
holds on a single Redis node. Pointing `REDIS_HOST`/`REDIS_PORT` at a
cluster-mode Redis (including cluster-mode managed services) produces
`CROSSSLOT Keys in request don't hash to the same slot` from the worker at
startup or on first job. This compose ships a single, non-clustered Redis —
if that ever changes, cluster mode is not a supported substitution.

**Postgres auth failures.** `DATABASE_URL` is assembled here from
`LANGFUSE_DB_USER`/`LANGFUSE_DB_PASSWORD`, the same two variables that
configure the `postgres` service itself, so the common failure mode of "app
credentials drifted from the database's own" cannot happen from `.env`
alone. It can still happen if the volume already holds data initialized
under different credentials (e.g. after manually editing `.env` post
first-boot) — Postgres does not re-apply `POSTGRES_PASSWORD` to an existing
data directory. If auth fails after a credential change, either restore the
original password or start from a fresh `langfuse-db` volume.

## Topology

`langfuse-web` and `langfuse-worker` call inward to their four stores only;
neither calls the router, a scanned target, or any other Sentinel stack. This
stack joins none of `dd-net`, `juice-net`, or `litellm-net` — it gets its own
`langfuse-net`.

## Pinned images

| Component | Image | Digest |
|---|---|---|
| `postgres` | `postgres:17-alpine` | `sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193` |
| `clickhouse-server` | `clickhouse/clickhouse-server:25.8.28-alpine` | `sha256:f40cd6034fb8c54dce6a85338750fbad79f387e2705e1991a85f2e7086b5b9ea` |
| `redis` | `redis:7.4-alpine` | `sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99` |
| `minio` | `minio/minio:RELEASE.2025-09-07T16-13-09Z` | `sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e` |
| `langfuse` (web) | `langfuse/langfuse:3.224.1` | `sha256:576132f792276d07380f46a6958877a38a51d20a94e42fa9b3cb096d76db1d9c` |
| `langfuse-worker` | `langfuse/langfuse-worker:3.224.1` | `sha256:d517aad54f7030a104b6e32c52bbd998cae7e12777d23eb9cdbc9ed3f1a1fdf9` |

The `redis:7.4-alpine` digest is identical to the one pinned in
`infra/defectdojo/docker-compose.yml` — same tag, same manifest, resolved
independently.

**MinIO's upstream project archived its GitHub repository on 2026-04-25.**
`RELEASE.2025-09-07T16-13-09Z` is the last official tag published before
that; there has been no newer official release to pin since. This is
recorded here rather than silently pinned, because it changes the answer to
"how do we take a security patch to this component" — there may not be one
from upstream going forward. Revisit the S3-compatible store choice if that
matters more than it does today.

Tags are informational; the digests are the pin. For an air-gapped
deployment, mirror these six digests into a local registry — nothing else is
pulled at runtime.
