# DefectDojo data lake — standup

Project Sentinel Week 1, plan-02 P1. DefectDojo is the multi-source aggregation
point that native scanners (P3) and the CI orchestrator (P4) import into.

Verified against **DefectDojo 3.1.200** (open source) on 2026-07-23.

## Layout

```
infra/
  .env.example              committed template
  .env                      real secrets, gitignored, 0600
  defectdojo/
    docker-compose.yml      5 long-running services + one-shot initializer
    README.md               this file
  defectdojo-db/
    docker-compose.yml      external postgres, separate lifecycle
    pg_hba.conf             TLS-only client authentication
    certs/                  generated, gitignored
scripts/
  dd-gen-keys.sh            print fresh key material
  dd-gen-db-certs.sh        local CA + postgres server cert
  dd-boot-guard.sh          refuses public/absent crypto keys, runs before Django
  dd-entrypoint.sh          app entrypoint wrapper (guard -> upstream entrypoint)
  dd-pg-entrypoint.sh       postgres entrypoint wrapper (stages TLS material)
  dd-bootstrap.sh           seed hierarchy, issue scoped CI token
  dd-smoke.sh               acceptance checks
  dd-backup.sh              dump + escrow, and the deep restore drill
```

## Bring-up

```bash
cp infra/.env.example infra/.env
scripts/dd-gen-keys.sh              # paste the output into infra/.env
chmod 600 infra/.env

scripts/dd-gen-db-certs.sh          # local CA + server cert
docker network create dd-net

docker compose --env-file ../.env -f infra/defectdojo-db/docker-compose.yml up -d
docker compose --env-file ../.env -f infra/defectdojo/docker-compose.yml up -d

scripts/dd-bootstrap.sh             # prints the CI token exactly once
scripts/dd-smoke.sh                 # must exit 0
```

UI/API: <http://localhost:8080> (loopback only — see *Network exposure*).

## Ports on this host

`5432`, `5433`, `55432` were already taken by unrelated stacks, so the database
publishes on **`127.0.0.1:55433`**. nginx publishes on **`127.0.0.1:8080`**.
Inside `dd-net` the database is plain `dd-postgres:5432`.

## Database is external on purpose

The app stack has no postgres service. `docker compose down` on
`infra/defectdojo/` cannot take the data with it, and repointing at a managed
host later is an `.env` change rather than a compose rewrite.

The app connects with **discrete** `DD_DATABASE_*` variables, never
`DD_DATABASE_URL`: a DSN carries the password inside a URL that surfaces in
tracebacks, `docker inspect`, and celery logs.

### TLS

`sslmode=verify-full`. DefectDojo's `DATABASES` dict has no `OPTIONS` key
(`settings.dist.py:379-390`), so TLS cannot be configured through any `DD_*`
variable. It is set through libpq's own `PGSSLMODE` / `PGSSLROOTCERT`, which
covers both the ORM and `manage.py dbshell` — the latter being what upstream's
`docker/reach_database.sh` uses for its readiness probe, so the readiness wait is
itself TLS-verified.

`pg_hba.conf` accepts `hostssl` only and explicitly rejects `hostnossl`, so a
misconfigured client fails with a clear error instead of silently downgrading.

Certificate SANs cover `dd-postgres` (in-network) and `localhost` / `127.0.0.1`
(host-side backups). Regenerating certs invalidates the trust anchor of a running
stack — `dd-gen-db-certs.sh` refuses to overwrite without `--force`.

## Boot guard

`dd-boot-guard.sh` runs as the first command of every Django container's
entrypoint, **before Django is imported**. Placement is the control: a process
that reaches Django settings has already decrypted stored credentials with
whatever key it was handed, so a post-boot assertion would only detect the
problem. It exits 78 on a key that is unset, empty, shorter than 16 characters,
or equal to a value published in the DefectDojo repo — including the in-code
fallbacks `""` and `"."` (`settings.dist.py:157-158`) and both compose defaults.
It also refuses `DD_DEBUG != False`.

## Migrations

Owned by the one-shot `initializer` service, gated by
`service_completed_successfully`. Neither the app nor either celery container can
race it or leave a half-applied migration after a crash-loop.

## Authorization — read this before wiring CI

**The open-source build has no role-based access control.**
`dojo/authorization/authorization.py` states that the hierarchical roles
(Reader / Writer / Maintainer / Owner / API_Importer) were moved to the `dojo-pro`
plugin. The `Role` and `Product_Member` tables still exist but are never
consulted, and `/api/v2/roles/` and `/api/v2/product_members/` return **404**.

Open-source resolution order:

| Condition | Result |
|---|---|
| superuser | everything |
| `Delete` or `StaffOnly` action | requires `is_staff` |
| `View` / `Edit` / `Add` / `Import` | `is_staff`, else membership in the object's `authorized_users` chain |

So the CI account is a **non-superuser, non-staff** user added to
`Product.authorized_users` for one product. Measured behaviour of that token:

| Action | Result |
|---|---|
| `POST /api/v2/import-scan/` | **201** |
| `GET` product / engagement / findings in scope | 200 |
| `DELETE` a finding | **403** |
| `DELETE` the product | **403** |
| any other product | invisible (404) |

This is a *smaller* residual than the role model would have given: delete is
impossible without `is_staff`, so a leaked CI token cannot destroy the lake.
Reading findings remains inherent to the grant, so **redaction (P3) is still the
control that keeps secrets out of what this token can read.**

`dd-bootstrap.sh` fails closed if the account is staff/superuser, or if it holds
any grant beyond the single product.

## Broker: redis, not valkey

Upstream's compose pins `valkey 9.1.0`. **It does not work here.** With valkey the
celery worker connects, logs `ready`, registers every task, and answers
`inspect ping` and `active_queues` claiming to consume `celery` — but it never
issues a `BRPOP` against the task queue. Only the pidbox (control) channel is
polled. Measured: queue depth climbed 13 → 53 with zero consumption, no error in
any log, `blocked_clients: 1`.

Same image, same broker URL, same worker command, `redis 7.4` instead:
`Task … received` → `Task … succeeded`, queue drains to 0.

This is not a dedup-only problem — **every** async path in DefectDojo runs through
celery (deduplication, notifications, product grading, jira sync). On valkey they
all silently do nothing while the UI looks healthy.

## Deduplication

**Deduplication is OFF in a fresh install.** `System_Settings.enable_deduplication`
defaults to `False` and **no `DD_*` environment variable can change it** — it is a
database field only. Until it is on, both dedup variables below are loaded and
validated but never consulted.

`dd-bootstrap.sh` turns it on. `dd-smoke.sh` asserts it, and — more importantly —
asserts the *behaviour*: it imports the same finding twice and requires the second
to come back flagged `duplicate`. That behavioural check is the only thing that
catches this class of failure. The config-only checks passed 22/22 while no
deduplication was happening at all.

Both variables are set together in `infra/defectdojo/docker-compose.yml`
(committed — this is reviewable policy, not a secret):

- `DD_DEDUPLICATION_ALGORITHM_PER_PARSER` selects the **strategy**
- `DD_HASHCODE_FIELDS_PER_SCANNER` selects **which fields the hash covers**

Setting only the first leaves DefectDojo's defaults in place, and those defaults
are not endpoint-based:

| Scanner | Upstream default | Set here |
|---|---|---|
| `ZAP Scan` | `title, cwe, severity` | `title, cwe, severity, endpoints` |
| `Nuclei Scan` | `title, cwe, severity, component_name` | `title, cwe, severity, endpoints` |
| `Trivy Scan` | `title, severity, vulnerability_ids, cwe, description` | `component_name, component_version, vulnerability_ids` |
| `Semgrep JSON Report` | *(no entry)* | `file_path, line` |
| `Generic Findings Import` | *(no entry)* | `title, cwe, severity, description` |

Per-key values **replace** the defaults rather than merging
(`settings.dist.py:1163-1177`). Keys must match a registered `scan_type` exactly;
a typo falls back silently, which is why `dd-smoke.sh` resolves every key against
`/api/v2/test_types/` and fails on an unknown one.

When `endpoints` participates, DefectDojo hashes
`DEDUPE_ALGO_ENDPOINT_FIELDS = ["host", "path"]` (`settings.dist.py:1276`).
**P3's redaction must preserve host and path** and redact only credential values —
otherwise the hash moves every run and the lake inflates instead of deduplicating.

## Backup and the restore drill

```bash
scripts/dd-backup.sh            # dump + escrow metadata
scripts/dd-backup.sh --drill    # also rehearse the restore
```

Each dump gets a `.meta.json` recording the sha256 of the dump and the
**fingerprint** of the AES key in force (sha256 of the key, never the key). A dump
restored under a rotated key produces rows that are present, well-formed, and
permanently unreadable, so the fingerprint is what makes that failure obvious
before the restore instead of after.

`--drill` restores into a throwaway database, boots the application against it,
and asserts a planted canary credential decrypts back to its known plaintext. A
row count would prove neither integrity nor recoverability.

The canary is written through `dojo_crypto_encrypt()` and read back through
`prepare_for_view()`. This detail is the difference between a real check and a
rubber stamp: **assigning `Tool_Configuration.api_key` directly stores
plaintext**, because encryption lives in the form layer rather than the model's
`save()`. A plaintext canary "decrypts" under any key, so the drill would pass
even after a key rotation destroyed real credentials. `dd-backup.sh` refuses to
proceed if it finds the canary stored in plaintext.

Verified both directions on 2026-07-23: stored ciphertext is `AES.2:…`
(AES-256-GCM), the correct key yields `DRILL_RESULT=OK`, and a randomly
generated key yields `DRILL_RESULT=MISMATCH`.

Ownership: with the current self-managed postgres container this script owns
backups and should run from cron. Against a managed host, the provider owns
snapshots and their cadence must be documented — but the drill stays here.

## Secret rotation (90 days)

`DD_SECRET_KEY` and `DD_CREDENTIAL_AES_256_KEY` rotate on a 90-day cadence.
Rotating the AES key **without escrowing the previous version breaks every dump
taken under it**. Escrow the old key alongside its dumps before rotating.

The CI token can be rotated with `POST /api/v2/users/{id}/reset_api_token/`.

## nginx and stale upstream addresses

nginx resolves the `uwsgi` hostname once at startup and caches the address in its
workers. If uwsgi is replaced and gets a different container IP, nginx keeps
proxying to the old one and every request returns **502 indefinitely** — the app
is healthy, only nginx is looking in the wrong place.

`depends_on: uwsgi: {restart: true}` handles the normal path: editing config and
running `docker compose up -d` makes compose recreate uwsgi and then restart
nginx for it. Verified — nginx's `StartedAt` ends up after uwsgi's.

It does **not** cover replacing the container outside compose
(`docker rm dd-uwsgi` then `docker compose up -d uwsgi`): compose sees nginx
already running and leaves it alone. Measured, with uwsgi forced onto a new IP:
nginx stayed on the old address and served 502 until restarted. If you take that
path, follow it with:

```bash
docker restart dd-nginx
```

## Network exposure

nginx binds `127.0.0.1` only. Whether a CI runner needs to reach this instance —
and therefore whether it must listen on a routable address — is still an open
question in plan-02. Until it is answered, loopback is the safe default.

## Pinned images

| Component | Digest |
|---|---|
| `defectdojo-django` | `sha256:166d484b855105e18c033c1bf4dfc80a0aac9d1d54f54e122a86c9728400fbc3` (3.1.200) |
| `defectdojo-nginx` | `sha256:1c2b8efc3b2309b0592288e57bcce9a11ff35bb50673317b232496793b6fff7c` (3.1.200) |
| `postgres` | `sha256:1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa` (18.4-alpine) |
| `redis` | `sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99` (7.4-alpine) |

Tags are informational; the digests are the pin. Valkey rather than redis is
upstream's own broker choice for 3.x — the URL scheme stays `redis://` because
valkey is protocol-compatible.

For an air-gapped deployment, mirror these four digests into a local registry;
nothing else is pulled at runtime.
