# Sentinel on GCP — Compute Engine deploy kit

Deploy the full **Charter** topology (Juice Shop + Kong + LiteLLM + Langfuse +
DefectDojo) to a single GCP Compute Engine VM that mirrors the local
docker-compose stack **1:1**. This is a parity deploy: same compose files, same
`scripts/sentinel-charter-up.sh`, so behaviour matches the graded local run.

## Why a VM (not Cloud Run)

The topology is multi-container, stateful (DefectDojo Postgres, Kong DB,
Langfuse ClickHouse/MinIO/Redis) and needs a private network for the
deliberately-vulnerable Juice Shop target. Cloud Run is stateless and
per-service — a poor fit. A VM reproduces the local environment exactly with the
lowest risk.

## Security posture — Juice Shop is never public

Every service publishes to `127.0.0.1` on the VM (verified in the compose
files): Juice Shop `:13000`, Kong `:18443`, LiteLLM `:4000`, Langfuse `:3001`,
DefectDojo `:8080`, DefectDojo DB `:55433`. The deploy creates **no firewall
rule that opens any app port**. The only inbound path is SSH — over IAP
(`35.235.240.0/20`) by default, or one operator CIDR. You reach the product
surface through an **IAP/SSH tunnel** to your own localhost. The vulnerable
target therefore has no route from the internet — consistent with Sentinel's
loopback/allowlist charter.

For an impressive but safe public demo, expose **only** a safe product surface
behind auth. This is now **implemented**: `app.vinsoc.manhquy.io.vn` →
Cloudflare Tunnel → **DefectDojo** (`:8080`, the OWASP findings dashboard),
gated by **Cloudflare Access** (email OTP). Juice Shop, Kong-internal, and the
databases stay private (loopback-only, not on the tunnel). See
[`../../docs/operations/live-deployment-guide.md`](../../docs/operations/live-deployment-guide.md).

### Metadata / service-account hardening

Vertex AI is reached via the mounted ADC file (`VERTEXAI_ADC_PATH`), not the VM's
attached service account — so the kit attaches **no service account** by default
(`config.env` leaves `SERVICE_ACCOUNT_*` blank → `--no-service-account
--no-scopes`). This stops the deliberately-vulnerable Juice Shop container from
minting a project-wide token via the GCP metadata server (SSRF blast radius). As
defense in depth, `remote-bootstrap.sh` installs a `sentinel-metadata-guard`
systemd unit that inserts a `DOCKER-USER` iptables DROP for container egress to
`169.254.169.254` (persisted across reboots). If a VM-side agent ever needs a
token, attach a **dedicated least-privilege** SA — never the default compute SA
with `cloud-platform`.

## Prerequisites (one-time)

`gcloud` must be installed and authenticated. On this machine it is **not yet
installed**:

```bash
sudo snap install google-cloud-cli --classic
gcloud init                       # pick account + project
gcloud auth login
gcloud auth application-default login
gcloud services enable compute.googleapis.com aiplatform.googleapis.com
```

Application secrets: `infra/.env` (from `infra/.env.example`) and DefectDojo
TLS certs under `infra/defectdojo-db/certs/` must exist locally. They are
transferred to the VM directly by `deploy.sh sync` — never committed to git.

## Deploy

```bash
cp infra/gcp/config.env.example infra/gcp/config.env
$EDITOR infra/gcp/config.env          # set PROJECT_ID, ZONE, service account, etc.

bash infra/gcp/deploy.sh preflight    # gcloud/auth/project/billing/APIs + local secrets
bash infra/gcp/deploy.sh provision    # firewall (SSH-only) + VM (idempotent)
bash infra/gcp/deploy.sh sync         # rsync repo + infra/.env + certs to the VM
bash infra/gcp/deploy.sh bootstrap    # install Docker + create dd-net on the VM
bash infra/gcp/deploy.sh up           # run scripts/sentinel-charter-up.sh on the VM
bash infra/gcp/deploy.sh status       # VM + container status

# or the whole chain:
bash infra/gcp/deploy.sh all
```

## Access the product surface

```bash
bash infra/gcp/deploy.sh tunnel
# then on your machine:
#   http://127.0.0.1:8080   DefectDojo
#   http://127.0.0.1:3001   Langfuse
#   http://127.0.0.1:13000  Juice Shop (target — view only)
#   https://127.0.0.1:18443 Kong TLS proxy
```

Run a live demo with `docs/operations/sentinel-charter-demo-runbook.md`.

## Vertex AI credential on the VM

`scripts/sentinel-charter-up.sh` requires `VERTEXAI_ADC_PATH` in `infra/.env` to
point at a readable ADC/service-account file. On the VM, either:

- **Recommended (least privilege):** attach a service account with
  `roles/aiplatform.user`, mount a short-lived key or ADC file, and set
  `VERTEXAI_ADC_PATH` to it; or
- run `gcloud auth application-default login` on the VM and point
  `VERTEXAI_ADC_PATH` at
  `~/.config/gcloud/application_default_credentials.json`.

Set `VERTEXAI_PROJECT` / `VERTEXAI_LOCATION` in `infra/.env` to your project and
Vertex region.

## Cost & teardown

An `e2-standard-4` VM with a 60 GB balanced disk runs on the order of a few USD
per day; stop it when idle (`gcloud compute instances stop`). Full teardown:

```bash
bash infra/gcp/deploy.sh teardown         # delete the VM
bash infra/gcp/deploy.sh teardown --all   # also delete the SSH firewall rule
```

## Files

| File | Role |
|---|---|
| `config.env.example` | Non-secret deploy coordinates template (copy to `config.env`). |
| `deploy.sh` | Controller: preflight / provision / sync / bootstrap / up / status / tunnel / teardown. |
| `remote-bootstrap.sh` | Runs on the VM: installs Docker + Compose, creates `dd-net`. |
| `README.md` | This runbook. |

Nothing here provisions cloud resources implicitly or handles secrets through
git. `config.env` is gitignored.
