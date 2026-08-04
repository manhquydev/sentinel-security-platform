# Orchestration and operations

The scanners in `../scanners/` produce and redact reports; the scripts here drive
them into the DefectDojo lake, verify the result, and schedule it.

## The loop

```
scan-and-import.sh → per scanner: run wrapper → read <report>.status.json
                     → redact → import (close_old_findings only if contact proven)
                     → gate (parsed == reported) ;  serialised by a flock
verify-lake.sh     → active counts == recorded baseline, reimport idempotent, age fresh
```

`scan-and-import.sh` also exposes `gate <response.json> <reported>` and
`decide <status.json>` so the two lake-corrupting guards — the completeness gate and
the close decision — are testable without a live instance (`tests/core-gate-test.sh`).

## Environment contract

| Variable | Used by | Meaning |
|---|---|---|
| `TARGET_SRC` | semgrep, trivy (fs) | source tree to scan |
| `IMAGE` | trivy (image) | container image to scan |
| `TARGET_URL` | nuclei, zap | URL to probe |
| `ALLOWLIST` | nuclei, zap | fail-closed target guard (`IP`, `IP:PORT`, `CIDR`) |
| `SEMGREP_RULESET` | semgrep | mirrored, checksummed ruleset path |
| `SEMGREP_BIN` / `*_IMAGE` | wrappers | local binary, or a `@sha256`-pinned image |
| `TRIVY_SCANNERS` | trivy | e.g. `secret,misconfig` when the vuln DB is unreachable |
| `SCANNERS` | scan-and-import | subset of `semgrep trivy nuclei zap` |
| `DD_API_TOKEN` | import-report | preferred; a Product-scoped token so CI/ops never needs `infra/.env` |
| `BASELINE` | verify-lake | path to `../infra/defectdojo/lake-baseline.json` |
| `MAX_IMPORT_AGE_SECONDS` | verify-lake | makes the freshness check fatal above this age |

Without `DD_API_TOKEN`, `import-report.sh` falls back to `infra/.env` and its
service-account username/password. That file also holds the AES credential key and
the database password, so on any host that is not the developer's own, set
`DD_API_TOKEN` and never ship the env file. The token is the non-superuser,
non-staff account scoped to one product ([decision 0004](../docs/decisions/0004-defectdojo-oss-has-no-role-based-authorization.md)):
it can read and write the product's findings, not administer the instance.

## Run it locally

## Charter topology startup

From the repository root, start the existing Charter Compose owners with:

```bash
bash scripts/sentinel-charter-up.sh
```

This requires Docker access, the existing private environment configuration with
its readable ADC file, the established DefectDojo network and certificate
material, and no existing Charter Kong containers or database volume. The
launcher starts the existing Compose owners only; its executable contract and
offline proof are [`sentinel-charter-up.sh`](sentinel-charter-up.sh) and
[`sentinel-charter-launcher-test.sh`](../tests/sentinel-charter-launcher-test.sh).

It does not scan, import, run the controller, obtain an approval, execute a
request, or verify service health. A successful launcher invocation is not a
fresh completed Charter run.

## Charter controller

`bash scripts/sentinel-demo.sh run --profile charter --run-id <id>` creates a private
`.sentinel-runs/<id>/manifest.json`. CI handoff additionally requires a matching Trivy sanitized
JSON artifact, SHA-256, and its versioned metadata sidecar. `verify`, `resume`, and `--teardown`
are separate commands; teardown never removes shared volumes.

New runs use `sentinel-run/v2`. Before any resume, the controller recomputes a
closed, secret-free execution identity and rechecks every private (`0700` run,
`0600` artifact) checkpoint. A changed descriptor, altered artifact, or a
prepared/unknown import or executor effect stops without invoking an adapter,
signer, scanner, or executor; start a separately authorized new run rather than
repairing the old directory. `sentinel-run/v1` remains readable by `verify` as
historical evidence, but every pending v1 run (including R5) returns `legacy
manifest lacks exhaustive resume identity` and is never backfilled or resumed.
Manifests store digests and typed safe artifacts only—never credentials, raw
scan output, provider responses, or rendered secret values.

The local charter path requires the literal Juice Shop target, a reviewed pinned Nuclei
image (or the explicit documented local-binary override), `SENTINEL_LITELLM_ALIAS`, and a
credentialed LiteLLM route. After it writes the fixed request spec, it exits `75` while
waiting for a human-signed approval envelope. Resume with both
`SENTINEL_CHARTER_APPROVAL_FILE` and `SENTINEL_CHARTER_PUBLIC_KEY`; preflight additionally
requires the explicit DER-SHA-256 pin in `SENTINEL_CHARTER_PUBLIC_KEY_SHA256`. The envelope must bind
that exact run-local spec. The controller never reads the executor OAuth secret or API key. An executable
`SENTINEL_CHARTER_EXECUTOR_ADAPTER` owns that secret in its separate context, invokes
`sentinel-charter-executor.py`, and returns only its sanitized receipt result. Without the
adapter the request stage fails closed.

```bash
# one scan → import → gate, then verify
TARGET_SRC="$PWD" IMAGE="bkimminich/juice-shop@sha256:…" TARGET_URL="http://127.0.0.1:13000" \
ALLOWLIST="127.0.0.1:13000" SEMGREP_RULESET="$PWD/scanners/rulesets/owasp-local.yml" \
TRIVY_IMAGE="aquasec/trivy@sha256:…" TRIVY_SCANNERS="secret,misconfig" \
  bash scripts/scan-and-import.sh

bash scripts/verify-lake.sh
```

## Two adapters, one writer per application

The lake has one writer per application, and it is not CI.

- **`../infra/systemd/sentinel-scan.{service,timer}`** — Juice Shop's writer: Trivy and
  Nuclei, the DAST and image arms. **`sentinel-scan-webgoat.{service,timer}`** is the
  second pair, running Semgrep against the WebGoat source into its own Product. A
  *user* systemd unit on the developer host, so it runs under the account that already
  holds the docker group and the DefectDojo credentials rather than granting root a new
  capability. It runs `scan-and-import.sh` then `verify-lake.sh`, on the timer's cadence.
  Install steps are in the service file's header.

- **`../.github/workflows/security-scan.yml`** — SAST/SCA on push, as the capstone's
  "CI/CD integration". It runs on a GitHub-hosted runner, scans the source with Semgrep
  and Trivy, redacts, and uploads the redacted reports as an artifact. It **never
  contacts the lake** — a hosted runner cannot reach the loopback-bound DefectDojo, and a
  self-hosted runner on a public repo would need root-equivalent docker access — so it
  holds no secrets at all. `tests/workflow-safety-test.sh` enforces the no-fork-trigger,
  SHA-pinned-actions, least-privilege, and no-lake-contact properties so a later edit
  cannot quietly weaken them.

There are now two writers, one per application, and they cannot corrupt each other's
Product: distinct `PRODUCT_NAME`, disjoint scan types, disjoint output filenames. They do
share the `flock` in `scan-and-import.sh`, which is `flock -n` — the loser **aborts with
exit 75 rather than waiting**, the oneshot unit enters `failed`, and `Persistent=true`
does not retry a failed run. With both timers on a daily schedule plus a randomised delay,
a collision is a recurring probability, not a theoretical one, and its cost is a skipped
day for one Product.

Neither unit declares `OnFailure=`, so a failed scheduled run is silent unless someone
runs `systemctl --user status`.
