# Native scanners → DefectDojo data lake (phase-03)

Four OSS scanners run against the Juice Shop harness (or any allowlisted target),
their reports are **redacted**, then imported into the P1 DefectDojo lake. Every
scanner is a Docker image pinned by `@sha256` in `image-pins.env`.

## Pipeline

```
scanner wrapper → RAW report → redact-report.sh → SANITIZED report → import-report.sh → DefectDojo (reimport, dedup)
```

Redaction is mandatory and runs on the native path (these imports bypass the P5
adapter). It removes secret VALUES but preserves the endpoint/file LOCATORS that
P1 endpoint-dedup hashes on — see `redact-report.sh`.

## Scanners

| Wrapper | Class | Reads | DefectDojo `scan_type` | Report |
|---|---|---|---|---|
| `run-semgrep.sh` | SAST | `TARGET_SRC` + mirrored ruleset | `Semgrep JSON Report` | JSON |
| `run-trivy.sh` | SCA/secret/misconfig | `TARGET_SRC` (fs) or `IMAGE` | `Trivy Scan` | JSON |
| `run-zap.sh` | DAST | `TARGET_URL` | `ZAP Scan` | XML |
| `run-nuclei.sh` | DAST | `TARGET_URL` | `Nuclei Scan` | JSONL → convert |

**SAST/SCA vs DAST read different targets.** `TARGET_URL` (a running app) is not a
Semgrep/Trivy target; they need `TARGET_SRC`/`IMAGE`. This is a scanner-type fact,
not replica machinery — the harness is permanently Juice Shop.

## Target guard (SSRF, fail-closed)

`target-allowlist.sh validate <url>` resolves the host and rejects (exit 1) any
answer in a loopback / link-local / cloud-metadata / RFC1918 / ULA range **unless**
it is explicitly listed in `ALLOWLIST` (`IP`, `IP:PORT`, or `CIDR`). If a host
resolves to multiple IPs and any one is rejected, the whole target is rejected.
The single pinned IP is emitted so scanners can be forced onto it (anti-DNS-rebind).
`ready <url>` additionally waits for the target to serve HTTP.

Juice Shop is loopback, so it must be explicitly allowed: `ALLOWLIST="127.0.0.1:13000"`.

## Harness

`../infra/harness/juice-shop.compose.yml` — Juice Shop pinned by `@sha256`, published
ONLY on `127.0.0.1:13000` (never `0.0.0.0`), on an isolated bridge network, with a
distroless-compatible node healthcheck. Dockerized DAST scanners use `--network host`
to reach it over the host loopback.

```bash
docker compose -f ../infra/harness/juice-shop.compose.yml up -d
```

## Supply-chain pinning

`image-pins.env` holds every scanner image `@sha256` digest; each wrapper fails
closed if its image var is unset or not digest-pinned. Semgrep rulesets and Nuclei
templates are executable analysis logic and must be mirrored + checksummed +
version-recorded, not pulled unpinned from a registry at scan time.

## Tests (TDD)

- `../tests/redaction-guarantee-test.sh` — 4 planted-secret fixtures; asserts every
  secret is removed AND the endpoint/file locator survives. Seen red (no-op stub)
  before the redactor was written.
- `../tests/target-allowlist-test.sh` — allow/reject cases for the SSRF guard,
  including 6 negative controls.

## End-to-end (local)

```bash
export ALLOWLIST="127.0.0.1:13000" TARGET_URL="http://127.0.0.1:13000"
./run-trivy.sh /tmp/trivy.json            # (IMAGE=... for an image scan)
./redact-report.sh trivy /tmp/trivy.json /tmp/trivy.san.json
./import-report.sh "Trivy Scan" /tmp/trivy.san.json
```

Scan artifacts are secret-bearing until redacted — write them to a scratch/gitignored
path, never commit a raw report.
