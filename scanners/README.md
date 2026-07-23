# Native scanners → DefectDojo data lake (phase-03)

Four OSS scanners run against the Juice Shop harness (or any allowlisted target),
their reports are **redacted**, then imported into the P1 DefectDojo lake. Every
scanner is a Docker image pinned by `@sha256` in `image-pins.env`.

## Pipeline

```
scanner wrapper → RAW report → redact-report.sh → SANITIZED report → import-report.sh → DefectDojo (reimport, dedup)
                       │
                       └→ <RAW>.status.json  (status sidecar; see below)
```

`scripts/scan-and-import.sh` drives this whole loop for every configured scanner,
serialised by a `flock` so two runs cannot close each other's findings.

Redaction is mandatory and runs on the native path (these imports bypass the P5
adapter). It removes secret VALUES but preserves the endpoint/file LOCATORS that
P1 endpoint-dedup hashes on — see `redact-report.sh`.

## Status sidecar

Every wrapper writes `<report>.status.json` atomically beside its report:

```json
{ "tool": "...", "status": "ok|error", "exit": <int>,
  "reported": <raw finding count, 0 valid, -1 = unparseable>,
  "contact_proven": true|false, "detail": "..." }
```

The orchestrator keys on this, **not** on the wrapper exit code, because the four
wrappers overload their exit-code namespace (the same integer means "target
rejected" in one and "scanner error" in another). `write-status.sh` owns the schema
and the raw-report counting so the wrappers cannot drift. The sidecar is written on
error paths too, which is what lets the orchestrator tell "ran and failed" (skip
import, alert) from "never ran".

`contact_proven` gates whether an import may close absent findings: an empty report
mitigates a whole baseline as "remediated" only if the scan is known to have reached
its target, so the orchestrator sends `close_old_findings=true` only when the sidecar
proves contact AND the report is non-empty AND status is ok.

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

### Redirect and egress containment (DAST)

The DAST wrappers constrain where the scanner can go beyond the seed URL:

- **Nuclei** runs with `-dr` (redirects forcibly disabled — a template cannot opt in
  with `redirects: true` and walk off the target) and `-ni` (no interactsh: OAST
  templates otherwise call ProjectDiscovery's public servers with target-derived data,
  egress the allowlist never sees; the templates are dropped instead).
- **ZAP** (`zap-baseline.py`) exposes no host/port scope flag for its spider, so its
  redirect/spider scope cannot be constrained at the wrapper. ZAP has not run live this
  cycle (no image); when it does, its egress needs to be constrained at the network
  layer, not by a flag.

**Known residual — `--network host`.** The Dockerised DAST scanners use `--network host`
to reach `127.0.0.1:13000`, which also places them where they can reach DefectDojo on
`127.0.0.1:8080` and Postgres on `127.0.0.1:55433`. The port is enforced only at
validation time on the seed URL, so a **same-host, different-port** redirect
(`:13000 → :8080`) is *not* a cross-host redirect and the allowlist does not catch it.
Closing this means dropping `--network host` and pinning the scanner into a namespace
whose only route is the validated `IP:PORT` — a larger change than this cycle took on.
For a deliberately vulnerable target with an open-redirect challenge, treat this as a
real gap, not a theoretical one.

## Harness

`../infra/harness/juice-shop.compose.yml` — Juice Shop pinned by `@sha256`, published
ONLY on `127.0.0.1:13000` (never `0.0.0.0`), on an isolated bridge network, with a
distroless-compatible node healthcheck. Dockerized DAST scanners use `--network host`
to reach it over the host loopback.

```bash
docker compose -f ../infra/harness/juice-shop.compose.yml up -d
```

## Finding identity is mode-independent (Semgrep)

DefectDojo's Semgrep hashcode fields are `file_path`, `line`, `vuln_id_from_tool`
(`infra/defectdojo/docker-compose.yml`) — computed from Semgrep's `path` and
`check_id`. Semgrep derives both from where the ruleset/target happen to sit on
disk at scan time, not from the source content: `check_id` is prefixed with the
config file's directory path relative to the process's cwd, and `path` echoes
whatever form the scan-target argument took. A docker mount (`/rules`, `/src`)
and a local checkout (`scanners/rulesets`, the host source tree) name those
differently, so **the same source tree scanned in the two run modes produces
two different finding identities** — confirmed empirically, not just reasoned:
running the OWASP ruleset against WebGoat produced `scanners.rulesets.java-insecure-random`
+ a `/home/<user>/...` absolute `path` from the local binary, and constructing
the docker branch's exact command shape (cwd pinned to the mounted ruleset dir,
config referenced by its mount-relative name, absolute `/src` target) produced
a bare-but-differently-prefixed `check_id` and a `/src/...`-rooted `path`.

Left alone, switching modes on an already-imported target would silently
auto-mitigate every existing finding as "remediated" and recreate it under the
new identity — the active, non-duplicate count stays the same, so
`verify-lake.sh`'s exact-match drift check cannot see it. The absolute host
`path` also leaked the OS username into the lake as a minor identity-leakage
residual in its own right, independent of the mode-mismatch.

`run-semgrep.sh` now makes identity mode-independent by construction, in the
wrapper (not `redact-report.sh` — this is a fact about how the two Semgrep
invocations name the same tree, not a secret to scrub, and `redact-report.sh`
passes `path`/`check_id` through unchanged whatever value they arrive with):

- **cwd is pinned to the ruleset's own directory** and the config is referenced
  by its bare filename, in both modes (docker gets an explicit `-w /rules` so
  its container cwd equals the mounted ruleset dir, mirroring the local branch
  exactly — Docker's `-w` is a guaranteed engine primitive, not an image
  assumption). This collapses Semgrep's directory-derived `check_id` prefix to
  nothing, regardless of what the ruleset's containing directory is named.
- **`path` is stripped down to be TARGET_SRC-relative**: the wrapper resolves
  `TARGET_SRC` to an absolute path once, uses that (or `/src` under docker) as
  the scan-target argument, then strips exactly that prefix from every
  result's `path` before the raw report leaves the wrapper. What remains is
  identical in both modes and never contains a host absolute path.
- Both normalisations are asserted, not just applied: the wrapper fails closed
  (exit 9) if a `path` doesn't start with the expected prefix, or if a
  `check_id` isn't one of the ids declared in `$SEMGREP_RULESET` — so a future
  Semgrep version changing its prefixing heuristic is caught here instead of
  silently reintroducing mode-dependent identity.

**The 11 pre-existing WebGoat findings were reconciled in place (2026-07-24).**
They had been produced by the local-binary path under the old scheme
(`file_path=/home/<user>/.../benchmark/targets/webgoat-src/...`,
`vuln_id_from_tool=scanners.rulesets.java-insecure-random`), which no longer
matches what the wrapper emits. A plain reimport at that point would have changed
every hashcode field DefectDojo dedups on and so **not** updated those findings in
place — it would have closed all 11 as "remediated" (a fabricated event; nothing
fixed) and created 11 new ones. The active count stays 11 either way, so
`verify-lake.sh`'s exact-count check is blind to it.

The 11 rows' `file_path`/`vuln_id_from_tool` were therefore patched in place via
the DefectDojo API to the normalised values (`src/main/java/...`, bare rule id
e.g. `java-insecure-random`), with no import event — the surgical option that
preserves finding history/age/notes and removes the host-path/username leak the
old absolute paths carried. Their stored identity now matches the wrapper's
output, so the next Semgrep import updates them in place rather than re-keying.
`verify-lake.sh --locator-scheme` reports `relative` for `Semgrep JSON Report`.

This wrapper does not reconcile existing rows — it only stops the drift from
recurring on the next scan. **If the identity scheme is ever changed again**, the
same hazard returns: before the next import against an already-populated
engagement, either reconcile the stored rows in place first, or delete the test
and reimport clean; never let a plain close-enabled reimport re-key a populated
engagement.

## Supply-chain pinning

`image-pins.env` holds every scanner image `@sha256` digest; each wrapper fails
closed if its image var is unset or not digest-pinned. Semgrep rulesets and Nuclei
templates are executable analysis logic and must be mirrored + checksummed +
version-recorded, not pulled unpinned from a registry at scan time.

## Tests (TDD)

- `../tests/redaction-guarantee-test.sh` — 4 planted-secret fixtures; asserts every
  secret is removed AND the endpoint/file locator survives. Seen red (no-op stub)
  before the redactor was written. Also asserts `run-semgrep.sh`'s finding
  identity is mode-independent (see "Finding identity" above); skips that
  section unless a local `semgrep` binary is available (`SEMGREP_BIN`, or
  `REQUIRE_SEMGREP=1` to fail instead of skip).
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
