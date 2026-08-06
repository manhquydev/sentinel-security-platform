# Workbench scanner viability

The Workbench B0 scanner set is CodeQL for JavaScript/TypeScript and GitHub
Actions, Semgrep for TS/TSX/YAML, and Trivy filesystem/config/secret analysis.
This page records capability status, not a scanner result.

Run the fixture-only preflight:

```bash
bash scripts/workbench-scanner-preflight.sh --fixture-profile typescript
```

## Frozen B0 policy (repository)

Committed freeze surface under `scanners/workbench-b0/`:

| Engine | Image pin | Frozen files |
|--------|-----------|--------------|
| CodeQL | `CODEQL_IMAGE` in `scanners/image-pins.env` | `codeql/distribution-policy.json`, `query-suite.qls`, `database-creation-policy.json` |
| Semgrep | `SEMGREP_IMAGE` | `semgrep/frozen.yml` (TS/TSX/YAML) |
| Trivy | `TRIVY_IMAGE` | `trivy/db-snapshot-policy.json` |

`policy.json` binds each file to its admitted acquisition digest. Preflight
reports `ready` only when the image pin and every bound file match. Ready is
**not** a clean B0 scan outcome: runners still require privately prepared
source-less dependency roots (query pack bytes, offline Trivy DB cache) and a
sealed snapshot before any source-mounted scan.

## OpenSSF corpus cache (host-local)

Acquire public git evidence without admission:

```bash
python3 scripts/workbench-corpus-acquire.py \
  --cache-root ~/.cache/sentinel-workbench \
  --max-repositories 5
```

Inventory candidates from that cache:

```bash
python3 scripts/workbench-corpus-inventory.py \
  --benchmark ~/.cache/sentinel-workbench/benchmark/ossf-cve-benchmark \
  --expected-revision 91c59fd54b2b768c0f310bb0027d2ac59cdf74d4 \
  --repository-cache ~/.cache/sentinel-workbench/repositories \
  --output /tmp/workbench-candidate-inventory.json
```

Acquisition never seals source, never scans, and never admits a comparative
corpus. Remaining gates (truth, licence, contamination, calibration, ≥20
clusters) stay unresolved until separate work completes.

## Historical note

Before the freeze, engines were intentionally `not-ready` (missing CodeQL pin,
missing Semgrep TS/YAML ruleset, missing Trivy DB policy). CMC
`codeql-agent-results/` remains invalid B0 evidence.

When the policy is ready, scanners receive only a registered copied sealed
fixture snapshot. Any source-mounted scanner or graph command must use Docker
network isolation (`--network none`). Database and rule acquisition are
separate, source-less pinned steps. The loopback browser service forbids
scanner source mounts, a Docker socket, and B3 credentials. Its only
privileged path is the host broker.

Existing `run-semgrep.sh` and `run-trivy.sh` keep their legacy behavior.
Setting `WORKBENCH_SOURCE_MOUNT=1` enables their Workbench-only source-mounted
path and requires `--network none`; it also rejects Semgrep local-binary mode
and Trivy image/Docker-socket mode.
