# Workbench scanner viability

Capability status for the Workbench B0 scanner set — **not** a scan result, baseline
verdict, or corpus admission claim.

B0 engines (fixed order): **CodeQL** (JavaScript/TypeScript + GitHub Actions),
**Semgrep** (TS/TSX/YAML), **Trivy** (filesystem/config/secret). Authority is
`workbench/scanner_contracts.py` (`default_engine_statuses`) plus the committed
freeze under `scanners/workbench-b0/`.

## Preflight (fixture profile only)

```bash
bash scripts/workbench-scanner-preflight.sh --fixture-profile typescript
```

Emits JSON (`sentinel-workbench-scanner-preflight/v1`, profile
`fixture-typescript`, kind `capability-status-not-scan-result`). The script never
invokes a scanner.

### When an engine is `ready`

| Check | Source |
|-------|--------|
| Digest-pinned image | `scanners/image-pins.env` — `CODEQL_IMAGE`, `SEMGREP_IMAGE`, `TRIVY_IMAGE` must contain `@sha256:` |
| Frozen policy files match admitted digests | `scanners/workbench-b0/policy.json` + bound files |

Ready reason from code: `image-and-frozen-policy-present`.

**Ready means only that.** It is **not**:

- a clean or completed B0 scan
- an admitted comparative corpus
- proof that private prepared dependency roots exist (query-pack bytes, offline
  Trivy DB cache)
- authorization to mount mutable source outside a sealed fixture

Not-ready reasons (code): `missing-digest-pinned-image`, or engine-specific
missing frozen policy (`missing-frozen-query-pack-and-db-policy`,
`missing-frozen-typescript-yaml-ruleset`, `missing-frozen-db-snapshot-policy`).

## Frozen B0 policy (repository)

| Engine | Image pin | Frozen files under `scanners/workbench-b0/` |
|--------|-----------|---------------------------------------------|
| CodeQL | `CODEQL_IMAGE` | `codeql/distribution-policy.json`, `codeql/query-suite.qls`, `codeql/database-creation-policy.json` |
| Semgrep | `SEMGREP_IMAGE` | `semgrep/frozen.yml` |
| Trivy | `TRIVY_IMAGE` | `trivy/db-snapshot-policy.json` |

`policy.json` schema: `sentinel-workbench-b0-policy/v1`, profile
`fixture-typescript`. Each engine binds relative files to acquisition digests;
preflight SHA-256-matches those files.

Policy freezes the **admission contract** only. Operators still prepare
source-less dependency material privately; source-mounted scans use Docker
`--network none` and a registered sealed fixture snapshot. Incomplete
preparation is never a clean B0 result.

Prepare host-private dependency layout (not a scan, not corpus admission):

```bash
python3 scripts/workbench-prepare-scanner-deps.py \
  --prepared-root ~/.cache/sentinel-workbench/prepared-deps
```

Semgrep copies `frozen.yml`; Trivy may download an offline DB when Docker can
reach the registry; CodeQL still needs a full query pack under `query-pack/`
before a successful `database analyze`.

## OpenSSF corpus cache (host-local, no admission)

Acquire public git evidence into a private cache. Never seals, scans, or admits
a comparative corpus:

```bash
python3 scripts/workbench-corpus-acquire.py \
  --cache-root ~/.cache/sentinel-workbench \
  --max-repositories 5
```

Defaults (from `scripts/workbench-corpus-acquire.py`):

- benchmark URL: `https://github.com/ossf-cve-benchmark/ossf-cve-benchmark.git`
- revision: `91c59fd54b2b768c0f310bb0027d2ac59cdf74d4`
- `--max-repositories 0` → benchmark only

Inventory candidates from that cache (still not admission):

```bash
python3 scripts/workbench-corpus-inventory.py \
  --benchmark ~/.cache/sentinel-workbench/benchmark/ossf-cve-benchmark \
  --expected-revision 91c59fd54b2b768c0f310bb0027d2ac59cdf74d4 \
  --repository-cache ~/.cache/sentinel-workbench/repositories \
  --output /tmp/workbench-candidate-inventory.json
```

Remaining gates (truth, licence, contamination, calibration, ≥20 clusters) stay
unresolved until separate work completes.

## Legacy wrappers vs Workbench path

`scanners/run-semgrep.sh` and `scanners/run-trivy.sh` keep their DefectDojo-oriented
defaults. Set `WORKBENCH_SOURCE_MOUNT=1` only for the Workbench source-mounted path:
requires pinned Docker images, forces `--network none`, rejects Semgrep
`SEMGREP_BIN` local mode and Trivy image/Docker-socket mode.

NUCLEI/ZAP/Juice Shop pins in `image-pins.env` serve the phase-03 DefectDojo
pipeline; they are not B0 Workbench engines. See [`scanners/README.md`](../../scanners/README.md).

## Historical note

Before the freeze, engines were intentionally `not-ready` (missing CodeQL pin,
missing Semgrep TS/YAML ruleset, missing Trivy DB policy). CMC
`codeql-agent-results/` remains invalid B0 evidence.
