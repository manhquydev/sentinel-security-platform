# Workbench scanner viability

The Workbench B0 scanner set is CodeQL for JavaScript/TypeScript and GitHub
Actions, Semgrep for TS/TSX/YAML, and Trivy filesystem/config/secret analysis.
This page records capability status, not a scanner result.

Run the fixture-only preflight:

```bash
bash scripts/workbench-scanner-preflight.sh --fixture-profile typescript
```

On August 4, 2026 the repository is intentionally **not ready** for a B0
source scan:

- CodeQL has no frozen distribution, query-suite, or database policy.
- Semgrep has no digest-pinned image and no frozen TypeScript/TSX/YAML ruleset.
- Trivy has an image pin but no frozen database-snapshot policy.

`not-ready`, `incomplete`, parse failure, an unfinished CodeQL database, absent
SARIF, skipped conversion, missing runner metadata, or an invalid raw artifact
is never rendered as a clean baseline. The historical CMC
`codeql-agent-results/` directory is invalid and cannot supply B0 evidence.

When the policy is ready, scanners receive only a registered copied sealed
fixture snapshot. Any source-mounted scanner or graph command must use Docker
network isolation (`--network none`). Database and rule acquisition are
separate, source-less pinned steps. The loopback browser service forbids
scanner source mounts, a Docker socket, and B3 credentials. Its only
privileged path is the host broker: a fragment-delivered one-time capability
becomes an exact-origin session/CSRF exchange, then typed commands reach an
owner-only private worker through a one-use broker-to-worker capability.

The current browser demo can run only a metadata-only readiness command. It
terminates as refused before any source scan while this preflight is
`not-ready`; that terminal state is not a B0 result.

Existing `run-semgrep.sh` and `run-trivy.sh` keep their legacy behavior.
Setting `WORKBENCH_SOURCE_MOUNT=1` enables their Workbench-only source-mounted
path and requires `--network none`; it also rejects Semgrep local-binary mode
and Trivy image/Docker-socket mode.
