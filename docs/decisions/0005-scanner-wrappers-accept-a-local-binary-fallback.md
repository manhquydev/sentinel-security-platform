# 0005 Scanner wrappers accept a local-binary fallback, not only a pinned image

Date: 2026-07-23

## Status

Accepted

## Context

The P3 native scanners (`scanners/run-*.sh`) were designed to run each tool from a Docker
image pinned by `@sha256` digest — the supply-chain posture the Week-1 plan requires. Every
wrapper fails closed if its image variable is unset or not digest-pinned.

On this host the container registry was effectively unusable for large layers. Docker Hub
answered its auth challenge in under a second (HTTP 401 in 0.9s), so connectivity was fine,
but the layer/blob transfers timed out repeatedly:

- `bkimminich/juice-shop` (520 MB) pulled after a long wait;
- `aquasec/trivy` (254 MB) pulled;
- `ghcr.io/zaproxy/zaproxy:stable` (~1.6 GB) stalled with no progress for ~40 min and was
  abandoned;
- `projectdiscovery/nuclei` stalled on an fs layer;
- `semgrep/semgrep` reached the final layer then died: `read: connection timed out`.

Two retries (which resume cached layers) also failed. The bottleneck is registry blob
throughput, not reachability, and it is not something the harness can fix.

The same tools were reachable through **other channels**: Semgrep installed from PyPI
(`pip install semgrep`), and Nuclei downloaded as a single binary from its GitHub release
CDN (43 MB, one request). Both succeeded on the first attempt where the equivalent Docker
pulls had failed.

## Decision

Each wrapper keeps the digest-pinned Docker image as its default and production path, but
also accepts an explicit local-binary override:

- `run-semgrep.sh` honours `SEMGREP_BIN`;
- `run-nuclei.sh` honours `NUCLEI_BIN`.

When the override is set, the wrapper runs that binary directly and skips the
`@sha256`-pin guard (there is no image to pin). Every other guard is unchanged: the Semgrep
ruleset checksum verification still runs, the Nuclei allowlist + resolved-IP validation
still runs, and redaction still runs before import.

## Consequences

- The `@sha256` supply-chain guarantee applies only to the Docker path. In local-binary
  mode the integrity guarantee rests on whatever installed the binary (a pip lockfile, a
  verified release download) and is weaker. This is a deliberate, disclosed trade-off for
  environments where the registry is unreachable, not the recommended default.
- The fallback is opt-in and explicit — an operator must set `*_BIN`. A normal run still
  fails closed on an unpinned image, so the weaker mode cannot be entered by accident.
- Trivy and ZAP have no local-binary branch yet; add one only if a run is actually blocked
  on their images, to avoid speculative surface (YAGNI).
