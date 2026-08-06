# Sentinel Security Research Workbench

Sentinel Security Research Workbench is a separately named, self-hosted research
and advisory tool. It records what deterministic controls inspected and can
measure a constrained AI proposal/ranking arm only against an independently
admitted TypeScript corpus with frozen truth.

It is not an extension, replacement, completion claim, target, approval flow or
evidence source for the six-week Sentinel Charter. The Charter remains a
Juice-Shop loopback lab flow. CMC EDU is a local inventory/workflow case study:
it cannot be presented as recall, precision, false negatives, truth-reconciled
gaps, an AI win, or a private-code capability result.

## Operator-visible boundaries

- The UI states before B3 use: **“selected redacted source is sent to the
  configured cloud model.”**
- Only an explicitly approved configured cloud recipient may receive a selected
  redacted canonical unit and at most 8 KiB of sealed dependency context.
- Compose owns only the unprivileged loopback UI. Host-owned workers retain raw
  source, Docker scanner access and the scoped B3 credential.
- Private evidence is retained for 30 days, then expires by ownership-marked
  manifest policy. Sanitized reproducibility bundles do not contain source.
- CMC catalog, approval, dispatch and smoke-test demo are disabled unless a
  persisted `cmc_value_gate` is `passed`.

## Current evidence state

### B0 policy freeze (ready ≠ experiment complete)

The committed B0 freeze surface lives under `scanners/workbench-b0/`
(`policy.json` plus CodeQL/Semgrep/Trivy frozen files). Fixture preflight reports
engine `ready` only when the digest-pinned image in `scanners/image-pins.env`
and every bound policy file match. Ready is a capability fact, not a clean scan
outcome and not a comparative B0–B3 result: runners still need privately prepared
source-less dependency roots and a sealed snapshot before any source-mounted
scan. Incomplete policy, missing pins, or unavailable private dependencies remain
`not-ready` / incomplete measurement failures—never silent clean findings. No B0
finding may be removed, downgraded, or replaced by B3.

### Corpus catalog and acquisition (cache ≠ admission)

The committed corpus catalog remains
`blocked-no-eligible-typescript-corpus`. CMC remains `case-study-only`, and its
committed `cmc_value_gate` is `not-run` because no timed decision census exists
yet.

Operators may materialize a host-local OpenSSF CVE Benchmark / public repository
cache with `scripts/workbench-corpus-acquire.py` and inventory candidates with
`scripts/workbench-corpus-inventory.py`. Acquisition receipts always record
`admission_decision: not-admitted`; they never seal source, run scanners, admit
a comparative catalog row, or authorize efficacy language. Inventory stays
`not-admitted` even when local TypeScript is present at both referenced commits.
Remaining gates—frozen truth, licence/authorship, contamination screening,
independent control audit, non-confirmatory B3 calibration, and ≥20 paired
repositories—are separate and still open.

Until an independent TypeScript corpus is admitted, a non-confirmatory B3
calibration record exists, and (for CMC active demo only) the value gate passes,
the workbench may expose fixture/safety and containment workflow only. It cannot
render a comparative efficacy result or a CMC active-demo action.

The local browser can demonstrate a broker-mediated, metadata-only readiness
workflow. A `not-ready` B0 preflight or missing sealed snapshot deliberately
refuses before a source scan; that is containment evidence, not an analysis
result.
