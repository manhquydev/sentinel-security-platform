# 0028 Sentinel Workbench advisory authority and B0 policy

Date: 2026-08-04

## Status

Accepted

## Context

The existing Sentinel Charter is a six-week Juice Shop capstone. A research
workbench that can send selected redacted source to a cloud model and compare
experimental arms must not inherit the Charter's target, approval, capstone, or
evidence claims.

## Decision

Sentinel Security Research Workbench is a distinct advisory/research product.
Maintainer approval, the configured cloud recipient, permitted source
categories, 30-day private-evidence retention, profile revocation and the UI
consent phrase are its authority boundaries. The consent is: **“selected
redacted source is sent to the configured cloud model.”**

B0 is frozen before any source scan:

- CodeQL runs only the recorded pack and revision from the per-run policy
  manifest; unavailable/partial output is incomplete, never clean.
- Semgrep runs only versioned TypeScript and YAML rule files and records their
  digests; unavailable/partial output is incomplete, never clean.
- Trivy records scanner version and DB snapshot digest; unavailable or stale
  snapshot policy failure is incomplete, never clean.

No B0 finding may be removed, downgraded or replaced by B3. B3 produces
structured proposals/ranking only. CMC remains case-study-only unless the
separate value gate passes; it never supplies comparative efficacy evidence.

## Alternatives Considered

1. Treat the workbench as a Charter feature. Rejected because it would conflate
   source-egress authority and case-study inventory with the Charter capstone.
2. Permit a cloud model to select its own source context. Rejected because the
   experiment could no longer state a frozen information budget.

## Consequences

Positive:

- Product copy and evidence stay explicit about source egress and claim bounds.
- Scanner failures are visible measurement failures rather than silent clean
  outcomes.

Tradeoffs:

- An eligible independent corpus, calibration record and separate host workers
  are required before a comparative result or CMC active demo.

## Follow-Up

- Phase 2 implements the fixture-only B0 runner contract.
- Phase 3 establishes sealed real-source intake and the B3 egress boundary.

## Implemented as of 2026-08-06

- Frozen B0 policy surface is committed under `scanners/workbench-b0/`;
  `default_engine_statuses` reports `ready` only when image pins and bound
  file digests match. Ready is not a clean scan and not a comparative experiment.
- Public OpenSSF cache acquisition exists
  (`scripts/workbench-corpus-acquire.py` / `workbench/corpus_acquisition.py`);
  receipts remain `admission_decision: not-admitted`. Acquisition cache is not
  corpus admission.
- Committed corpus catalog is still `blocked-no-eligible-typescript-corpus`;
  CMC remains `case-study-only` with `cmc_value_gate` `not-run`. Comparative
  admission, B3 calibration, and CMC value gate stay open.
