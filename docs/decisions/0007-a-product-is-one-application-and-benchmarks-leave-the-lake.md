# 0007 A Product is one application, and benchmark corpora leave the lake

Date: 2026-07-23

## Status

Accepted

## Context

The Week-1 lake holds 246 active findings in a single DefectDojo Product named
`juice-shop-harness`, engagement `week1-baseline`. Inspection of what each source actually
scanned shows the name is wrong about most of its own contents:

| Source | Count | Actually scanned |
|---|---:|---|
| Trivy | 4 | `bkimminich/juice-shop@sha256:e681447…` — the Juice Shop image |
| Nuclei | 21 | `127.0.0.1` — Juice Shop on port 13000 |
| Semgrep | 221 | `benchmark/targets/owasp-benchmark/` — the OWASP Benchmark corpus |

So 221 of 246 findings say nothing about Juice Shop. Meanwhile the staged systemd unit points
`TARGET_SRC` at `benchmark/targets/webgoat-src` (v2025.3, `c3ed45a`), a third tree that has
never been scanned, and `infra/defectdojo/lake-baseline.json` records `Semgrep JSON
Report: 221` — a count measured against a corpus the scheduler no longer targets. The unit is
not installed, so nothing has failed yet; the first firing would fail `verify-lake.sh`'s
exact-match drift check.

The brief's Week-1 deliverable is a unified data lake for *a* staging application. The
question is not how to patch the drift but what the lake is a lake *of*.

A supervisor has separately directed that WebGoat be the scanned target.

## Decision

**A DefectDojo Product represents exactly one application. The lake carries staging
applications only; scanner-scoring corpora do not belong in it.**

Concretely:

1. **OWASP Benchmark leaves the vulnerability lake.** It is a scoring corpus of 2740 synthetic
   test cases with known ground truth, owned by the benchmark stream. Its findings are not
   triageable and never will be — nobody remediates `BenchmarkTest00023.java`. It entered the
   lake only because a Java-only mirrored ruleset needed a Java tree to point at.
2. **WebGoat becomes the SAST target**, in its own Product. Its source is already local and
   the existing Java ruleset matches it, so this is the cheap half of the supervisor's
   direction and it lands now.
3. **Juice Shop remains the DAST and image-scanning target**, in its own Product, and keeps
   the attack-surface baseline already committed against it. It has a working digest-pinned
   runtime; WebGoat does not, and obtaining one runs into the same registry blob throughput
   that [decision 0005](0005-scanner-wrappers-accept-a-local-binary-fallback.md) records as
   having defeated ZAP.
4. **The asymmetry is documented, not hidden.** The lake describes two applications with
   unequal coverage: WebGoat has SAST only, Juice Shop has DAST and SCA only. Stating that is
   more useful than a single Product whose name implies a completeness it does not have.

## Alternatives Considered

1. **Keep one Product and rename it.** Cheapest, and it was tempting because it changes no
   scan. Rejected on a correctness finding rather than on tidiness: **deduplication is
   product-wide**, measured live during Week-1 (221 findings imported into a second engagement
   returned flagged `duplicate: 221` against the baseline engagement). `DEDUPE_ALGO_ENDPOINT_FIELDS`
   is not overridden in `infra/defectdojo/docker-compose.yml`, so DefectDojo's default
   `["host","path"]` applies — **port is not part of the hash**. Every current Nuclei finding
   carries host `127.0.0.1`. A second loopback-hosted target would therefore collide with Juice
   Shop on any shared path: the eight security-header matchers on `/` hash identically once
   host, path, title, cwe, severity and component match. One application's findings would be
   silently filed as duplicates of another's. Semgrep and Trivy are unaffected because their
   hashes include `file_path`; the exposure is specific to the DAST arm, which is exactly the
   arm a second target would add.
2. **Unify everything on WebGoat.** Follows the supervisor's direction most literally.
   Rejected as currently unachievable rather than wrong: the SAST half lands immediately, but
   Trivy and Nuclei need a WebGoat runtime, and no WebGoat image is present locally while the
   host's registry throughput is the known-broken path from decision 0005. Committing to it
   now would trade a working DAST arm for a blocked one. Revisit when a WebGoat runtime exists.
3. **Delete the 221 OWASP Benchmark findings.** Rejected for this decision. Deletion requires
   admin — the service account received 403 on `DELETE /engagements/{id}/` during Week-1 — and
   destroying measured data to make a name accurate is the wrong order of operations. The
   corpus is removed from the lake's *scanning scope*; how its existing rows are retired is an
   implementation choice for the plan that carries this out.

## Consequences

Positive:

- Cross-target dedup collision on the DAST arm is prevented before a second target exists,
  rather than diagnosed after findings start disappearing.
- The supervisor's direction is honoured on the arm where it is achievable today, without
  pretending the blocked arm is done.
- The lake stops making a claim its contents do not support. A reader of
  `juice-shop-harness` currently learns something false.
- The benchmark stream's data returns to the benchmark stream, where its ground truth and
  scoring semantics actually mean something.

Tradeoffs:

- `infra/defectdojo/lake-baseline.json` becomes per-Product and `verify-lake.sh` must verify
  more than one. Both are Week-1 surfaces that a later plan must touch carefully.
- The systemd unit currently runs one scan pass; per-target scanning needs either a target
  parameter or a second unit.
- Coverage is genuinely asymmetric until a WebGoat runtime exists. That is a real gap in the
  Week-1 deliverable and must be stated in any report of it, not smoothed over.
- The existing attack-surface baseline stays Juice Shop-only. A WebGoat equivalent is future
  work.

## Follow-Up

- This decision is not self-executing. It needs its own execution plan covering the Product
  split, the per-Product baseline, `verify-lake.sh`, the systemd unit, and the disposition of
  the 221 existing rows. That plan must run **before** the systemd timer is installed, since
  the first firing fails the drift check as things stand.
- Consider overriding `DEDUPE_ALGO_ENDPOINT_FIELDS` to include port, which would make loopback
  targets distinguishable within a Product. Not adopted here because separate Products is the
  more honest model and does not depend on a global dedup setting, but it is the natural
  defence in depth.
- The long-term question the architecture proposal already records — whether the staging
  target should eventually be a real VinSOC replica rather than any public vulnerable app —
  stays open and is unaffected by this decision.
