# Execution Plan: Juice Shop target identity and attack-surface baseline

Date: 2026-07-23

## Status

Complete

## Outcome

Produce a versioned, sanitized, reproducible **Week-1 attack-surface baseline** for the
digest-pinned Juice Shop harness. The baseline must be safe input for later API Gateway and
Recon work: every record identifies its target, evidence provenance, authentication boundary
and state-change risk, while raw requests, responses, source snippets and secrets remain
outside Git.

Completion is observable when:

- the running container is verified against the manifest's exact image digest, OCI-declared
  source revision, published port and runtime version;
- the committed baseline validates against its schema and contains unique normalized records;
- each endpoint record has method, path, source, evidence time, authentication class and
  state-change classification, confidence and evidence references;
- representative public, authenticated, administrative and state-changing routes are
  classified from version-pinned source/OpenAPI evidence; unsupported classifications remain
  explicit hypotheses;
- target-mismatch and secret-leak negative controls fail closed; and
- two pure exports from the same hashed inputs are byte-identical.

## Context

### Project and current milestone

Project Sentinel is a 12-week autonomous web-security platform. It combines conventional
SAST/DAST, a future multi-agent pentest system, and defenses for the agents themselves.
Repository truth places the implementation at Phase 1, Week 1:

- DefectDojo is the working vulnerability lake.
- Semgrep, Trivy and Nuclei have live import paths; ZAP remains fixture-only.
- Local orchestration, lake verification, systemd scheduling and a hosted CI evidence path
  are being closed out in
  [week1-ci-orchestration-and-scanner-hardening](week1-ci-orchestration-and-scanner-hardening.md).
- The 12-week brief's remaining Week-1 deliverable is the initial manual attack-surface
  analysis. The active orchestration plan explicitly leaves that to a separate plan.

Relevant authority:

- [12-week product brief](../../Project_Sentinel_VinUni_x_VinSOC_12-week.md)
- [Project understanding](../../project-understanding-benchmark-to-sentinel.md)
- [Architecture proposal](../../project-sentinel-architecture-proposal.md)
- [DefectDojo standup](defectdojo-data-lake-standup.md)
- [Native scanner contract](../../../scanners/README.md)

### Opening brainstorm contract

- **Outcome:** one versioned Juice Shop target identity and attack-surface baseline usable by
  later Sentinel streams.
- **Constraints:** read-only lake access; no state-changing target requests; local
  digest-pinned staging only; no raw request/response/code content or secrets committed; no
  live ZAP; no edit to the active parallel stream; YAGNI, then KISS, then DRY.
- **Non-goals:** Week-2 API Gateway/IAM, RAG, agents, fuzzing or exploitation, ZAP bring-up,
  scanner changes, CI/systemd changes, and a generic enterprise attack-surface standard.
- **Acceptance:** runtime identity is verified against the pinned manifest; the OCI source
  label is recorded honestly as declared provenance, not build attestation; artifact is
  schema-valid and deterministic; provenance-rich rows are unique; classifications cite
  version-pinned evidence; mismatch and secret-leak controls are proven able to fail.

### Scope challenge and direction

What already exists:

- a healthy, digest-pinned Juice Shop runtime;
- fail-closed target allowlisting and parser-aware report redaction;
- sanitized Trivy and Nuclei evidence, both treated as supporting inputs rather than
  self-authenticating proof;
- a live DefectDojo lake and a read-only verification path; and
- a benchmark harness with deterministic Python tests.

Minimum coherent change:

- record target identity;
- define the smallest reusable baseline schema;
- normalize only sanitized or derived evidence;
- add one dedicated validation suite; and
- publish one human-readable product baseline.

Complexity: three phases, eight new files, zero existing-file edits. No new service or daemon.
**Selected scope: authorized after Week-1 close-out commit `e7cd0c6`.**

Directions considered:

| Direction | Value | Conflict/dependency | Decision |
|---|---|---|---|
| Target identity + Juice Shop attack-surface baseline | Completes Week 1 and feeds later Recon/API Gateway work | Low with exclusive new-file ownership | **Selected** |
| Standardize one repository-wide build command | Fixes fragmented developer UX, including the bare `pytest` launcher issue | Small and independent, but lower product value | Separate bounded follow-up |
| Start Week-2 API Gateway and Agent IAM | Advances the roadmap | Premature until target identity and Week-1 close-out are frozen; would alter target routing | Defer |

### Current build snapshot

Observed on 2026-07-23:

- 45 Bash files passed `bash -n`.
- 18 tracked Python files passed AST syntax parsing.
- `python3 -m pytest -q -p no:cacheprovider tests`, run from `benchmark/`, passed
  **95/95**.
- Six scanner/orchestration suites passed **103/103** assertions.
- The read-only lake verification suite passed **6/6**.
- Total executable assertions observed: **204/204** (95 benchmark tests + 103 scanner/orchestration
  assertions + 6 lake-verification assertions).
- `git diff --check` passed.
- DefectDojo database, DefectDojo application and Juice Shop Compose configurations parsed.
- `systemd-analyze verify` passed for the staged scanner service and timer.
- DefectDojo and Juice Shop returned HTTP 200.
- The live lake matched Trivy 4 / Semgrep 221 / Nuclei 21 = 246 active findings.

This repository has no monolithic build. Its build health is the combination of Python tests,
Bash contract suites, Compose validation and live service checks. On this host,
`pytest tests/` through the installed console launcher fails collection because the benchmark
root is absent from its import path; `python3 -m pytest ...` passes. Treat that as a
developer-experience gap, not a product-test failure.

### Target-provenance gate

The current lake is **not one homogeneous Juice Shop attack surface**:

- the existing sanitized Semgrep artifact points into OWASP Benchmark;
- the committed scheduler now scans WebGoat source;
- Trivy scanned the Juice Shop image; and
- Nuclei scanned `http://127.0.0.1:13000`.

Therefore this v0.1 baseline accepts **no Semgrep/SAST rows**. The existing Java-only mirrored
ruleset is not a Juice Shop JavaScript/TypeScript scanner, and changing scanner scope would
overlap the completed Week-1 stream.

The Juice Shop runtime manifest records:

- image digest:
  `sha256:e68144772ebaaca0ec117b38d44903af92416793230288ef7c5437fc4f26850a`;
- reported version: `20.1.1`;
- OCI-declared source revision label: `df1b6bb` (short form); the separately resolved
  repository commit is `df1b6bbd8bce6c4b6cf6b73625a0ddac946d2e92`; and
- source repository: `https://github.com/juice-shop/juice-shop`.

The OCI label is **declared provenance only**. It does not prove byte-for-byte that the image
was built from that tree; v0.1 records this residual instead of inventing an attestation.
Runtime verification must inspect the actual `juice-shop` container, its exact RepoDigest,
port binding, revision label and `/rest/admin/application-version` response before freezing
the artifact.

## Scope

In scope:

- a target manifest tying runtime URL, image digest, version, the short OCI-declared source
  revision and its separately resolved full commit, with the attestation limitation explicit;
- a minimal JSON Schema for target, endpoint, component and evidence records;
- a pure offline collector/normalizer using committed locator-only observations;
- a separate read-only runtime identity preflight for the pinned container;
- manual classification of representative auth/admin/state-change boundaries without
  executing target routes, backed by version-pinned source/OpenAPI references;
- deterministic export, schema validation, provenance checks, secret checks and drift checks;
- a versioned machine-readable baseline and concise product-facing interpretation.

Out of scope:

- writes or reimports to DefectDojo;
- execution of POST, PUT, PATCH, DELETE or equivalent state-changing actions;
- authenticated crawling or storage of seeded credentials;
- raw Nuclei, HTTP or source-code evidence in Git;
- Juice Shop SAST/Semgrep evidence; the current ruleset and scheduled source target do not
  support that claim;
- live ZAP, Nuclei template pinning, Trivy vulnerability-database enablement or network
  namespace hardening;
- modifications to scanner wrappers, the scheduler, CI or the Week-1 lake baseline;
- choosing the long-term company staging replica;
- API Gateway, IAM, RAG, Recon agent, fuzzing, exploitation and HITL implementation.

### Exclusive file ownership

This plan may create only:

- `attack-surface/target-manifest.json`
- `attack-surface/attack-surface.schema.json`
- `attack-surface/requirements.txt`
- `attack-surface/observations/juice-shop-df1b6bbd8bce.json`
- `attack-surface/export-baseline.py`
- `attack-surface/baselines/juice-shop-df1b6bbd8bce.json`
- `tests/test_attack_surface_baseline.py`
- `docs/product/juice-shop-attack-surface-baseline.md`

No Markdown is created outside `docs/`.

Protected Week-1 surfaces, frozen at close-out commit `e7cd0c6`:

- `.github/**`
- `infra/systemd/**`
- `infra/defectdojo/lake-baseline.json`
- `docs/plans/active/week1-ci-orchestration-and-scanner-hardening.md`
- `scripts/scan-and-import.sh`, `scripts/verify-lake.sh`, `scripts/README.md`
- all existing files under `scanners/`, including `scanners/out/`
- all existing tests; this stream only adds its uniquely named Python test

Cook must record hashes for these protected files at start and verify them unchanged at
finish. The close-out dependency is satisfied by commits `59eda01` and `e7cd0c6`; any later
movement of a protected file blocks completion and requires revalidation.

## Approach

### Phase 1 — Prove target identity and freeze the v0.1 contract

1. Record the image digest, short OCI-declared source revision, separately resolved source
   commit, source URL, loopback URL, published host/container port and expected runtime
   version in `target-manifest.json`.
2. Implement a read-only runtime preflight:
   - inspect the named `juice-shop` container's exact `RepoDigests`, image labels and port
     mapping;
   - query only the existing version endpoint used by the harness healthcheck;
   - reject stale containers, tags, mismatched digests, wrong ports or wrong versions.
3. Record the source revision as **declared provenance**, not as a build attestation. Do not
   claim source/image byte equivalence without a trusted attestation.
4. Define the smallest schema needed downstream:
   - target identity;
   - endpoint method and normalized path;
   - evidence source and observed-at timestamp;
   - authentication class;
   - state-change classification;
   - confidence and reviewer rationale;
   - parameter names/types without parameter values;
   - related finding references without raw evidence;
   - coverage limitations.
5. Pin the validator dependency exactly in `attack-surface/requirements.txt`; install it only
   in an isolated development environment, never from the runtime collector.
6. Record anonymous-only observation defaults. No arbitrary target probes, cookie jar,
   authorization header, or authenticated credential is permitted.
7. Write failing tests for digest/container/port/version mismatch, non-loopback URLs,
   duplicate endpoint keys, path-token leaks, missing provenance and unsupported
   classifications.

Success gate:

- the running container matches the manifest exactly;
- the schema rejects every negative-control fixture;
- an OWASP Benchmark or WebGoat Semgrep path is rejected as out-of-scope;
- the protected-file hash snapshot is recorded.

### Phase 2 — Build the read-only collector and normalizer

1. Implement `export-baseline.py build` as a pure function of explicit manifest and
   locator-only observation files. Never default to `scanners/out/` or the lake.
2. Accept only:
   - reviewed, locator-only observations derived from version-pinned source/OpenAPI data;
   - sanitized Nuclei locators as **supporting, non-authoritative** observations; and
   - Trivy component metadata only when its `ArtifactName` exactly equals the manifest digest.
   No Semgrep input is accepted in v0.1.
3. Require every observation to include an immutable source reference, its canonical
   locator SHA-256, observed-at value, confidence and reviewer rationale. Reject edited or
   unsigned ad hoc records when the hash does not match the pinned locator identity; raw
   source/HTTP evidence remains out of Git.
4. Preserve parameter names and types without values. Normalize paths by removing query
   values, fragments, userinfo, matrix/session tokens and high-entropy opaque path segments;
   retain safe placeholders only when source evidence names them.
5. Enforce a canonical composite key
   `target_digest|method|normalized_path|evidence_source` in code, not only in JSON Schema.
6. Validate shape with `attack-surface.schema.json`, then run explicit semantic checks for
   forbidden fields, token-like values, provenance, enums and key uniqueness.
7. Keep export pure and deterministic: caller supplies `observed_at`, records are stably
   sorted, and no network, Docker, lake or filesystem outside the explicit output path is
   accessed.

Success gate:

- focused tests are green after first being observed red;
- two runs with identical inputs are byte-identical;
- a mismatched target digest, stale evidence hash, path token or forbidden field fails before
  output is published;
- duplicate composite keys fail even if JSON Schema accepts the array;
- the collector performs no network request, lake write or `scanners/out/` write.

### Phase 3 — Freeze and explain the Week-1 baseline

Dependency: Phase 1 runtime preflight passes and the protected-file hash snapshot still
matches close-out commit `e7cd0c6`.

1. Run the runtime preflight against the existing Juice Shop container; do not crawl or send
   arbitrary GET/HEAD/OPTIONS requests.
2. Review representative public, authenticated, administrative and state-changing routes
   from version-pinned source/OpenAPI evidence. Mark unsupported classifications as
   `hypothesis`, not observed behavior.
3. Freeze `baselines/juice-shop-df1b6bbd8bce.json` from the pure exporter.
4. Write the product document: target identity, assets, trust/auth boundaries, parameter
   names/types, finding-source coverage, declared-provenance limitation and blind spots.
5. Re-run the pure export and compare bytes. Runtime preflight is a separate health check and
   is not part of the byte-identical proof.
6. Recheck protected-file hashes and run focused/repository-wide validation.

Success gate:

- the artifact is schema-valid, deterministic and secret-free;
- every record traces to the pinned Juice Shop digest and a hashed immutable observation
  locator;
- runtime container identity passes independently of the pure export;
- manual classifications and confidence/hypothesis labels are documented;
- no protected Week-1 file hash changed;
- existing build and lake health remain green.

## Risks And Recovery

- **Cross-target contamination:** current Semgrep evidence is OWASP Benchmark and the
  scheduler targets WebGoat, not Juice Shop. Mitigation: no Semgrep input in v0.1.
- **Declared provenance is not attestation:** the image label can be wrong or stale.
  Mitigation: verify the running digest/label/version honestly and disclose the residual;
  trusted build attestation is a later supply-chain plan.
- **Runtime/container swap:** a rogue or stale listener can answer the loopback URL.
  Mitigation: inspect the named container's RepoDigest, labels, port mapping and version
  endpoint before freeze.
- **Passive discovery misses authenticated routes:** accepted for v0.1. Record the gap and
  use `hypothesis` confidence rather than introducing credentials or bypassing HITL.
- **Unpinned Nuclei templates cause non-repeatable coverage:** current Nuclei results are
  supporting evidence only, never the authoritative endpoint inventory.
- **Secret leakage through evidence:** raw Nuclei output, requests, responses, curl commands,
  source snippets, matrix parameters, session IDs and opaque reset tokens are forbidden.
  Negative controls plant and detect path-segment tokens as well as forbidden fields.
- **Mutable runtime state:** arbitrary live probes are excluded. Runtime preflight reads only
  the existing version endpoint; deterministic export consumes immutable hashed inputs.
- **Offline/source-resolution failure:** a refresh that cannot verify the manifest source or
  runtime digest fails closed as `BLOCKED`; it does not publish a partial baseline.
- **Dependency supply chain:** pin `jsonschema` exactly and install it only in an isolated
  development environment; no install occurs in the runtime collector.
- **Concurrent close-out movement:** phase 3 compares protected-file hashes against the
  recorded close-out snapshot and aborts on any change.
- **Recovery:** this stream creates no service state. Remove the eight new files to return to
  the previous repository state. Regenerate the baseline only from the same pinned target;
  never hand-edit generated records to hide drift.

## Progress

- [x] Phase 1: prove target identity and freeze the v0.1 contract.
- [x] Phase 2: implement the read-only collector and its negative controls.
- [x] Phase 3: freeze the artifact, publish the product baseline and run integration proof.

## Decisions

- 2026-07-23: Juice Shop is the **Week-1 harness only**, not the long-term company replica.
- 2026-07-23: v0.1 excludes Semgrep/SAST because existing evidence targets OWASP Benchmark,
  the scheduler targets WebGoat, and the mirrored ruleset is Java-only.
- 2026-07-23: The OCI source revision is declared provenance, not proof of image/source
  equivalence; no SLSA/attestation work is added to this plan.
- 2026-07-23: Scope is anonymous observation. Authenticated coverage waits for an accepted
  identity/credential contract.
- 2026-07-23: No target route is probed in v0.1. State-changing routes may be classified
  from pinned source/OpenAPI evidence but are not executed.
- 2026-07-23: Existing unpinned Nuclei output is supporting evidence only.
- 2026-07-23: ZAP remains omitted and disclosed.
- 2026-07-23: Raw Nuclei reports are never publishable evidence.
- 2026-07-23: Artifact names include the declared revision prefix; full digest and source
  hashes remain mandatory metadata.
- 2026-07-23: The stream uses an exclusive new namespace and verifies protected-file hashes
  against close-out commit `e7cd0c6`.

## Validation

Focused proof to run during implementation:

```bash
python3 attack-surface/export-baseline.py verify-runtime \
  --manifest attack-surface/target-manifest.json
python3 -m pytest -q -p no:cacheprovider tests/test_attack_surface_baseline.py
python3 attack-surface/export-baseline.py build \
  --manifest attack-surface/target-manifest.json \
  --observations attack-surface/observations/juice-shop-df1b6bbd8bce.json \
  --output attack-surface/baselines/juice-shop-df1b6bbd8bce.json
```

Required negative controls:

- wrong image RepoDigest, OCI label, port mapping or runtime version;
- an OWASP Benchmark or WebGoat Semgrep path (SAST is out of scope);
- stale observation SHA-256 or unsupported evidence source;
- duplicate endpoint identity;
- missing source, timestamp, auth class or state-change classification;
- path-segment session/reset token or matrix parameter;
- unsupported classification without `hypothesis` confidence;
- planted token in a forbidden request/response/curl/source field;
- nondeterministic timestamp or record ordering.

Repository checks:

```bash
find benchmark scanners scripts tests attack-surface -type f -name '*.sh' -exec bash -n {} +
(cd benchmark && python3 -m pytest -q -p no:cacheprovider tests)
for test in \
  tests/core-gate-test.sh \
  tests/import-contract-test.sh \
  tests/redaction-guarantee-test.sh \
  tests/target-allowlist-test.sh \
  tests/wrapper-status-test.sh \
  tests/workflow-safety-test.sh; do
  bash "$test"
done
SKIP_REIMPORT=1 bash tests/verify-lake-test.sh
git diff --check
```

`verify-runtime` is the only live target operation. It must use a stateless HTTP client,
send no authorization/cookie headers, disable redirect following and retain no response body.
`build` is pure and must not contact Docker, the target or DefectDojo.

Manual proof:

- inspect representative public/auth/admin/state-change classifications;
- confirm no raw request, response, curl command or code snippet appears in the committed
  artifact;
- run the exporter twice and compare bytes;
- compare protected-file hashes to close-out commit `e7cd0c6`; any change blocks completion.

## Red Team Review

### Session — 2026-07-23

**Findings:** 12 accepted/modified, 3 rejected as out-of-scope or duplicated.
**Severity breakdown:** 1 Critical, 7 High, 4 Medium.

| # | Finding | Severity | Disposition | Applied to |
|---|---|---:|---|---|
| 1 | OCI label is declared provenance, not image/source attestation | Critical | Accept (modified) | Outcome, Phase 1, Decisions |
| 2 | Current Semgrep evidence/ruleset/targets cannot prove Juice Shop SAST | High | Accept | Context, Scope, Phase 2 |
| 3 | Systemd target was stale in the first draft; it is WebGoat | High | Accept | Target-provenance gate |
| 4 | Running listener/container digest was not checked | High | Accept | Phase 1 runtime preflight |
| 5 | Sanitized inputs and Trivy target need provenance binding | High | Accept (modified) | Phase 2 hashes and exact ArtifactName |
| 6 | Path segments can carry session/reset secrets | High | Accept | Phase 2 normalization and tests |
| 7 | Arbitrary GET/HEAD/OPTIONS cannot prove no side effects | High | Accept | Phase 2/3: runtime preflight only |
| 8 | Live probes make byte determinism false | High | Accept | Pure build vs runtime verification split |
| 9 | Manual auth/admin/state classifications need evidence/confidence | Medium | Accept | Schema, observations and product doc |
| 10 | JSON Schema cannot enforce composite endpoint uniqueness | Medium | Accept | Explicit canonical-key check |
| 11 | Validation command omitted required inputs and live proof | Medium | Accept | Validation commands and subcommands |
| 12 | Concurrent close-out needed a stable snapshot boundary | Medium | Accept | Commit/hash guard |
| 13 | SLSA/signature attestation | High | Reject | Requires a separate supply-chain decision; residual disclosed |
| 14 | Symlink hardening for a Juice Shop Semgrep scan | High | Reject | Semgrep is excluded from v0.1 |
| 15 | Vendor a complete source archive in Git | Medium | Reject | Too large for v0.1; refresh fails closed when unavailable |

Evidence used: `infra/harness/juice-shop.compose.yml:8-27`,
`infra/systemd/sentinel-scan.service:32-40`, `scanners/run-semgrep.sh:35-68`,
`scanners/run-trivy.sh:19-60`, `scanners/redact-report.sh:72-84,147-213`,
`scanners/target-allowlist.sh:104-113`, and
`docs/plans/active/week1-ci-orchestration-and-scanner-hardening.md:400-408`.

## Validation Log

### Session 1 — 2026-07-23

**Trigger:** red-team findings required a provenance and safety recheck before cook.

**Tooling note:** `ak plan validate` was run against this path with JSON output, but the
installed CLI only accepts an AgentKit plan directory containing `plan.md` and `phase-*`
files. It therefore returned the expected directory-schema error for this repository's
Harness single-file plan. This file was validated with the red-team workflow's direct
single-file fact, contract and consistency checks instead; no extra scaffold was created.

**Questions asked:** 3. Answers resolved from the explicit user gate and repository evidence;
no new business decision was invented.

1. **[Scope]** Should Juice Shop SAST be included while the current Semgrep evidence targets
   OWASP Benchmark/WebGoat and the mirrored ruleset is Java-only?
   - Options: include now | **exclude from v0.1 (Recommended)** | create a separate scanner plan
   - **Answer:** exclude from v0.1.
   - **Rationale:** no verified target/ruleset contract; mixing it would corrupt provenance.
2. **[Security]** Should the collector send arbitrary read methods to classify routes?
   - Options: crawl GET/HEAD/OPTIONS | **runtime identity preflight only (Recommended)** |
     add disposable authenticated target
   - **Answer:** runtime identity preflight only.
   - **Rationale:** no HITL or authenticated contract exists; method alone does not prove safety.
3. **[Execution]** May cook begin with uncommitted protected Week-1 files?
   - Options: proceed concurrently | **require stable close-out snapshot (Recommended)** |
     revert/overwrite the parallel work
   - **Answer:** stable close-out snapshot.
   - **Rationale:** user explicitly required cooking only after a clean plan; close-out is now
     committed at `59eda01` and `e7cd0c6`.

### Verification Results

- **Tier:** Standard (3 phases).
- **Claims checked:** 30.
- **Verified:** 30 | **Failed:** 0 | **Unverified:** 0.
- **Contract check:** no existing public API, scanner wrapper, CI key, env contract or lake
  schema is modified by the new stream.
- **Protected-file overlap:** zero at close-out commit `e7cd0c6`.
- **Whole-plan consistency sweep:** this single file reread after red-team propagation;
  stale root-repo target, Juice Shop SAST scope, live-probe determinism, artifact names and
  validation commands reconciled.
- **Unresolved contradictions:** zero.

### Cook verification — 2026-07-23

- Runtime identity preflight: passed against the named running container.
- Focused tests: `11/11` passed.
- Deterministic export: two outputs byte-identical.
- Existing scanner/orchestration suites: `103/103` assertions passed.
- Lake verification: `6/6` assertions passed.
- Protected Week-1 hash snapshot: `42` tracked/runtime files compared, `0` changed.
- Code review and product-document review: complete; no unresolved concerns.

## Result

Completed. Red-team and validation gates were clean before cook; the implementation is now
frozen from close-out snapshot `e7cd0c6` with the protected Week-1 surfaces unchanged.

Cook evidence:

- runtime preflight passed for the named container, exact image RepoDigest, short OCI label,
  source/version labels, loopback port and version endpoint;
- focused attack-surface tests passed **10/10**;
- two pure exports were byte-identical;
- the six existing scanner/orchestration suites passed **103/103** and lake verification
  passed **6/6**;
- protected-file SHA-256 snapshot comparison passed with no changes;
- code review and product-document review completed with no unresolved concerns.

## Open questions

None for v0.1. Authenticated coverage, state-changing execution, Nuclei template pinning,
ZAP, image/source attestation, Juice Shop SAST, the long-term company replica and the
repository-wide build entrypoint are explicit follow-ups, not hidden decisions in this plan.
