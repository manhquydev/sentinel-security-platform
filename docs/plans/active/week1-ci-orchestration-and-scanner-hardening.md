# Execution Plan: Lake integrity repair + scan automation (Sentinel Week 1, close-out)

Date: 2026-07-23

## Status

Active

## Outcome

The DefectDojo lake stops losing findings, and then starts feeding itself.

Two halves, in that order. First, three defects in already-shipped P3 code that are silently
corrupting data today are fixed and proven fixed. Only then does automation land: one
command, `scripts/scan-and-import.sh`, running the full scan → redact → import → verify loop,
driven locally by a systemd timer and demonstrated in CI by a GitHub Actions workflow.

Order matters and is not negotiable: a completeness gate calibrated against a corrupted
baseline is itself corrupt, and automation run twice over these defects amplifies them.

## Context

- Predecessor: [defectdojo-data-lake-standup](defectdojo-data-lake-standup.md) — P1 standup,
  P3 native scanners.
- This plan replaces its own first draft, which a three-reviewer red team refuted on
  empirical grounds — every finding verified against the running instance rather than by
  reading. The conclusions that matter are inlined below; the full session record is
  local-only working memory under `plans/reports/`, which git does not retain.
- Binding decisions: [0003](../../decisions/0003-defectdojo-broker-is-redis-not-valkey.md),
  [0004](../../decisions/0004-defectdojo-oss-has-no-role-based-authorization.md),
  [0005](../../decisions/0005-scanner-wrappers-accept-a-local-binary-fallback.md).
- Verified against the running instance: **DefectDojo 3.1.200**, deduplication enabled.
- Repo is public: `github.com/manhquydev/sentinel-security-platform`.

### Corrected facts about the current system

The first draft asserted several things that are false. Recorded so no later reader rebuilds
on them:

- **Import is not asynchronous.** `DD_ASYNC_FINDING_IMPORT` does not exist in 3.1.200;
  parsing runs inline in the HTTP request and no operation id is returned. What *is*
  asynchronous is deduplication post-processing, whose default mode is fire-and-forget. The
  correct control is `deduplication_execution_mode=async_wait` plus the response's
  `deduplication_complete` flag — not a poll loop.
- **`test_imports` rows count distinct findings, not report entries**, and parsers collapse
  entries before counting. Measured: Trivy sums to 1 against 4 reported, Nuclei to 14 against
  21. A `parsed == reported` identity over that surface is unsatisfiable.
- **The real baseline is 1 active Trivy, 221 Semgrep, 14 active Nuclei** (236 total) — not
  the "246 findings, no duplication on reimport" the predecessor plan claims.
- **The ZAP redactor is not a document-level whitelist.** It rebuilds children of
  `alertitem` only; XML attributes anywhere, and elements outside `alertitem`, pass through.
- **Forcing a scanner onto the pinned IP is a no-op here.** The only target is the literal
  `127.0.0.1:13000`, so there is no second DNS resolution to rebind. The `-resolvers` flag
  cited in `scanners/target-allowlist.sh:16` supplies DNS *servers* and pins nothing.

### Measured during validation (2026-07-23)

Established by running against the live instance, not by reading:

- **`async_wait` is cheap.** The 221-finding Semgrep import completed in **2.46 s** on first
  import and **0.88 s** on reimport — roughly 25× under the 60 s default timeout.
  `deduplication_complete` returned `True` in both. The timeout is not a design constraint.
- **`statistics.delta` is `null` on the first import into a new test.** Only `after` is
  present; `before`/`delta`/`after` appear from the second import onward. The gate must
  branch on this or it fails on every newly created test.
- **On reimport, `delta.untouched.total.total` equalled 221 — exactly the reported count.**
  The delta-based accounting is sound; it is the retrieval surface that had to change.
- **Deduplication is product-wide, not engagement-scoped.** 221 findings imported into a
  second engagement came back flagged `duplicate: 221` against the baseline engagement.
- **The service account cannot delete.** `DELETE /engagements/{id}/` returned 403 for the
  CI account and 204 for admin — decision 0004's least-privilege boundary confirmed live.

## Scope

In scope:

- Repair: Nuclei and ZAP redaction whitelists, Trivy hashcode fields, and a parser
  round-trip assertion that makes the redaction suite able to detect these classes at all.
- Import-path safety: parameterised `close_old_findings`, proof-of-contact before trusting
  an empty report, token-based auth so CI never needs the AES key, and the engagement-override
  clobber.
- The core: `scan-and-import.sh` with structured wrapper status, `async_wait` dedup, a gate
  built on `statistics`, and `flock` serialisation.
- Cross-host redirect containment for the two scanners that issue HTTP.
- `verify-lake.sh`.
- Two adapters: a systemd timer that owns the lake, and a SAST-only GitHub Actions workflow
  that never touches it.

Out of scope:

- Trivy vulnerability-database scanning; `NUCLEI_IMAGE`/`ZAP_IMAGE`/`SEMGREP_IMAGE` digests;
  Nuclei template pinning.
- P2 mapping spec, P5 AI-SAST, triage layer.
- Attack-surface baseline (the brief's third Week-1 task) — real work, separate plan.
- Root `README.md` for the public repo.
- **A live ZAP run.** See the disclosed residual below.

Cut, with reasons:

- **Correcting the gitignored Week-1 phase documents.** Their targets live under `plans/`,
  which git discards entirely, and the "abandoned branches" whose statuses would be closed no
  longer exist — only `main` remains. Zero repository-observable change. The false claims in
  *tracked* documents are fixed in Phase 1.
- **Forcing the scanner onto the pinned IP.** No-op for a literal-IP target; replaced by a
  precondition comment and a correction to the false `-resolvers` claim.
- **`heartbeat-check.sh`.** No threshold, no alert channel, no operator on a personal machine
  that is not continuously powered. Last-import age folds into `verify-lake.sh`.
- **The ephemeral engagement and the single-writer topology.** Both existed to stop PR/push
  CI runs from mutating baseline finding state. With CI scoped to SAST-only artifact upload
  that never contacts the lake, the systemd timer is the *only* writer, so there is nothing
  to defend against. Dropping it also sidesteps the product-wide dedup behaviour measured
  above, which would have flagged every branch-scan finding as a duplicate. `flock` stays —
  two timer firings can still overlap.

### Disclosed residual: ZAP has still never run

`ZAP_IMAGE` is unpopulated, the image has never pulled successfully (a prior attempt stalled
~40 minutes on registry throughput), and decision 0005 records that ZAP has no local-binary
branch. Building one means amending 0005, sourcing a ~250 MB distribution outside the
registry, and wiring `zap-baseline.py`'s Python dependencies — a cost large enough to consume
the cycle on its own, for the fourth scanner when three already work.

So ZAP stays fixture-only, knowingly, for another cycle. **Phase 1's ZAP redaction fix lands
regardless**, because without it no ZAP import can ever succeed — the sanitized XML currently
crashes the DefectDojo parser. This plan makes ZAP possible; it does not make it real.

## Approach

**Phase 1 — Stop the bleeding.**

Three repairs, each with a test that would have caught it:

- *Nuclei over-redaction.* `redact-report.sh` drops `info.classification` and `matcher-name`.
  Both feed dedup: `classification["cwe-id"]` becomes the finding's CWE, and `matcher-name`
  becomes `component_name` and part of the parser's own collapse key. Neither is
  secret-bearing. Consequence already observed: four findings closed as remediated and
  re-created with `cwe=0`, and eight security-header findings permanently collapsed to one.
- *ZAP redaction breaks the parser.* `ALERT_KEEP` omits `desc`, `solution` and `reference`,
  which the DefectDojo ZAP parser dereferences unconditionally — the sanitized fixture makes
  it raise `AttributeError`. These are static plugin text, not target data. Separately,
  rebuild the ZAP branch as a genuine document-level whitelist: construct a new tree from
  enumerated elements and strip attributes to an explicit keep-set.
- *Trivy hash collapse.* Secret and misconfiguration findings populate none of the three
  configured hashcode fields, and `HASHCODE_ALLOWS_NULL_CWE` suppresses the legacy fallback,
  so all four share one hash. Give Trivy discriminating fields and verify behaviourally.

The suite change that matters more than any single fix: `redaction-guarantee-test.sh` today
only greps for planted strings, so it cannot observe a sanitized report the parser rejects.
Add a **parser round-trip assertion per scan type** — feed each sanitized fixture to the real
DefectDojo parser and assert a non-zero finding count with non-null severity and a surviving
locator. Add fixture cases for a secret in an XML attribute, a secret outside `alertitem`,
and a credential in a `uri` query string.

Then re-import, record the true per-source counts as the persisted baseline Phase 4 compares
against, and correct the stale claims in the predecessor plan.

**Phase 2 — Make the import path safe to automate.**

Every item is a defect that only becomes dangerous once a scheduler runs the loop unattended:

- `close_old_findings=true` is hardcoded at `import-report.sh:62`. Make it a parameter, and
  never send it true for a zero-finding report or one whose scan lacks proof of contact. A
  degraded target or a mis-pointed `TARGET_SRC` currently closes the entire baseline in one
  call with every gate reporting green.
- *Proof of contact.* An empty report is only "remediated" if the scan demonstrably reached
  its target. For the SAST/SCA sources the check is **scanned-file count > 0** — Semgrep and
  Trivy both report it, and zero is exactly the signature of `TARGET_SRC` pointing at the
  wrong or an empty directory, which is the identified failure mode. For Nuclei, a
  requests-issued count. Absent proof, import without closing and alert.
- `import-report.sh` sources `infra/.env` with `set -a`, which needs a username and password
  and exports the AES credential key and database password to every child process. Add
  `DD_API_TOKEN` support so CI holds exactly one secret and `infra/.env` is never
  materialised on a runner.
- That same `set -a` source silently overwrites a caller-supplied `DD_ENGAGEMENT`. Make the
  caller's value win. (`PRODUCT_NAME`/`ENGAGEMENT_NAME` are read after the source and are
  currently the only safe overrides.)
- Non-file `curl -F` fields read a file when the value starts with `@`. Use `--form-string`
  for every non-file field and validate derived names.
- Emit the full response JSON — `statistics` and `deduplication_complete` are the fields the
  gate needs, and the helper currently discards them.
- Count `reported` from the **raw** report. The redactor hardcodes `errors: []`, erasing
  Semgrep's partial-scan signal; counting from the sanitized file makes a degraded scan look
  complete.
- A missing `CHECKSUMS.txt` currently downgrades ruleset verification to a warning and exits
  0. Make it fatal.

**Phase 3 — The core, tests first.**

Two RED tests, both able to fail, replacing the phantom async-poll test of the first draft:

1. A dedup reimport (`created==0, untouched==N`) must pass the completeness gate.
2. A zero-finding report must not close existing findings.

Then the core: allowlist and readiness → wrappers → redaction → classify → import with
`deduplication_execution_mode=async_wait` → gate on the response statistics.

The gate reads the reimport response directly. It must branch on test age: **`delta` is null
on the first import into a new test**, where only `after` is present, so a gate written
solely against `delta` fails on every freshly created test. First import gates on `after`;
every subsequent one on `delta`, where the action totals sum to the reported count.

Two structural choices the red team forced:

- *Structured wrapper status, not exit codes.* The wrappers have already overloaded their
  numeric space — `run-semgrep.sh:29` exits 2 for "ruleset not found" while Semgrep itself
  uses 2 for a fatal error; `run-nuclei.sh:27` and `run-zap.sh:24` both exit 1 for "target
  rejected", colliding with scanner-error 1. A per-scanner exit-code whitelist over a
  collided namespace cannot be sound. Each wrapper emits a one-line JSON status sidecar; the
  core keys on that.
- *`flock` serialisation.* Two overlapping runs reimporting the same Test with
  `close_old_findings` will each close findings the other just created, non-deterministically
  and silently. This survives the single-writer cut: one writer can still overlap itself.

Cross-host redirect containment applies to Nuclei and ZAP only — Semgrep and Trivy read
`TARGET_SRC` and never issue HTTP. Enforce at the network layer where practical: both
wrappers use `--network host`, which puts the scanner where it can reach DefectDojo on
`127.0.0.1:8080` and Postgres on `127.0.0.1:55433`, and a same-host different-port redirect is
not a cross-host redirect. Also set Nuclei `-ni` to stop OAST templates calling third-party
interactsh servers.

**Phase 4 — Prove it.**

`verify-lake.sh`: two runs, per-source counts matched against the baseline recorded in
Phase 1, no duplicate growth, last-import age fresh.

The drift threshold is **exact**: any deviation from the recorded per-source count fails.
This is the right bar precisely because the target is pinned by digest and the rulesets by
checksum — the finding count *cannot* legitimately move, so any movement is a defect. When a
pin is deliberately bumped, the baseline is re-recorded as part of that change. Note that
"counts stable across two adjacent runs" is not evidence of health; it is exactly what a
stuck degradation looks like, which is why the comparison is against a persisted baseline
rather than the previous run.

**Phase 5 — Two adapters, each in its own role.**

- *systemd timer, operational.* The sole writer, running on this host, reaching loopback
  services directly. No network exposure, no runner registration, one engagement.
- *GitHub Actions, capstone evidence.* The brief names "SAST/DAST CI/CD Integration", so a
  real workflow is a deliverable. It runs on a hosted runner, executes Semgrep and Trivy
  against source, redacts, uploads an artifact, and **never touches the lake** — a hosted
  runner can reach neither DefectDojo nor Juice Shop. No `pull_request`/`pull_request_target`,
  actions SHA-pinned, `permissions: contents: read`, `persist-credentials: false`.

No self-hosted runner is registered. On a public repo it would need `docker` group
membership, which is root-equivalent, on a host that also runs unrelated services bound to
`0.0.0.0`.

## Risks And Recovery

- **Phase 1 changes redaction, which changes hashes.** Restoring fields to the Nuclei
  whitelist changes `hash_code` inputs, so existing findings re-key once. Expect a one-time
  churn; verify it settles on the following run rather than repeating.
- **The Trivy hashcode change is a compose-file edit**, so it needs a container restart and
  re-verification that `dd-smoke.sh` still passes 26/26.
- **Exact-match drift detection will fail loudly on any legitimate pin bump.** That is the
  intended trade: the failure is cheap and the fix is re-recording the baseline, whereas a
  tolerance band would hide the degradation class this check exists to catch.
- **Public repo, public Actions logs.** Anything the workflow prints is world-readable.
  Secrets registered as GitHub Secrets are masked; a token minted at runtime is not.
- **Recovery:** Phases 1–2 modify existing scripts, so their recovery is the existing test
  suites, which must stay green. Phase 3 onward composes rather than modifies. The lake
  itself is covered by the rehearsed restore drill from P1.

Resolved since the first draft: the `async_wait` timeout risk (measured at 2.46 s against a
60 s budget) and the ZAP-image risk (removed from scope as a disclosed residual).

## Progress

Phase 1 — stop the bleeding — **complete 2026-07-23**

- [x] Nuclei whitelist restores `info.classification` and `matcher-name`; a parsed finding
      keeps a non-zero CWE and a `component_name`. Real report: 21 findings parsed where 14
      were before, 11 distinct components, 11/21 with a real CWE.
- [x] ZAP `ALERT_KEEP` restores `desc`/`solution`/`reference`; the DefectDojo ZAP parser
      accepts a sanitized report without raising.
- [x] ZAP branch rebuilt as a document-level whitelist: attributes stripped to a keep-set,
      elements outside `alertitem` dropped, and `uri` userinfo/query/fragment removed (the
      parser discards query and fragment when building the endpoint, so dedup is unaffected).
- [x] Trivy hashcode fields discriminate secret and misconfiguration findings; four distinct
      secrets yield four distinct findings, verified behaviourally (4 active, was 1).
- [x] Nuclei hashcode gains `component_name` alongside `endpoints`. Restoring `matcher-name`
      alone was not enough: eight security-header matchers share title, cwe, severity and
      endpoint, so DefectDojo still filed seven as duplicates until the matcher joined the
      hash. 21 active, was 14.
- [x] `redaction-guarantee-test.sh` gains a parser round-trip assertion per scan type, plus
      fixtures for a secret in an attribute, outside `alertitem`, and in a `uri` query string.
      **39/39, observed failing 31/8 first.**
- [x] A null-stripping filter added to every jq branch. `jq` emits an explicit null for a
      whitelisted key whose source is absent, and Python's `dict.get(key, default)` does not
      apply the default when the key exists holding null — which crashed the Trivy parser on
      `misc_message += ...`. Found by the new round-trip assertion, not by the red team.
- [x] Re-import; per-source baseline recorded for Phase 4: **Trivy 4 / Semgrep 221 /
      Nuclei 21 = 246 active**, stable across a second reimport. Two claims in the
      predecessor plan corrected: the 246-finding count (it was the reported count; the lake
      held 236), and the "allowlist validates but does not force" residual — forcing retired
      as a no-op and recorded as a precondition in `target-allowlist.sh`, redirect-blocking
      carried into Phase 3.
- [x] `dd-smoke.sh` still 26/26; `target-allowlist-test.sh` still 9/9.
- [x] Adversarial code review of the change itself, which found three defects introduced by
      the repair and one inherited: `CweIDs` added to the Trivy whitelist crashed the parser
      on NVD's `NVD-CWE-noinfo` placeholder (`int("CWE")`) and was scope creep — removed;
      `urlsplit().port` validates lazily and raised outside its guard, so one malformed port
      destroyed the whole ZAP report; IPv6 literals lost their brackets and were persisted as
      corrupt locators; and Semgrep's `metadata` needed a default rather than removal, the
      same class the null-stripping filter was added to fix. All fixed and re-verified
      against the inputs that broke them.
- [x] `clean_uri` documented honestly: it strips userinfo, query and fragment, and empties
      non-http(s) schemes, but a credential inside a PATH segment survives —
      `/shop;jsessionid=<token>`, which is exactly what ZAP pluginid 3 reports. The path is
      the locator dedup hashes on, so it cannot be dropped. Recorded as a residual instead of
      asserted away.
- [x] The round-trip assertions no longer pass silently when DefectDojo is down;
      `REQUIRE_DD=1` turns a skip into a failure.
- [x] The 29 findings left flagged `is_mitigated` by the hash re-key deleted. They recorded a
      remediation that never happened, and a lake whose value is trustworthy aggregation
      cannot carry false remediation history. Verified: 0 mitigated, 246 active.

Phase 2 — safe import path — **complete 2026-07-23**

- [x] `close_old_findings` is a parameter defaulting to **false**. The importer cannot tell a
      genuinely clean scan from a broken one, so the caller must opt in; the safe direction
      is the default.
- [x] Proof of contact per source, each using the strongest signal that source actually
      offers, and the asymmetry documented rather than papered over:
      **Semgrep** post-scan `paths.scanned > 0` read from the raw report;
      **Trivy** pre-scan file presence in `TARGET_SRC`, because Trivy reports no scanned
      count at all — this proves the directory had content, not that Trivy read it;
      **Nuclei** post-scan re-probe of the target, since nuclei skips an erroring host and
      still exits 0, and the pre-scan readiness gate says nothing about the minutes the scan
      spanned.
- [x] `DD_API_TOKEN` auth path; verified importing with `ENV_FILE` pointed at a nonexistent
      path, so CI never needs the file carrying the AES key and database password.
- [x] A caller-supplied engagement reaches the API unmodified — caller values are captured
      before the env file is sourced. Asserted against a decoy env file naming a different
      engagement.
- [x] `--form-string` for every non-file field, plus a character allowlist on names. `@` and
      `<` prefixes are rejected before reaching the wire.
- [x] Importer emits the full response JSON; `statistics` and `deduplication_complete` are
      present, and `deduplication_execution_mode=async_wait` makes the statistics
      post-deduplication rather than a race.
- [x] `reported` counted from the raw report. Semgrep `errors` non-empty fails the run — the
      redactor blanks that array, so a count taken from the sanitized file would describe a
      scan that never happened.
- [x] Missing `CHECKSUMS.txt` is fatal (exit 6), not a warning that scrolls past.
- [x] New `tests/import-contract-test.sh` — 8/8, each assertion covering a way an unattended
      scheduler could destroy the lake. Negative controls verified: missing checksums,
      zero-file Semgrep scan, empty Trivy target, dead Nuclei target all fail closed, and
      none of them blocks a healthy run.

Phase 3 — the core — **complete 2026-07-23**

- [x] RED: `tests/core-gate-test.sh` — dedup reimport must pass the gate, zero-finding report
      must not close, plus first-import/racing-dedup/mismatch/malformed cases. Observed 4/9
      failing before the core existed, 13/13 after.
- [x] `scripts/scan-and-import.sh`, with `gate` and `decide` exposed as subcommands so the
      two lake-corrupting guards are testable without a live instance.
- [x] Gate reads the reimport response's statistics and branches on a null `delta`: a first
      import into a new test gates on `after`, every reimport on the summed delta. Verified
      live — the delta path was measured returning `untouched.total=221` against reported 221.
- [x] Wrappers emit the structured status sidecar via a shared `scanners/write-status.sh`
      (atomic write, raw-report counting in one place); the core keys on `status`/`reported`,
      never on the collided exit codes. `tests/wrapper-status-test.sh` 15/15, hermetic against
      committed fixtures rather than the overwritable `scanners/out/` corpus.
- [x] `flock` serialisation; a second run while the lock is held exits 75. Verified.
- [x] Redirect/egress containment for Nuclei: `-dr` forcibly disables redirects (verified
      against the real binary's flags), `-ni` drops OAST callbacks. ZAP's spider scope is not
      flag-constrainable and it has not run live; both facts, and the `--network host`
      same-host-port residual, are documented in `scanners/README.md`.
- [x] Local end-to-end through the core, all three behaviours proven against the live
      instance: a finding-bearing scan lands and is granted close (`gate: 4 == 4`, lake steady
      at 246); a clean zero-finding scan lands without closing the baseline (`gate: 0 == 0`,
      `close=false`); a scanner error (Maven 429) is caught via `status=error reported=-1`,
      the import skipped and alerted, the lake untouched.

Phase 4 — prove it

- [ ] `scripts/verify-lake.sh`: two runs, per-source counts exactly match the recorded
      baseline, no duplicate growth, last-import age fresh.

Phase 5 — the two adapters

- [ ] systemd timer + unit as sole writer; documented install steps.
- [ ] `.github/workflows/security-scan.yml`: SAST-only, hosted runner, artifact upload,
      never contacts the lake.
- [ ] Workflow triggers, action pinning, permissions and `persist-credentials` verified; a
      test greps for forbidden triggers so drift fails rather than being caught by review.
- [ ] `scripts/README.md`: env contract, token scope, local-run steps.

## Decisions

- 2026-07-23: This plan lives in `docs/plans/active/`. `plans/` is gitignored in full, so a
  plan written there would not exist in the repository it plans work for.
- 2026-07-23: Data-integrity repair precedes automation. A gate calibrated against a
  corrupted baseline is corrupt, and `verify-lake.sh` runs the core twice over whatever
  defects remain.
- 2026-07-23: The completeness gate reads the reimport response's `statistics`, branching on
  `delta` being null for a first import. The `test_imports` accounting design is abandoned —
  it counts distinct findings, not report entries, making the identity unsatisfiable.
- 2026-07-23: No async import poll. Import is inline in 3.1.200; the asynchronous step is
  deduplication, guarded by `async_wait` and `deduplication_complete`. Measured at 2.46 s
  against a 60 s budget, so the timeout is not a design constraint.
- 2026-07-23: Two adapters with separate jobs — a local systemd timer for operational value,
  a hosted-runner SAST-only workflow for capstone evidence. No self-hosted runner.
- 2026-07-23: The ephemeral engagement and single-writer topology are dropped. They defended
  against CI mutating baseline state; CI no longer touches the lake, so the defence has no
  attacker. `flock` is retained because one writer can still overlap itself.
- 2026-07-23: Drift detection is exact-match, not a tolerance band. The target is pinned by
  digest and the rulesets by checksum, so the finding count cannot legitimately move; any
  movement is a defect. A deliberate pin bump re-records the baseline.
- 2026-07-23: Proof of contact for SAST/SCA sources is a scanned-file count above zero — the
  direct signature of the identified failure mode (`TARGET_SRC` pointing at nothing) without
  a per-target magic number to maintain.
- 2026-07-23: ZAP stays fixture-only for another cycle, disclosed rather than deferred
  silently. The redaction fix still lands, because it is what makes any future ZAP import
  possible.
- 2026-07-23: Wrapper status is structured, not encoded in exit codes, because the wrappers'
  numeric namespaces already collide.

## Validation

- Focused proof: `tests/redaction-guarantee-test.sh` extended with parser round-trip
  assertions and the three new leak vectors; `tests/target-allowlist-test.sh` extended with
  redirect containment. The two RED guard tests observed failing before the core exists,
  then passing.
- Integration proof: `scripts/verify-lake.sh` across two runs. `scripts/dd-smoke.sh` 26/26
  after the compose change.
- Negative controls:
  - a zero-finding report ⇒ nothing is closed;
  - a scan reporting zero scanned files ⇒ import without closing, and alert;
  - a same-host different-port redirect ⇒ scan fails;
  - a sanitized fixture fed to the real DefectDojo parser ⇒ must parse, with locator intact;
  - two concurrent core runs ⇒ the second exits on the lock;
  - `CHECKSUMS.txt` removed ⇒ run fails, not warns;
  - a Semgrep report with non-empty `errors` ⇒ run fails rather than auto-closing;
  - a per-source count moved by one ⇒ `verify-lake.sh` fails.

## Validation Log

### Session 1 — 2026-07-23

**Red team.** Three hostile reviewers in parallel (security adversary, failure-mode analyst,
assumption destroyer), each verifying against the live instance rather than reading. Four of
the first draft's premises refuted; five defects found in already-shipped P3 code. All
accepted; plan rewritten rather than patched.

**Verification pass.** 7 plan claims checked against source — 7 verified, 0 failed, 0
unverified. `redact-report.sh:68` (Nuclei whitelist), `:40-41` (ZAP `ALERT_KEEP`),
`import-report.sh:62` (`close_old_findings`), `docker-compose.yml:68` (Trivy hashcode),
`run-semgrep.sh:39` (checksum fail-open), `run-zap.sh:38` / `run-nuclei.sh:43`
(`--network host`), and the exit-code collisions at `run-semgrep.sh:29`, `run-nuclei.sh:27`,
`run-zap.sh:24`.

**Live measurement.** Recorded under "Measured during validation" above. A throwaway
engagement was created for the timing probe and deleted afterwards; the baseline was verified
intact at 1 / 221 / 14 across tests 69, 70, 71.

**Interview — 4 questions.** Ephemeral engagement dropped; drift threshold set to exact
match; SAST proof-of-contact set to scanned-file count > 0; ZAP kept fixture-only as a
disclosed residual. All four recorded in Decisions.

### Whole-Plan Consistency Sweep

Single-file plan; no phase files to reconcile. Re-read after propagation. The ephemeral-engagement
cut was propagated to Scope, Approach Phase 3 and Phase 5, Progress, and Decisions; `flock`
retained with its rationale restated for the single-writer context. The ZAP live run was
removed from Outcome, Scope, Approach and Progress and replaced by an explicit residual
section. `statistics.delta` references qualified with the first-import branch everywhere they
appear. Cross-document check against the predecessor plan: its "246 findings" claim and its
"allowlist validates but does not force" residual both contradict this plan and are queued
for correction in Phase 1. No unresolved contradictions.

## Result

Not started. All five phases unblocked.

## Open questions

- Are `cmcv2-prod-api-1` and `cmcv2-prod-postgres-1`, both bound to `0.0.0.0` on this host,
  intentional? Unrelated to this project, but they widen the blast radius of anything that
  executes here. Does not block any phase.
