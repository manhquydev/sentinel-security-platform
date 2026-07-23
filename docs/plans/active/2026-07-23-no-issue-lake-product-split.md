# Execution Plan: Split the DefectDojo lake into one Product per application

Date: 2026-07-23

## Status

Active

## Outcome

Execute [decision 0007](../../decisions/0007-a-product-is-one-application-and-benchmarks-leave-the-lake.md):
a DefectDojo Product represents exactly one application. The lake ends this plan with two
Products — `juice-shop-harness` (Trivy image scan + Nuclei DAST) and `webgoat` (Semgrep SAST,
its own real count) — and zero rows attributable to the OWASP Benchmark corpus. The systemd
scheduler runs one pass per Product instead of one pass mixing three sources into one Product.

Completion is observable when `scripts/verify-lake.sh` reports **0 failed** against the live
lake for both Products, and the two systemd timer pairs can be installed without their first
firing tripping the drift check.

## Context

- Authority: [decision 0007](../../decisions/0007-a-product-is-one-application-and-benchmarks-leave-the-lake.md).
  Read it first; this plan does not re-argue the decision, only executes it.
- Predecessor: [week1-ci-orchestration-and-scanner-hardening](week1-ci-orchestration-and-scanner-hardening.md)
  built the import path, the completeness gate, and the original single-Product
  `verify-lake.sh`/`lake-baseline.json` this plan restructures.
- `scripts/dd-bootstrap.sh` seeded the one existing Product and scoped the CI service account
  to it via `Product.authorized_users`, guarded by a check that FATALs if the account is ever
  authorized on more than one Product (`dd-bootstrap.sh:204-206`). That guard predates this
  decision and assumes exactly one Product will ever exist; it is now a real obstacle (see
  Approach) and a live security-posture question for whoever runs this plan (see Decisions).

### Observed live state (2026-07-23, read-only, via `GET`)

- One Product: `id=1 name=juice-shop-harness`.
- One Engagement: `id=1 name=week1-baseline`, product 1.
- Three Tests in that engagement: `id=69 Trivy Scan` (4 active), `id=70 Semgrep JSON Report`
  (221 active — the OWASP Benchmark corpus), `id=71 Nuclei Scan` (21 active). 246 active total.
- Confirmed live: `GET /api/v2/engagements/?product=&name=week1-baseline` (empty `product=`)
  returns the real engagement for product 1 rather than an empty result set — DefectDojo
  ignores an empty filter value instead of treating it as "match nothing". A verifier that
  resolves a Product's id and passes it straight into this filter without first checking the
  id is non-empty would silently validate an absent-Product baseline against the WRONG
  Product's engagement. `verify-lake.sh` now looks the Product up by name first and fails
  closed when that lookup is empty, before ever querying engagements — see
  `tests/verify-lake-test.sh`'s "absent Product" and "multi-Product baseline reports each
  Product independently" controls, both observed failing against a copy of the verifier with
  that guard removed before the guard was proven to fix them.

## Scope

In scope:

- Restructure `infra/defectdojo/lake-baseline.json` to a `products[]` list, one entry per
  DefectDojo Product.
- Restructure `scripts/verify-lake.sh` to check every Product in the baseline independently —
  a problem with one Product must not hide the state of the others.
- Extend `tests/verify-lake-test.sh` with negative controls for the new failure modes
  (absent Product, multi-Product independence) alongside the migrated existing ones (missing
  source, rogue extra test, drifted count, unreadable file).
- Split `infra/systemd/sentinel-scan.{service,timer}` into two per-target pairs: the existing
  pair repurposed to Juice Shop only (Trivy + Nuclei), plus a new
  `sentinel-scan-webgoat.{service,timer}` pair for the WebGoat Semgrep pass.
- Document, as literal steps below, the live migration: creating the `webgoat` Product,
  authorizing the service account on it, running WebGoat's first real Semgrep scan, retiring
  the 221 stale OWASP Benchmark rows, and recording WebGoat's true baseline count.

Out of scope (the hard constraint of this task, not a choice):

- **Executing any of the live migration steps.** This plan documents them; the orchestrator
  runs them after review. This agent had read-only (`GET`) access to the live instance and used
  it only to observe the state recorded above.
- Obtaining a WebGoat runtime for Trivy/Nuclei. Decision 0007 already accepts the asymmetry:
  WebGoat is SAST-only, Juice Shop is DAST+image-only, until a WebGoat runtime exists.
- `scripts/scan-and-import.sh` / `scanners/import-report.sh` changes. Both already take
  `PRODUCT_NAME`/`ENGAGEMENT_NAME`/`SCANNERS`/`TARGET_SRC` as environment overrides with
  caller-wins precedence over `infra/.env` (`import-report.sh:54-68`), which is sufficient to
  target either Product from a systemd unit's `Environment=` lines. No code change needed.
- `scripts/dd-bootstrap.sh` edits. Its single-Product guard is a real obstacle (see Approach),
  but editing it is not in this task's file ownership and the equivalent effect is achieved
  with direct API calls below instead.
- `scripts/README.md`. Line 58 ("the sole baseline writer") and line 73 ("no
  single-writer/ephemeral-engagement machinery because there is no second [writer]") describe
  the pre-split, one-unit topology and are now stale. Not in this task's file ownership;
  flagged here as a follow-up for whoever next touches that file.

## Approach

Ordered; each step depends on the one before it. All are **admin-token** operations against
the live instance — none of them can run as the scoped service account, and none of them ran
during this phase.

1. **Authorize the service account on a second Product.** `dd-bootstrap.sh`'s
   `authorized_users.add()` step is guarded by a check that FATALs if the account ends up
   authorized on more than one Product — a deliberate least-privilege control from when one
   Product was the whole lake. Re-running `dd-bootstrap.sh` with `DD_PRODUCT=webgoat` would
   create the Product but then hit that guard. Two ways forward, in order of preference:
   - **(a) Widen the guard's intent explicitly.** The two Products this plan creates are both
     Week-1 staging targets under the same `VinSOC` Product_Type, scanned by the same
     unattended writer; the account still cannot delete anything (`is_staff` required, and it
     is neither staff nor superuser) on either. Run the equivalent of `dd-bootstrap.sh`'s
     product/engagement/authorization block by hand against `webgoat` (same API calls,
     skipping the now-inapplicable "authorized on exactly one Product" assertion), so the
     account ends the migration authorized on exactly `{juice-shop-harness, webgoat}` — the
     full set of Products this lake will ever hold under decision 0007, not an open-ended grant.
   - **(b) Second service account, one per Product.** Strictly narrower blast radius, at the
     cost of a second credential to mint, store, and rotate, for a control (`is_staff`-gated
     delete) that already caps the damage a compromised account can do to "read/import/edit
     within its Products". This plan does not choose between (a) and (b) — it is a
     security-posture change to an existing decision (`dd-bootstrap.sh`'s guard), not a
     technical implementation detail, and the person running the migration should pick.
   Commands (as admin token `$ADMIN_TOKEN`, mirroring `dd-bootstrap.sh`'s own API calls):
   ```bash
   # Product
   curl -sS -X POST "$DD_URL/api/v2/products/" -H "Authorization: Token $ADMIN_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"name":"webgoat","description":"WebGoat SAST target (decision 0007)","prod_type":<PT_ID>}'
   # Engagement (product id from the response above)
   curl -sS -X POST "$DD_URL/api/v2/engagements/" -H "Authorization: Token $ADMIN_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"name":"week1-baseline","product":<WEBGOAT_PRODUCT_ID>,"target_start":"<today>","target_end":"<+365d>","status":"In Progress","engagement_type":"CI/CD","deduplication_on_engagement":false}'
   # Authorization (django shell, same pattern as dd-bootstrap.sh:187-209, minus its
   # single-Product FATAL guard)
   docker exec dd-uwsgi python manage.py shell --no-imports -c "
   from dojo.models import Product, Dojo_User
   u = Dojo_User.objects.get(username='$DD_SERVICE_ACCOUNT_USER')
   p = Product.objects.get(pk=<WEBGOAT_PRODUCT_ID>)
   p.authorized_users.add(u)
   print('authorized on:', [x.name for x in Product.objects.filter(authorized_users=u)])
   "
   ```
2. **Run WebGoat's first real Semgrep scan.**
   ```bash
   SCANNERS=semgrep \
   TARGET_SRC="$HOME/Downloads/vinsoc/benchmark/targets/webgoat-src" \
   SEMGREP_RULESET="$HOME/Downloads/vinsoc/scanners/rulesets/owasp-local.yml" \
   PRODUCT_NAME=webgoat ENGAGEMENT_NAME=week1-baseline \
   bash scripts/scan-and-import.sh
   ```
   This is the count that belongs in the baseline — not 221. That number was measured against
   the OWASP Benchmark corpus (2740 synthetic cases with known ground truth); WebGoat is a
   different Java tree entirely and there is no reason to expect the same count.
3. **Retire the 221 OWASP Benchmark rows.** They live in test id 70, inside
   `juice-shop-harness`'s `week1-baseline` engagement. The service account got 403 on `DELETE`
   during Week-1; only admin can remove them (decision 0007's alternative 3). Delete the test,
   not the whole engagement — Trivy (69) and Nuclei (71) stay:
   ```bash
   curl -sS -X DELETE "$DD_URL/api/v2/tests/70/" -H "Authorization: Token $ADMIN_TOKEN"
   # expect 204, matching the DELETE /engagements/{id}/ result already measured for admin
   # during Week-1 (0-vs-403 for the service account, 204 for admin)
   ```
4. **Record WebGoat's baseline and re-verify.** Add the measured count from step 2 to
   `infra/defectdojo/lake-baseline.json`:
   ```json
   {
     "product": "webgoat",
     "engagement": "week1-baseline",
     "expected": { "Semgrep JSON Report": <measured count from step 2> }
   }
   ```
   appended to the existing `products[]` array (`juice-shop-harness`'s entry is unchanged —
   step 3 makes the live lake match it, not the other way round). Run
   `bash scripts/verify-lake.sh` and confirm **0 failed** across both Products before
   proceeding.
5. **Only then install the systemd timers.** `sentinel-scan.timer` and
   `sentinel-scan-webgoat.timer`, per the install steps in
   `infra/systemd/sentinel-scan.service`'s header. Installing either timer before step 4 is
   confirmed green means its first `ExecStartPost=verify-lake.sh` fails: today,
   `juice-shop-harness` still carries the stale Semgrep test (step 3 not done) and `webgoat`
   does not exist yet (steps 1–2 not done) — both are proven failing right now, in this
   session, by the committed `lake-baseline.json` against the live lake (see Validation).

## Risks And Recovery

- **Step 1's authorization widening is a live security-posture change**, not purely additive —
  it changes what the existing `dd-bootstrap.sh` guard asserts is true. If the person running
  the migration prefers option (b) (a second service account), steps 2–5 are unaffected; only
  step 1's commands change to mint and scope a second account instead of widening the first.
- **Step 3 is irreversible** (only admin can delete; there is no soft-delete). If the 221 rows
  ever need to be inspected again, they are not recoverable from DefectDojo after this step —
  recover from the raw/sanitized scanner report files under `scanners/out/` if still present,
  or from `benchmark/targets/owasp-benchmark/` re-scanned fresh. Recorded so nobody runs step 3
  believing it is undoable.
- **Step 2 may fail the completeness gate or proof-of-contact check** exactly as designed if
  `TARGET_SRC` is wrong or the ruleset checksum is stale — `scan-and-import.sh` already fails
  closed on both (Phase 2 of the predecessor plan). If it does, WebGoat's Product/Engagement
  from step 1 still exist and are empty; step 2 is safe to retry.
- **Recovery for steps 1–5 as a whole:** none of them mutate `juice-shop-harness`'s Trivy or
  Nuclei data, so the DAST/image-scan arm is never at risk. If the migration is abandoned
  partway, the lake is left with an extra empty-or-partial `webgoat` Product and possibly a
  still-present test 70 — both inert (nothing scheduled points at them until the timers are
  installed in step 5), not silently corrupting anything.

## Status update — migration executed 2026-07-23

The sections below were written before the live migration and describe a lake that no
longer exists. They are kept for the reasoning, not for the state. What is true now:

- `juice-shop-harness` holds 4 Trivy + 21 Nuclei; `webgoat` holds 11 Semgrep; 36 total,
  none mitigated or duplicated.
- Test 70 (221 OWASP Benchmark rows) was deleted by an admin after a backup, and the 25
  Juice Shop findings were verified byte-identical to that backup down to their hash codes.
- The authorisation open question was resolved as option (a): the service account is
  authorised on exactly `{juice-shop-harness, webgoat}` and is still neither staff nor
  superuser.
- `verify-lake.sh` passes; `tests/verify-lake-test.sh` is 9 assertions, not 8.
- **The timers are still not installable without further work.** Both units were missing
  the scanner binary variables their wrappers require and would have failed on first
  firing; that is fixed, but `verify-lake.sh` is blind to a Product it was not told about,
  which a review demonstrated by hiding an entire Product from it.

## Progress

- [x] `infra/defectdojo/lake-baseline.json` restructured to `products[]`; committed content
      matches today's true `juice-shop-harness` state for Trivy/Nuclei (4/21) and deliberately
      omits Semgrep, which now belongs to a Product that does not exist yet.
- [x] `scripts/verify-lake.sh` checks every Product in the baseline independently: Product
      existence, engagement scan_type set, per-source exact count, import freshness. A missing
      Product or engagement fails that Product's checks and continues to the next, rather than
      aborting the whole run.
- [x] `tests/verify-lake-test.sh` — 8/8, `SKIP_REIMPORT=1`. The "committed baseline" case now
      asserts the live lake's real, current migration debt (the un-retired Semgrep test) rather
      than a clean pass — genuine evidence, not a fixture, that the migration in this plan is
      still pending. The absent-Product and multi-Product-independence controls were observed
      failing against a deliberately unguarded copy of `verify-lake.sh` (the Product-existence
      check removed) before the real check was confirmed to fix them.
- [x] `infra/systemd/sentinel-scan.service`/`.timer` repurposed to Juice Shop only (Trivy +
      Nuclei, `PRODUCT_NAME=juice-shop-harness`); new
      `sentinel-scan-webgoat.service`/`.timer` added for the Semgrep pass
      (`PRODUCT_NAME=webgoat`). `systemd-analyze verify` clean on all four files.
- [ ] Live migration steps 1–5 above. **Not executed by this phase** — read-only constraint;
      the orchestrator runs these after review.
- [ ] `scripts/README.md` updated to describe the two-Product, two-unit-pair topology (flagged,
      not in this phase's file ownership).

## Decisions

- 2026-07-23: The committed `lake-baseline.json` describes the POST-split target for
  `juice-shop-harness` (Trivy + Nuclei only), not a fabricated number for `webgoat`. Recording
  an unmeasured Semgrep count for a Product that does not exist yet would itself be the kind of
  drift this file exists to catch — the honest state is "not yet in the baseline", added only
  once step 2 produces a real count.
- 2026-07-23: Two concrete systemd unit pairs, not a templated `sentinel-scan@.service`. A
  templated unit would need either an external per-instance `EnvironmentFile` (a new
  install-time convention) or an inline `case` statement inside `ExecStart=` (harder to audit
  and to run `systemd-analyze verify` reason about). Two targets is small enough that two
  self-contained files, matching the existing single-file style, are easier to read and diff.
- 2026-07-23: `verify-lake.sh`'s `ExecStartPost` in both unit pairs checks the WHOLE lake
  (every Product in the baseline), not just the Product its own scan pass touched. The lake is
  one shared asset; either writer observing lake-wide drift is real signal.
- 2026-07-23: Step 1's authorization approach ((a) widen vs (b) second account) is left as an
  explicit open choice for whoever executes the migration, not decided here — it changes an
  existing security-posture guard in `dd-bootstrap.sh`, which this plan's file ownership does
  not include editing.

## Validation

- Focused proof: `bash -n` clean on `scripts/verify-lake.sh` and `tests/verify-lake-test.sh`;
  `systemd-analyze verify` clean on all four touched unit files;
  `python3 -m json.tool infra/defectdojo/lake-baseline.json` valid.
- Integration proof: `SKIP_REIMPORT=1 bash tests/verify-lake-test.sh` — 8 passed, 0 failed,
  run twice (before and after removing a temporary unguarded copy of `verify-lake.sh` used to
  observe the new controls fail first).
- Read-only live checks (no lake mutation): `bash scripts/verify-lake.sh` against the real,
  unmigrated lake — 4 passed, 1 failed (`extra: Semgrep JSON Report`), matching the documented
  migration debt exactly.
- Negative controls, each observed failing before passing:
  - a baseline omitting a real source (Nuclei) while the lake has it ⇒ fails;
  - an inflated (Trivy=5) and a deflated (Nuclei=20) count ⇒ both fail;
  - a baseline naming a scan_type absent from the engagement ⇒ fails;
  - a baseline naming a Product absent from DefectDojo ⇒ fails — observed passing incorrectly
    against a copy of `verify-lake.sh` with the Product-existence check removed (DefectDojo's
    `engagements` endpoint ignores an empty `product=` filter rather than matching nothing, so
    the removed-guard version silently fell through to the wrong Product's engagement), then
    observed correctly failing once the check was restored;
  - a mixed baseline (one real Product, one absent) ⇒ the real Product is still checked and
    the absent one is reported, in the same run, rather than the first failure aborting the
    rest;
  - an unreadable baseline file ⇒ fails.

## Result

Code and configuration side complete: restructured baseline and verifier, extended tests
(8/8, negative controls observed failing first), two per-target systemd unit pairs
(`systemd-analyze verify` clean). The live migration (Approach steps 1–5) has not run — this
agent's access to the live instance was read-only `GET` throughout, per the task's hard
constraint, and mutating the lake (creating Products, deleting the OWASP Benchmark test,
running a real scan) is explicitly the orchestrator's to execute after review.

**Live lake, observed unchanged start to end:** `juice-shop-harness` / `week1-baseline` — Trivy
4 active, Semgrep 221 active, Nuclei 21 active (246 total), one Product, one Engagement,
throughout this phase.

Move to `docs/plans/completed/` once Approach steps 1–5 have run and
`scripts/verify-lake.sh` reports 0 failed against the live two-Product lake.

## Open questions

- Step 1's authorization approach — widen the existing service account to both Products, or
  mint a second one scoped to `webgoat` only. Presented with its trade-off in Approach and
  Risks; needs a decision from whoever runs the migration, not assumed here.
- `scripts/README.md`'s single-writer language (lines 58, 73) is now stale but out of this
  phase's file ownership. Someone should update it alongside or shortly after the migration.
