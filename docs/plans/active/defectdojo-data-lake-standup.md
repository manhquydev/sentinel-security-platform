# Execution Plan: DefectDojo data-lake standup (Sentinel Week 1, Stream A)

Date: 2026-07-23

## Status

Active

## Outcome

A running DefectDojo instance that native scanners (Semgrep, Trivy, ZAP, Nuclei) and a
CI orchestrator can import into, with deduplication that demonstrably works, credentials
that cannot silently fall back to published defaults, and a restore procedure that has
been rehearsed rather than merely written.

## Context

- Detailed phase material: `plans/260721-2216-week1-sast-dast-data-lake-defectdojo/`
  (P1 standup, P2 mapping spec, P3 native scanners, P4 CI orchestration, P5 AI-SAST hold).
- Decisions promoted from this work: [0003 broker is Redis](../../decisions/0003-defectdojo-broker-is-redis-not-valkey.md),
  [0004 no role-based authorization](../../decisions/0004-defectdojo-oss-has-no-role-based-authorization.md).
- Operator documentation: `infra/defectdojo/README.md`.
- Session reports: `plans/reports/from-cook-to-user-260723-0200-defectdojo-p1-standup-report.md`,
  `plans/reports/from-brainstorm-to-user-260723-0831-p1-decision-recheck-dedup-master-flag-off-report.md`.
- Independent of the AI-SAST benchmark track, which completed separately
  (`runs/model-comparison.md`, decisions 0001–0002).

Verified against **DefectDojo 3.1.200** open source.

## Scope

In scope:

- P1: DefectDojo stack, external TLS database, boot guard, seeded data model, scoped CI
  token, deduplication, backup + rehearsed restore drill, acceptance checks.
- P3: native scanner wrappers, the Juice Shop harness, whitelist redaction, the fail-closed
  target allowlist, and the scan→redact→import→dedup loop.

Out of scope for now:

- P4 CI-agnostic orchestration.
- P5 AI-SAST source wiring (held pending engine choice).
- Exposing the instance beyond loopback — deferred until P4 establishes where CI runs.

## Approach

Two stacks with separate lifecycles: `infra/defectdojo-db/` (external Postgres) and
`infra/defectdojo/` (application). `docker compose down` on the application can never
take the data with it, and repointing at a managed database later is an `.env` change.

Every Django container boots through `scripts/dd-entrypoint.sh`, which runs
`scripts/dd-boot-guard.sh` **before Django is imported**. Placement is the control: a
process that reaches Django settings has already decrypted stored credentials with
whatever key it was handed, so a post-boot assertion could only detect the problem.

Migrations belong to a one-shot `initializer` service gated by
`service_completed_successfully`, so no container can race them or leave a half-applied
migration after a crash-loop.

## Risks And Recovery

- **Published default crypto keys.** `dd-boot-guard.sh` exits 78 on a key that is unset,
  empty, under 16 characters, or equal to any value published in the DefectDojo repo
  (including the in-code fallbacks `""` and `"."`). Verified across 8 cases.
- **Silent async failure.** A Celery worker can report healthy while consuming nothing
  (decision 0003). Recovery: the smoke suite asserts the queue drains and that a
  reimported finding is flagged duplicate.
- **Inert deduplication.** `enable_deduplication` is `False` in every fresh install and no
  environment variable changes it. `dd-bootstrap.sh` sets it; `dd-smoke.sh` fails if it is
  off.
- **Unreadable backups after key rotation.** Each dump carries a `.meta.json` recording the
  SHA-256 **fingerprint** of the AES key in force (never the key). Restoring under a
  different key yields rows that are present and permanently unreadable.
- **Stale nginx upstream.** nginx caches the uwsgi address at startup; a recreated uwsgi
  gets a new IP and nginx serves 502 indefinitely. `depends_on: restart: true` covers the
  normal `compose up -d` path. Replacing the container outside compose is **not** covered
  and needs `docker restart dd-nginx`.
- **Recovery procedure:** `scripts/dd-backup.sh --drill` restores into a throwaway
  database, boots the application against it, and asserts a planted canary credential
  decrypts to its known plaintext.

## Progress

- [x] Two-stack compose, all images pinned by `@sha256` digest.
- [x] External Postgres on `127.0.0.1:55433` with `sslmode=verify-full` and a local CA.
- [x] `pg_hba.conf` accepts `hostssl` only and explicitly rejects `hostnossl`.
- [x] Boot guard wired first in every Django entrypoint (8/8 cases correct).
- [x] One-shot initializer owns migrations.
- [x] Data model seeded: Product_Type `VinSOC` → Product `juice-shop-harness` →
      Engagement `week1-baseline`.
- [x] Non-superuser, non-staff CI account scoped to one product.
- [x] Both deduplication variables set; ZAP/Nuclei hash on `endpoints`.
- [x] Broker switched to Redis; Celery verified executing tasks.
- [x] `enable_deduplication` set by bootstrap; duplicate detection verified behaviourally.
- [x] Backup + **deep restore drill executed and passing**.
- [x] Acceptance suite: 26/26, and proven able to fail.
- [ ] Correct the Week-1 phase documents that describe the superseded RBAC model and the
      two-variable-only deduplication requirement.
- [x] P3 native scanners — **complete, with disclosed residuals** (accepted 2026-07-23). The
      ClaudeKit plan `plans/260721-2216-week1-sast-dast-data-lake-defectdojo/` was narrowed
      for the solo/no-customer context: Jenkins cut (GitHub Actions only), replica-swap cut
      (Juice Shop permanent), TDD structure added; Juice Shop binds `127.0.0.1:13000`
      (host `:3000` taken). Proven: parser-aware 4-tool **whitelist** redaction (fixture
      29/29 — the original blacklist leaked through un-enumerated fields and was rewritten
      after code review), fail-closed SSRF allowlist (9/9), Juice Shop harness healthy, and
      the scan→redact→import→dedup loop end-to-end against live DefectDojo for **three**
      scanners: Trivy (4), Semgrep (221), Nuclei (21) → 246 findings aggregated in one
      engagement, no duplication on reimport.

## Owed to P4 (P3 residuals, accepted knowingly)

P3 was accepted at the plan's "≥3 native scanners" bar rather than held on a fourth. What
did not get proven is recorded here so P4 inherits it explicitly:

- **ZAP has never run.** `scanners/run-zap.sh` exists and its redaction passes the fixture,
  but the image pull was blocked by registry blob throughput, so no part of the ZAP
  scan→redact→import path has executed against anything real. Endpoint-hash stability for
  ZAP is fixture-only. P4 must populate `ZAP_IMAGE` or use the local-binary fallback, then
  re-assert on a real report.
- **Trivy vulnerability scanning is unproven** — the vulnerability database was unreachable;
  only the secret and misconfiguration scanners ran.
- **Supply-chain pins are incomplete.** `NUCLEI_IMAGE`, `ZAP_IMAGE`, and `SEMGREP_IMAGE` are
  unpopulated in `scanners/image-pins.env`, and the Nuclei template set is unpinned. The
  wrappers fail closed on a non-digest image, so this is a gap in coverage, not in
  enforcement. Nuclei ran through the local-binary fallback (decision 0005).
- **The allowlist validates but does not force.** It resolves the target, rejects
  loopback/link-local/metadata/RFC1918 unless explicitly listed, rejects when *any* resolved
  answer is dangerous, and pins the IP — but the P3 wrappers do not yet force the scanner
  onto that pinned IP, and cross-host redirects are not blocked. Both belong to the P4 core.

## Decisions

- 2026-07-23: External database in a **separate compose stack**, not merely a separate
  container, so the application lifecycle cannot destroy data.
- 2026-07-23: TLS at `verify-full` with a local CA. Not for MITM protection on a Docker
  bridge — so the TLS path is genuinely exercised now rather than discovered broken on the
  day the database is swapped for the VinSOC replica.
- 2026-07-23: Deduplication configuration lives in the committed compose file, not `.env`:
  it is reviewable policy, not a secret.
- 2026-07-23: Semgrep hashes on `file_path, line, vuln_id_from_tool`. The Week-1 plan
  specified only the first two, which collapses two different rules firing on the same
  line into one finding. Deviation from a locked decision, accepted by the owner.
- 2026-07-23: `enable_deduplication` is set by `dd-bootstrap.sh` rather than by hand,
  because no environment variable exists for it and a fresh environment would otherwise
  repeat the failure.
- 2026-07-23: Broker is Redis — promoted to [decision 0003](../../decisions/0003-defectdojo-broker-is-redis-not-valkey.md).
- 2026-07-23: CI scoping uses `authorized_users` — promoted to [decision 0004](../../decisions/0004-defectdojo-oss-has-no-role-based-authorization.md).

## Validation

- Focused proof: `scripts/dd-smoke.sh` — **26/26 pass, exit 0**. Covers token auth, data
  model, least privilege (`DELETE` → 403, account not staff/superuser, exactly one grant),
  `DD_DEBUG=False`, non-default keys, live boot-guard rejection, database TLS
  (`ssl=true TLSv1.3`) and plaintext refusal, both dedup dictionaries parsing and
  resolving against `/api/v2/test_types/`, async import reaching a terminal state, and
  deduplication **behaviour**.
- Integration proof: `scripts/dd-backup.sh --drill` — dump → restore into a throwaway
  database → boot the application against it → canary credential AES-decrypts.
- Negative controls, because a check that cannot fail proves nothing:
  - restore drill under a random AES key → `MISMATCH` (the first version of this drill
    stored the canary in plaintext and passed under any key — it was fixed);
  - deduplication disabled → smoke fails 2 checks and exits 1;
  - `sslmode=disable` → refused by `pg_hba`; `verify-full` without the CA → refused;
  - uwsgi forced onto a new IP → nginx 502 until restarted, confirming the documented
    limitation is real.
- Isolation check: the whole standup ran while a 9-run benchmark occupied the host, and
  that benchmark completed unaffected (2740/2740 on every run).

## Result

Not complete. P1 is functionally done and validated; the remaining work is correcting the
Week-1 phase documents that still describe mechanisms this build does not have, after
which P1 can be marked complete and P3 started.

Two limitations are known and disclosed rather than fixed: the exact valkey/Celery
incompatibility is unidentified (decision 0003 follow-up), and `authorized_users` scoping
is asserted at bootstrap rather than continuously (decision 0004 follow-up).
