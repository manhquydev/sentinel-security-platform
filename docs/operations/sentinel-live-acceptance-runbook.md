# Sentinel Live Acceptance Runbook

This runbook is the operator-facing procedure for one fresh bounded local
acceptance attempt against the six-week charter. It is intentionally no-secret:
it names files, environment-variable names, permissions, and evidence classes,
but never prints values, private keys, bearer tokens, raw audit payloads, or raw
response bodies.

## Scope

- Target is the loopback Juice Shop lab only: `http://127.0.0.1:13000`.
- Gateway transit is through the local Charter Kong path only.
- Historical R5 is prohibited. Do not reuse, mutate, re-sign, resume, or
  backfill `live-charter-260728-vertex-gemini-flash-lite-r5`.
- A rejected decision is valid zero-dispatch evidence, but it does not close the
  charter's approved-request acceptance requirement.

## Required decisions

Do not dispatch an approved request until the product owner records all three
decisions below.

| Decision | Required record | Current effect when absent |
|---|---|---|
| Trusted approval-key source | Key owner, permitted fingerprint or rotation rule, and who may create the approval envelope | No approve-and-dispatch branch |
| Executor adapter principal | Named operator or service principal, controlled adapter location, and executor-secret ownership boundary | No adapter invocation |
| Authoritative Kong audit source | Exact source, access method, retention window, and source-identity or digest rule for this local threat model | No live acceptance claim and no `unknown` terminalization |

Until those records exist, stop after readiness or reject-branch proof. Do not
guess a key, adapter principal, or audit stream from a test fixture, generated
artifact, environment-variable name, or a running container.

## Recorded authority decisions

Recorded 2026-07-30 by product owner `manhquy`. Bounded loopback lab only. This
section is the source of truth for the three required decisions above; an agent
may proceed past the authority gate on these values without re-interviewing the
owner. No secret values appear here (owner, key fingerprint, principal name,
paths, and policy only).

- **Trusted approval-key source**
  - owner: `manhquy` (product owner / local operator).
  - algorithm: Ed25519. `sentinel-charter-approve.py` signs with `--key-file`
    (PEM private, unencrypted per current loader); `sentinel-charter-executor.py`
    verifies with `--public-key`.
  - public key file: `~/.sentinel/charter-approval-manhquy.ed25519.pub.pem`
    (set as `SENTINEL_CHARTER_PUBLIC_KEY`). Private key held offline, mode 600,
    never committed.
  - trusted fingerprint (pin this exact key): SHA-256 of the DER SubjectPublicKeyInfo =
    `93d82ca0c299d3df6adaec268b0a76356989a5798fa9f2d489cec477e2ac3098`.
    Recompute to verify: `openssl pkey -pubin -in "$SENTINEL_CHARTER_PUBLIC_KEY" -outform DER | sha256sum`.
  - rotation rule: one key per acceptance campaign; revoke = replace the pinned
    fingerprint above and re-record. A signature that does not verify against the
    pinned public key is not a valid human approval.

- **Executor adapter principal**
  - principal_name: `sentinel-charter-executor` (Kong OAuth2 consumer; ACL groups
    `charter-read` + `write-basket`).
  - adapter_location_boundary: trusted local operator host, loopback lab only.
    `$SENTINEL_CHARTER_EXECUTOR_ADAPTER` is an executable, non-symlink wrapper that
    alone holds `SENTINEL_CHARTER_EXECUTOR_SECRET` in its own context and invokes
    `scripts/sentinel-charter-executor.py`. Gateway `127.0.0.1:18443`; target
    `127.0.0.1:13000` only.
  - credential_owner: `manhquy` / local operator. The secret is never given to any
    agent, supervisor, or the controller.

- **Authoritative Kong audit source**
  - source_name: Kong `file-log` plugin to `/dev/stdout`, captured by the Docker
    logging driver of the `sentinel-kong` container (raw nginx access log off;
    Authorization/token stripped before serialization, so the stream is audit-only).
  - access_method: `docker logs sentinel-kong` (charter Kong, `127.0.0.1:18443`).
  - retention_window: 7 days.
  - source_identity_or_digest_rule: bind an audit line to a run by run-local
    `request_id` + consumer `sentinel-charter-executor` + route, within the run's
    time window. A local `receipt_digest` is adapter metadata, not authoritative
    Kong evidence.

## Automation posture (loopback lab)

Owner `manhquy` authorized full automation of the approve-and-dispatch chain in
the bounded loopback lab on 2026-07-30. This **supersedes, for this local lab
only, the earlier "no automatic approval" handoff bound**: an agent may sign and
dispatch without an interactive human step here. The decision is recorded, not silent.
The approval control itself is unchanged — a valid Ed25519 approval envelope is
still mandatory and is still verified by the executor before any dispatch; only the
human keystroke is automated by an owner-held key in this lab. This lab exception
does NOT relax the product charter's human-approval requirement for any non-lab or
risky request; `README.md` and `docs/Project_Sentinel_6-week.md` remain the product
authority outside this loopback lab.

Safety does not rest on the human step; it rests on compiled-in bounds in
`agent/charter_requests.py`:

- Immutable gateway origin `https://127.0.0.1:18443` (asserted; cannot be
  redirected to any external target).
- Exactly two purpose-bound requests are accepted: `GET /rest/products/search?q=apple`
  and `POST /rest/basket` body `{}` (expected 4xx, no target-state change). Any
  other method/path/query/body is refused at `load_spec`, so auto-approval cannot
  sign anything outside this set.
- Target is loopback Juice Shop only. No destructive payloads are expressible.

Operator artifacts (outside the repo, never committed):

- `~/.sentinel/charter-approval-manhquy.ed25519.pem` — approval private key (600).
- `~/.sentinel/charter-approval-manhquy.ed25519.pub.pem` — public key (`SENTINEL_CHARTER_PUBLIC_KEY`).
- `~/.sentinel/executor-secret.env` — the executor OAuth secret, read only by the adapter (600).
- `~/.sentinel/charter-executor-adapter.sh` — `SENTINEL_CHARTER_EXECUTOR_ADAPTER` (700).
- `~/.sentinel/charter-auto-approve.sh` — signs a fresh spec non-interactively (700).
- `~/.sentinel/charter-operator.env` — non-secret env; `source` it before a run.

Kong consumer `sentinel-charter-executor` is provisioned (OAuth2 client-credentials,
ACL `charter-read` + `write-basket`); its secret lives in `infra/.env` (git-ignored)
and is mirrored only into the adapter's secret store.

Verified 2026-07-30 — the **approved-request dispatch + authoritative Kong audit
sub-gate only** (NOT the full six-week charter acceptance). Both compiled-in
requests were auto-approved and dispatched fresh v2:

- `GET /rest/products/search?q=apple` → adapter receipt `status 200`; Kong file-log
  `consumer=sentinel-charter-executor route=charter-search status=200 method=GET`.
- `POST /rest/basket` `{}` → adapter receipt `status 401`, `post_expected_4xx: true`
  (non-mutating); Kong file-log `consumer=sentinel-charter-executor route=basket-write
  status=401 method=POST`.

Still pending (not proven by the above): the complete controller live demonstration
(scan → import → analysis → proposal → approval → executor → evaluation) and the
six-week ledger closure in
`docs/plans/active/2026-07-28-sentinel-six-week-charter-delivery.md`. README and the
ledger still correctly say the *full* terminal live demo is not yet claimed.

## No-secret rules

- Inspect only presence, path type, file mode, and health. Do not paste values.
- Treat `infra/.env`, approval envelopes, public keys, adapter paths, and audit
  extracts as private operational material.
- The controller must not read `SENTINEL_CHARTER_EXECUTOR_SECRET`.
- A local `receipt_digest` is adapter metadata, not authoritative Kong evidence.
- Never store raw Kong file-log lines or raw target-response bodies in a tracked
  document, shell history snippet, report, or commit.

## Preflight checklist

Record pass or block for each item by name only.

### Required repository/runtime paths

- `rag/.venv` exists.
- `infra/.env` exists and is a regular file.
- `plans/260730-1018-sentinel-fresh-bounded-live-acceptance-closure/` remains the
  active AgentKit execution slice for this work.

### Required environment-variable names or files

- `SENTINEL_LITELLM_ALIAS`
- `SENTINEL_CHARTER_APPROVAL_FILE`
- `SENTINEL_CHARTER_PUBLIC_KEY`
- `SENTINEL_CHARTER_EXECUTOR_ADAPTER`
- Exactly one admitted scanner runtime selector:
  - `SENTINEL_NUCLEI_IMAGE_DIGEST`, or
  - `SENTINEL_NUCLEI_BIN`

### Required local services

- Juice Shop reachable on `127.0.0.1:13000`
- Charter Kong reachable on `127.0.0.1:18443`
- LiteLLM reachable on `127.0.0.1:4000`

### Required evidence policy

- Fresh v2 request only. No R5 reuse.
- Focused offline proof is green before any live action:
  - `pytest -q tests/test_charter_requests.py`
  - `bash tests/charter-hitl-request-test.sh`
  - `bash tests/sentinel-demo-test.sh`
- Every run uses a new safe run ID.

If any item above is missing, stop with a blocked readiness report. Do not
download tooling, create secrets, generate approval keys, or infer operator
authority inside this runbook.

## Fresh v2 proposal flow

1. Start from a new run ID.
2. Run the controller only far enough to produce a fresh v2 `request-spec.json`.
3. Verify that the request is current and unexpired.
4. Hand the exact run-local spec to the recorded approval authority.
5. Store only the run-local approval artifact selected by that authority.

Do not substitute a test key, old approval file, or any artifact derived from
R5. If the approval source rejects or revokes, treat that as a valid terminal
zero-dispatch branch.

## Reject branch

Use the recorded trusted approval source to produce `reject` or `revoke`.

Expected outcome:

- No executor invocation
- No OAuth mint
- No request dispatch
- No receipt artifact
- A factual terminal record showing zero dispatch

This branch is safe to demonstrate before an approved run, but it is not proof
of the charter's approved-request requirement.

## Approved branch

Run this branch only after the three decisions are recorded and every preflight
gate passes.

1. Confirm the executor adapter is the recorded principal boundary.
2. Confirm the trusted public key path matches the recorded approval-key source.
3. Confirm the selected scanner runtime is explicitly admitted for this run.
4. Resume the controller with the fresh approval artifact.
5. Capture only sanitized evidence:
   - manifest path
   - run ID
   - request ID
   - approval decision metadata
   - final receipt metadata
   - current-run evaluation result

Expected approved-request behavior:

- Fixed safe GET path remains bounded and non-destructive.
- The fixed POST path goes through Kong only and preserves the expected bounded
  non-mutating 4xx semantics.
- No required skip is accepted as success.

## Unknown outcome handling

If the executor branch becomes `unknown`, stop immediately.

- Do not retry.
- Do not mint a second token.
- Do not create a second approval.
- Do not mutate the original run directory.

For a durable `unknown` outcome only, the controller publishes
`recover-audit ID` under its bounded `audit-v1` contract. It reads the fixed
Kong log source, never retries or dispatches, and can terminalize only as
`recovered`. That limited result is not a receipt, response-guard, normal final
report, or evaluation proof; it does not make the run a live-acceptance success
or permit ordinary resume. All other `unknown` states remain preserved and
blocked.

## Evidence capture

Capture references and digests, not secret values:

- run directory path
- manifest path and digest
- request-spec path and digest
- approval artifact path and digest
- selected audit-source reference or digest
- receipt artifact path and digest
- evaluation artifact path and digest

Do not copy raw audit lines, private keys, OAuth secrets, authorization headers,
or full response bodies into notes or tracked files.

## Stop conditions

Stop and report the exact gate if any of these occurs:

- missing authority decision
- missing or non-current approval artifact
- missing admitted scanner runtime
- missing executor adapter or trusted public key
- required local service unavailable
- focused proof not green
- required skip reported
- `unknown` executor outcome
- missing or ambiguous authoritative Kong audit evidence

The correct blocked result is a factual readiness report, not fabricated
acceptance evidence.
