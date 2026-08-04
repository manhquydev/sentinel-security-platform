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

Recorded for the bounded loopback lab. This section is the source of truth for
the three required decisions above. Each local operator records their own
non-secret public-key pin and adapter path in an untracked operator environment;
the private key and executor credentials remain outside the repository.

- **Trusted approval-key source**
  - owner: the local operator running the acceptance attempt.
  - algorithm: Ed25519. `sentinel-charter-approve.py` signs with `--key-file`
    (PEM private, unencrypted per current loader); `sentinel-charter-executor.py`
    verifies with `--public-key`.
  - public key file: an operator-owned regular file, supplied as
    `SENTINEL_CHARTER_PUBLIC_KEY`; it must not be group/other writable.
    Every directory from the file through its trusted ancestor chain must be
    non-symlink, owned by the operator or root, and non-group/other writable
    (except a root-owned sticky directory such as `/tmp`).
    The corresponding private key stays offline, mode 600, and is never committed.
  - trusted fingerprint: set `SENTINEL_CHARTER_PUBLIC_KEY_SHA256` to the lowercase
    SHA-256 of that key's DER SubjectPublicKeyInfo. Recompute it with
    `openssl pkey -pubin -in "$SENTINEL_CHARTER_PUBLIC_KEY" -outform DER | sha256sum`.
    Preflight calculates the value from the safe public-key file and rejects a mismatch.
  - rotation rule: each operator records a new explicit pin when rotating a key.
    A signature that does not verify against the configured, pinned public key is
    not a valid human approval.

- **Executor adapter principal**
  - principal_name: `sentinel-charter-executor` (Kong OAuth2 plus a route-local
    dedicated API-key guard; ACL groups `charter-read` + `write-basket`).
  - adapter_location_boundary: trusted local operator host, loopback lab only.
    `$SENTINEL_CHARTER_EXECUTOR_ADAPTER` is an executable, non-symlink,
    mode-700 wrapper with the same safe ancestor-directory requirement as the
    public key.
    alone holds `SENTINEL_CHARTER_EXECUTOR_SECRET` and
    `SENTINEL_CHARTER_EXECUTOR_API_KEY` in its own context and invokes
    `scripts/sentinel-charter-executor.py`. Gateway `127.0.0.1:18443`; target
    `127.0.0.1:13000` only.
  - credential_owner: local operator. The secret is never given to any
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

## Approval posture (loopback lab)

For every future approved acceptance dispatch, the operator must sign a fresh
approval artifact only after the fresh v2 request is available for review.
Automatic signing or dispatch is prohibited, including in the loopback lab.
The fresh signed artifact is the required operator confirmation; a previous
approval, test key, or automation exception does not authorize a new run.

The request policy remains bounded in
`agent/charter_requests.py`; it does not replace this confirmation gate.
`README.md` and `docs/Project_Sentinel_6-week.md` remain the product authority
outside the local lab.

Operator artifacts (outside the repo, never committed):

- `~/.sentinel/` — operator-owned directory (700).
- `~/.sentinel/charter-approval.ed25519.pem` — approval private key (600).
- `~/.sentinel/charter-approval.ed25519.pub.pem` — public key (`SENTINEL_CHARTER_PUBLIC_KEY`).
- `~/.sentinel/executor-secret.env` — executor OAuth secret and dedicated API key,
  read only by the adapter (600).
- `~/.sentinel/charter-executor-adapter.sh` — `SENTINEL_CHARTER_EXECUTOR_ADAPTER` (700).
- `~/.sentinel/charter-operator.env` — non-secret env; `source` it before a run.

Kong consumer `sentinel-charter-executor` is provisioned (OAuth2 client-credentials,
dedicated Key Auth credential, ACL `charter-read` + `write-basket`); its credentials
live in `infra/.env` (git-ignored) and are mirrored only into the adapter's secret
store.

## No-secret rules

- Inspect only presence, path type, file mode, and health. Do not paste values.
- Treat `infra/.env`, approval envelopes, public keys, adapter paths, and audit
  extracts as private operational material.
- The controller must not read `SENTINEL_CHARTER_EXECUTOR_SECRET` or
  `SENTINEL_CHARTER_EXECUTOR_API_KEY`.
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

### Base-mode environment-variable names

- `TARGET_URL` set to the loopback target.
- `SENTINEL_LITELLM_ALIAS`
- `LITELLM_MASTER_KEY` present for the controller's labelled-chat stage.
- `SENTINEL_CHARTER_PUBLIC_KEY`
- `SENTINEL_CHARTER_PUBLIC_KEY_SHA256`
- `SENTINEL_CHARTER_EXECUTOR_ADAPTER`
- An image selector that matches the reviewable `NUCLEI_IMAGE` pin in
  `scanners/image-pins.env`: `SENTINEL_NUCLEI_IMAGE_DIGEST`.
  Do not set legacy `NUCLEI_IMAGE` or `NUCLEI_BIN`.
- A local-binary selector is deliberately not admitted by this controller until
  the authorized owner records its path, SHA-256, version, and verified release
  provenance in scanner policy. Do not treat a cached or historic binary as that
  record.

### Dispatch-only environment-variable names or files

- `SENTINEL_CHARTER_APPROVAL_FILE`, a fresh owner-held approval artifact (600).
- `SENTINEL_RUNS_DIR` when a non-default run directory is used.

### Required local services

- Juice Shop reachable on `127.0.0.1:13000`
- Charter Kong reachable on `127.0.0.1:18443`
- LiteLLM reachable on `127.0.0.1:4000`
- DefectDojo nginx reachable on `127.0.0.1:8080`
- LiteLLM, Kong, and Juice Shop report Docker health `healthy`; DefectDojo nginx
  is running.

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

## Executable preflight

Run the no-secret base check before creating a proposal:

```bash
scripts/sentinel-live-preflight.sh base
```

`READY_FOR_FRESH_PROPOSAL` means only that local prerequisites are currently
ready. It is not an approval, dispatch, target request, audit record, or live
acceptance result. If scanner admission blocks, preflight adds one
`INFO scanner-selector-reason <category>` line. The category is intentionally
limited to an operator-safe cause—such as `missing-image-policy-pin`,
`image-policy-mismatch`, or `unregistered-local-binary`—and never prints a
selector value, local path, secret, or raw runtime detail. Record an approved
image pin, or the approved local-binary provenance record, through the
maintainer's normal scanner-policy review before retrying. Do not infer either
record from Docker cache or a historic binary.

After the controller has produced a fresh v2 request and the operator has
signed its approval artifact, verify that specific dispatch candidate:

```bash
scripts/sentinel-live-preflight.sh dispatch RUN_ID
```

`READY_FOR_APPROVED_DISPATCH` is still readiness only. It does not invoke the
adapter, mint OAuth, send a target request, resume the controller, or prove the
terminal acceptance evidence.

## Fresh v2 proposal flow

1. Start from a new run ID.
2. Run `scripts/sentinel-live-preflight.sh base`; stop unless it reports
   `READY_FOR_FRESH_PROPOSAL`.
3. Run the controller only far enough to produce a fresh v2 `request-spec.json`.
4. Verify that the request is current and unexpired.
5. Hand the exact run-local spec to the recorded approval authority.
6. Store only the fresh run-local approval artifact selected by that authority.
7. Run `scripts/sentinel-live-preflight.sh dispatch RUN_ID`; stop unless it
   reports `READY_FOR_APPROVED_DISPATCH`.

Do not substitute a test key, old approval file, or any artifact derived from
R5. If the approval source rejects or revokes, treat that as a valid terminal
zero-dispatch branch.

## Reject branch

Use the recorded trusted approval source to produce `reject` or `revoke`.

Expected outcome:

- No executor invocation
- No OAuth mint or API-key request
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
4. Confirm `scripts/sentinel-live-preflight.sh dispatch RUN_ID` just reported
   `READY_FOR_APPROVED_DISPATCH`.
5. Resume the controller with the fresh approval artifact.
6. Capture only sanitized evidence:
   - manifest path
   - run ID
   - request ID
   - approval decision metadata
   - final receipt metadata
   - current-run evaluation result

Expected approved-request behavior:

- Only the compiled safe-request catalog may be selected: baseline, empty,
  special-character, or 256-character product-search queries; empty-object or
  wrong-type basket POST bodies.
- Every GET stays bounded and non-destructive. Every POST goes through Kong only,
  requires signed HITL, and preserves expected non-mutating 4xx semantics.
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

Do not copy raw audit lines, private keys, OAuth secrets, API keys, authorization headers,
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
