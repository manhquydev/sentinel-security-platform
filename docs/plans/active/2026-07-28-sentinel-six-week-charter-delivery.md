# Execution Plan: Sentinel six-week charter delivery

Date: 2026-07-28

## Status

Active — component/controller code has offline evidence, and the selected Vertex
alias has proven the strict structured-output path through the live request
proposal. The checksum-verified local Nuclei fallback completed scan/import. R5
remains historically `pending` with no live dispatch, but is now permanently
non-resumable: its persisted v1 request spec lacks policy-v2 `purpose` and expired
at `2026-07-28T10:08:19Z`. See the R5 state correction in
`plans/260728-2047-charter-r5-live-get-operator-gate/`.

## Outcome

One reproducible charter-profile command produces sanitized normalized findings JSONL,
grounded report JSONL, only Kong-mediated safe requests with signed HITL, and a
sanitized final report/run manifest for the exact Juice Shop sandbox.

## Context

- Detailed implementation phases: [AgentKit plan](../../../plans/260728-1147-sentinel-six-week-charter-delivery/plan.md).
- Current unblocked execution slice: [topology launcher](../../../plans/260729-0522-sentinel-charter-topology-launcher/plan.md).
  It is a hermetic, Compose-owner startup wrapper only: it cannot advance a
  Charter run or claim fresh live proof. Its scope, research, advisory, and
  adversarial review are recorded in `plans/reports/*260729-1358*`.
- Current supporting documentation slice: [Week-1 fresh-clone reproducibility](../../../plans/260729-1430-week-1-fresh-clone-reproducibility-docs/plan.md).
  It corrects the existing no-secret Trivy-to-redaction instructions and makes the
  provisioned DefectDojo/baseline boundary explicit. It does not reproduce the
  historic two-product lake or advance a Charter run.
- Product contract: [Project Sentinel 6-week charter](../../Project_Sentinel_6-week.md).
- Existing lake work remains active: [DefectDojo standup](defectdojo-data-lake-standup.md). This
  plan reuses it but supersedes automatic finding closure for the charter profile only.
- Source evidence and gaps: `plans/reports/scout-260728-1049-six-week-charter-evidence-audit.md`.

## Scope

In scope:

- Literal `http://127.0.0.1:13000` only; no redirects/external targets; trusted local-template Nuclei-only default DAST and private raw-artifact lifecycle.
- No-close DefectDojo import with durable remote-intent reconciliation, JSONL contracts, grounded real LLM analysis, PII and HTTP-response-injection hygiene.
- Kong-only allowed GET and signed fixed safe `POST /rest/basket` with `{}` and expected 4xx; exact base, five requests/minute, one POST/run, five-second timeout, 64 KiB cap.
- Reject/revoke zero-request proof, non-retriable unknown dispatch recovery, CI artifact handoff, 5–10-case current-run evaluation, metrics, product brief, E2E, demo.

Out of scope:

- ZAP until isolated no-egress network proof; finding reconciliation/closure; successful target mutation;
  GraphRAG, MCP/A2A, multi-agent, vLLM/GPU, external targets, 12-week expansion, hostile same-UID compromise protection, and WORM evidence claims.

## Approach

1. Lock literal scanner/import safety.
2. Publish sanitized normalized/report JSONL and repair required live LLM path.
3. Add a separate, signed fixed-request executor through Kong; preserve generic simulated HITL and reconcile unknown remote effects.
4. Orchestrate with CI artifact handoff, exhaustive hash-bound state, credentialed-chat readiness, then prove 5–10-case no-skip recovery/evaluation/demo from the same command.

## Risks And Recovery

- Missing provider credentials, LiteLLM topology, or a failing real chat route fails before scan/import; no `--no-llm` fallback claim.
- Failed scan/redaction/normalization/import stops downstream; no automated old-finding closure exists to roll back.
- A fresh v2 request may only be proposed under separate user authority. The historic
  R5 artifact must not be mutated, re-signed, or backfilled; `load_spec` refuses it
  before approval/controller network work, and the executor would also refuse its expiry.
- Invalid/rejected/revoked approval fails closed; zero-request semantics are a local
  request-policy result, not proof that R5 can final-verify or become a terminal demo.
  Unknown-dispatch reconciliation is limited to a request-store `unknown` record and
  does not resume a failed manifest or bind evaluator output to a Kong audit.
- Resume requires exhaustive immutable input hashes and forks mismatches; normal teardown never deletes volumes/lake data.

## Progress

- [x] Phase 1 — literal lab/import safety (offline proof passed 2026-07-28).
- [x] Phase 2 — normalized findings and grounded analysis (a separate Vertex Gemini
  Flash Lite alias passed the native strict-schema probe and produced a live grounded report).
- [~] Phase 3 — approved safe request executor (offline implementation,
  purpose-binding, receipt metadata, and atomic local bounded-response
  terminalization are complete). The formerly planned R5 live approval path is
  blocked/non-resumable because its persisted v1 spec is invalid under v2 and expired;
  no target request was sent.
- [x] Phase 4 — controller and manifest through proposal, including the separately
  verified offline CI artifact terminal/binding (the live literal-origin R5 run
  passed scan/import/analysis/proposal and recorded a pending approval stage; it
  cannot now resume because its persisted spec fails the current v2 loader).
- [~] Phase 5 — no-skip acceptance, recovery, docs, demo (offline E2E/evaluation pass;
  evaluator UUID false-positive remediation is complete with focused and demo
  regression evidence; complete live demonstration remains pending).
- [x] Topology readiness slice — deterministic existing-owner startup is complete
  as an offline contract. It verifies non-evaluating private-env handling,
  prerequisite/fresh-Kong rejection, exact owner order, and bounded `running`
  status admission; it does not supply service-health or fresh live-Charter proof.
- [x] Week-1 fresh-clone documentation slice — corrected the Trivy image-input
  quick-start, separated its no-secret scan/redaction proof from provisioned lake
  import/verification, and repaired repository-root Compose examples. Offline
  documentation contract and security regressions passed; no Docker/image runtime
  rehearsal or Charter run was attempted.
- [x] Charter RAG contract-runner slice — added a canonical hermetic entry point
  for the committed corpus/retrieval unit contract, with an external-CWD and
  missing-venv regression test. It does not run or replace the live-store suite.
- [x] Safe response-preview slice — GET now produces only a 512 UTF-8-byte/256-
  scalar guard-approved projection in strict receipt v2; one strict
  `application/json; charset=utf-8` media observation is required and v1 remains
  metadata-only for POST/existing receipts. Full-body classification remains at
  the executor boundary. Controller adapter streams are captured only in memory
  with 4096-byte per-stream caps, and helper/rendered-config digests participate
  in resume identity. Offline proof: controller 149/0, focused contracts 64/0,
  evaluator 12/0; no live request was sent.

## Decisions

- 2026-07-28: The six-week charter is the delivery contract for this work.
- 2026-07-28: The only authorized origin is the literal local Juice Shop sandbox; no generic Internet target support.
- 2026-07-28: Automated DefectDojo imports never close old findings.
- 2026-07-28: The real POST is fixed, signed, Kong-only, no-session `POST /rest/basket` `{}`; expected 4xx proves transit without state mutation.
- 2026-07-28: Quotas are five requests/minute and one POST/run; timeout is five seconds, persisted response cap 64 KiB, unknown dispatch consumes its reservation.
- 2026-07-28: A credential-owning executor is a separate trust boundary. An arbitrary
  executable adapter path is only an interface precondition, not evidence that the
  adapter is trusted. Same-UID host compromise and tamper-evident/WORM evidence are
  outside the capstone threat model and must not be claimed otherwise.
- 2026-07-28: Phase 3 implementation may proceed against the typed Phase 2 interface while the
  credentialed LiteLLM gate remains pending; the Phase 4 controller must require that gate before
  it can claim a complete charter run.
- 2026-07-28: The charter analysis default is `sast-grok45`. `sast-sol` remains a
  frozen benchmark alias: its current provider credential route returns 404, whereas
  the selected alias passed the same-base required provenance-labelled chat gate.
- 2026-07-28: Missing HITL input pauses at the first incomplete `approval` stage
  (exit 75); it neither auto-approves nor converts an absent human decision into a
  terminal rejection. Resume requires the exact existing immutable identity.
- 2026-07-28: The controller never receives the executor OAuth secret. A separately
  provisioned executable `SENTINEL_CHARTER_EXECUTOR_ADAPTER` is an interface boundary;
  executable status alone does not establish adapter trust. In the selected response-
  preview follow-on, the executor is the trusted full-body guard boundary and the
  controller uses bounded in-memory adapter capture, discards stderr, and validates
  only the strict typed receipt projection before durable publication. It does not
  claim it can reconstruct discarded raw response classification.
- 2026-07-29: Resume identity is bound to the actual rendered Kong configuration,
  not merely its template. The renderer's dynamic-scope output-variable collision
  was fixed so a changed public test env value produces a different rendered hash;
  the controller refuses that mismatch before stage dispatch. The renderer remains
  a parser of exact required keys, never a shell source of the env file.
- 2026-07-28: `sast-charter-vertex-gemini-flash-lite` is an isolated Vertex AI alias
  for charter analysis only. LiteLLM receives the user-owned ADC as a single read-only
  mount; frozen benchmark aliases remain unchanged.
- 2026-07-28: Proposal generation accepts only validated `ReportFinding` instances.
  Persisted JSONL is reparsed through that strict type before it reaches the immutable
  GET/POST policy; a dict merely shaped like a report cannot produce a request.
- 2026-07-28: The fixed request policy is purpose-bound v2: purpose is derived only
  from the admitted GET/POST shape, included in the existing signed canonical
  request, and persisted specs fail closed before signer, controller, or executor
  side effects. This preserves the charter's existing operator-visible-purpose
  requirement; no product-brief change is needed.
- 2026-07-28: The sealed receipt digest is trusted-adapter metadata, not an
  authenticated Kong audit artifact. The offline contract limits what may be
  persisted/evaluated, but does not replace the live adapter, approval, target,
  or authoritative-audit gates; pre-commit remote-unknown recovery and historical
  `observed` remediation remain executor debt.
- 2026-07-28: Red-team evidence supersedes the prior R5 approval-pending recovery
  assumption. The R5 `request-spec.json` is an expired v1 artifact without `purpose`;
  current `load_spec` refuses it before signer/controller network work and executor
  validation would separately reject expiry. Do not mutate, re-sign, or backfill it.
  A v2 proposal and new run require separate user authority.

## Validation

- Plan validation: `ak plan validate plans/260728-1147-sentinel-six-week-charter-delivery --json --no-interactive`.
- Implementation proof is specified in the linked plan: focused offline contracts, required `REQUIRE_*=1` live gates, controller E2E, and injected recovery.
- Phase 1 offline proof (2026-07-28, review fixes F1–F5 and re-review S1–S2 included):
  `bash tests/charter-scan-safety-test.sh` (27 passed, including
  redirect-before-scanner, nested encoded-delimiter removal, concurrent import
  serialization, import-failure quarantine, actual-wrapper stderr retention and
  cleanup, and gate-aware resume);
  `bash tests/target-allowlist-test.sh` (9 passed);
  `bash tests/core-gate-test.sh` (20 passed); and
  `bash tests/redaction-guarantee-test.sh` (43 passed); plus the affected
  `bash tests/wrapper-status-test.sh` (15 passed). No Docker scan, live target
  mutation, or DefectDojo import was run.
- Phase 2 offline proof (2026-07-28): final source review passed; final independent
  test evidence is 34 assertions plus two intentional no-service skips. It covers
  malformed/empty/fully-filtered no-call behavior, 0600 paired JSONL failure handling,
  corpus tamper rejection, bounded SQLi/XSS content+provenance retrieval, PII/IPI
  quarantine, model-fact rejection, and a LiteLLM stub proving `/health` 404 cannot
  dispatch chat while `/health/liveliness` HTTP 200 is required. See
  `plans/reports/code-review-260728-1147-phase2-final.md` and
  `plans/reports/tester-260728-1147-phase2-final.md`. No credentialed LiteLLM chat
  was run. A SIGKILL/power-loss pair mismatch is a Phase 4 manifest-recovery case,
  not an atomic-publication claim.
- Phase 3 offline proof (2026-07-28): final independent review and validation passed,
  including 20 repeated focused test runs, six-process quota proof, static Kong rendering,
  revoke-before-dispatch zero I/O, JSONL audit reconciliation for a request-store
  `unknown` state, restart recovery, and the
  unchanged generic HITL suite. See `plans/reports/code-review-260728-1147-phase3-accepted-review.md`
  and `plans/reports/tester-260728-1147-phase3-accepted.md`. No real Kong/OAuth/audit/Juice
  Shop interaction was used. An earlier test bug deleted untracked generated
  `infra/kong/kong.rendered.yml`; the test is now temp-output-only, but Git cannot restore
  that untracked file.
- Live gates (2026-07-28): `REQUIRE_LITELLM=1 SENTINEL_LITELLM_ALIAS=sast-grok45`
  passed the same-base liveliness and provenance-labelled chat path (9 passed, 0 failed,
  1 intentional non-agent skip). `REQUIRE_KONG=1 SKIP_KONG_LIVE=0 bash
  tests/gateway-authz-test.sh` passed 33/0, including read ACL, forbidden agent POST,
  route-escape refusal, and secret-free structured audit output. This is not a signed
  executor receipt proof.
- Current offline regression (2026-07-28): scan safety 27/0; target policy 9/0; core
  gate 20/0; redaction 43/0; wrapper 15/0; workflow 17/0; LiteLLM preflight 3/0;
  request/HITL 5/0 (also 20 consecutive focused quota runs); charter analysis 15/0;
  controller 40/0; E2E/evaluator 4/0.
- Docker image pull did not complete, but the accepted local-binary fallback was downloaded
  from the official Nuclei v3.11.0 release, resumed, checksum-verified, and used only for
  the live runs. A real compatibility defect in the charter template (`not in` DSL syntax)
  was repaired to `!contains(...)`, its reviewed manifest hash updated, and safety/redaction
  tests re-passed. `live-charter-260728-analysis-recorded` passed preflight, labelled chat,
  topology, Nuclei scan, redaction, no-close DefectDojo import, and gate observation; it then
  stopped at `analysis-report`. The provider returned ordinary remediation prose despite the
  strict JSON-schema response request, so the report contract rejected it with no partial
  report and the manifest records exactly that failed stage with one LLM and application error.
  A single bounded repair probe treated that prose as untrusted data and again requested only the
  schema; the same alias returned prose. `sast-sol`, `sast-terra`, `sast-gpt55`, and
  `local-onprem` failed their credential/provider probes. These probes showed that the
  earlier router configuration, rather than the parser, lacked a usable structured-output alias;
  the later Vertex/live proof below establishes the verified replacement.
  No approval, executor request, receipt, or final result is claimed. The reviewed image digest
  has not been persisted in `scanners/image-pins.env`: the local harness blocked that file by
  filename as sensitive, so persistence still needs explicit tool approval.
- Vertex/live controller proof (2026-07-28): direct Vertex and LiteLLM alias probes both
  passed the strict JSON-schema `{"status":"ok"}` contract. Static gateway validation
  passed 34/0, LiteLLM preflight passed 3/0, and the real provenance recon gateway test
  passed 9/0 (one optional analysis skip). Full run
  `live-charter-260728-vertex-gemini-flash-lite-r5`, using the verified local Nuclei
  v3.11.0 fallback, passed preflight, labelled chat, topology, scan/redact/no-close
  import, analysis report, and fixed request proposal. It is intentionally `pending`
  at `approval`; no approval, executor, receipt, or target state-changing request exists.
  A proposal boundary bug exposed during the first live attempts is covered by
  `tests/test_charter_proposal.py` (4/0): persisted JSONL must become a typed
  `ReportFinding` before it can reach the fixed request policy.
- Purpose-binding completion (2026-07-28): the purpose-bound v2 policy, shared
  persisted-spec validation, signer display, and proposal authority cleanup passed
  focused pytest (15 passed), charter HITL request wrapper (11 passed), Sentinel
  demo shell suite (41 passed), Python compilation, and `git diff --check`. The
  red-team non-finite-expiry bypass is closed: `NaN`, `+inf`, and `-inf` are
  refused before token mint or transport. No live approval, executor dispatch,
  receipt, or target request was performed; see
  `plans/reports/tester-260728-1913-purpose-binding-validation.md`.
- Receipt-contract sealing (2026-07-28): the offline receipt metadata slice
  passed 14 request pytest cases, 8 evaluator pytest cases, 63 Sentinel demo
  cases, and 14 HITL request cases. Python compilation, shell syntax validation,
  `git diff --check`, and receipt-plan validation passed. No live approval, OAuth
  material, Kong audit/request, or target call was made. The digest therefore
  remains trusted-adapter metadata, not authenticated Kong audit evidence; live
  approval, isolated adapter dispatch, authoritative audit, and executor crash
  recovery remain open.
- Atomic local terminalization (2026-07-28): the normal bounded-response executor
  path now records its receipt digest and direct terminal transition atomically, so
  it no longer leaves a local `observed` crash gap. The focused request suite passed
  50 tests twice independently; Python compilation, Sentinel demo shell syntax,
  diff checking, and the atomic-slice plan validation also passed. Independent review
  and follow-up hardening closed fail-open status typing and duplicate-key Kong-log
  parsing. A pre-commit remote outcome is still `unknown` until request-store audit
  reconciliation; that mechanism does not resume a failed manifest or make an
  evaluator bind an authoritative Kong audit. Historical `observed` state still
  requires remediation. See
  [atomic terminalization plan](../../../plans/260728-2006-charter-observed-state-recovery/plan.md)
  and [review](../../../plans/reports/code-reviewer-260728-2026-atomic-terminalization.md).
- Evaluator typed-identifier remediation (2026-07-29): a canonical request UUID
  could deterministically match the generic phone regex. The evaluator now has a
  field-and-value-scoped generic-value exemption only for the exact `request_id`
  literal and lowercase canonical UUID, while prior sensitive-key, JWT, and
  credential checks remain in force. Direct/nested boundaries and sent-action
  artifact `evaluate` plus `verify` coverage passed; focused pytest passed 11
  tests (10 subtests), the Sentinel demo passed 100/0, compilation, diff check,
  and plan validation passed. No live service, OAuth, Kong, or target action was
  performed. See [typed identifier plan](../../../plans/260729-0153-charter-evaluator-typed-identifier-sanitization/plan.md).
- Gateway redirect no-follow remediation (2026-07-29): the generic Gateway
  client now preserves the original response for OAuth token minting and target
  reads rather than following redirects. The offline regression passed 10 tests;
  its intercepted adapter/socket-guard matrix for 301/302/307/308 saw only the
  initial Kong URL, while its no-flag control recorded a follow-up. Compilation,
  diff check, plan validation, and independent review passed. No OAuth, Kong,
  target, consumer, or other live validation was performed; this is not live
  gateway proof. See the [redirect no-follow plan](../../../plans/260729-0204-charter-gateway-redirect-no-follow/plan.md).
- CI artifact handoff terminal (2026-07-29): the source-specific no-secret CI
  branch now produces only private admitted Trivy snapshots, strict normalized
  JSONL, final manifest, and CI binding. Its direct-production and verifier
  coverage passed 111/0, focused Trivy coverage passed 5/5, and all five exact
  checkpoint-recovery cases passed. Red-team root-path bypass coverage was fixed
  and revalidated. This is offline terminal/binding evidence only: it does not
  claim full charter completion or a live CI execution. See the
  [CI artifact handoff plan](../../../plans/260729-0240-ci-artifact-handoff-terminal/plan.md).
- Public verification evaluation seal (2026-07-29): approved review and the offline
  Sentinel demo shell suite passed 123/0. Public verification remains manifest-first,
  then dispatches `local` to the deterministic evaluator's `verify` and `ci` only to
  `ci-verify`; the checks retain local no-repair failure behavior and the CI
  five-artifact/no-evaluator boundary. This is local offline verification evidence,
  not a live run, live CI execution, or full-charter completion claim. See the
  [verification seal plan](../../../plans/260729-0330-charter-public-verify-evaluation-seal/plan.md).
- Resume identity v2 (2026-07-29): new charter manifests bind their closed,
  secret-free execution identity, completed artifact checkpoints, and remote-effect
  records before resume. Pending v1 records remain historical and non-resumable;
  unresolved v2 effects are reconciliation-only rather than replayable. This is
  offline controller evidence, not live dispatch or full-charter completion. See the
  [resume identity plan](../../../plans/260729-0350-charter-resume-identity-v2/plan.md).

## Result

The charter implementation has a real structured-output provider and a historical live path
through the fixed request proposal. No live dispatch occurred for R5. Its v1 persisted request
spec is invalid under current v2 policy and expired, so it is not an approval candidate and
cannot supply terminal evaluator/manifest evidence. A fresh v2 proposal/new run, if desired,
requires separate user authority; it must not rewrite, re-sign, or backfill R5. Local normal
bounded-response terminalization is complete; remote unknown reconciliation and historical
`observed`-state remediation remain separate debt.
The CI artifact handoff terminal is complete as a separate offline, no-secret
boundary; it neither advances the pending R5 approval nor supplies live CI or full
charter terminal evidence.
The completed public verification seal similarly certifies only the local evaluator
or CI handoff boundary; it does not advance R5 or establish live/full-charter
completion.
The completed v2 resume boundary protects newly created runs without changing that
historical R5 status or authorizing a live retry.
