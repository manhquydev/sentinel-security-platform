# Execution Plan: Sentinel six-week literal closure

Date: 2026-08-04

## Status

Completed — verified from source, tests, and a fresh local runtime run.

## Outcome

Complete the six-week Sentinel charter against code, tests, and observable
local runtime evidence. No optional expansion work starts before this plan has
either produced a terminal live acceptance run or recorded its exact runtime
blocker.

## Context

- Product contract: [Project Sentinel six-week charter](../../Project_Sentinel_6-week.md).
- Independent research: [charter closure evidence](../../../plans/reports/research-260804-1124-charter-closure-evidence.md).
- Accepted operating frame: [charter advisory](../../../plans/reports/advise-260804-1124-sentinel-charter-reframe.md).
- Existing controller: `scripts/sentinel-demo.sh`.
- Existing request policy: `agent/charter_requests.py`.

## Scope

In scope:

- Private, exclusive HITL approval output.
- Dedicated gateway API key with no secret logging.
- Immutable safe request/header/payload catalog, bounded to the local Juice Shop
  target and existing Kong controls.
- Actual normalizer-to-controller data handoff.
- Grounded report quality and focused proof.
- A real local acceptance attempt, current-run evaluation, metrics, and
  truthful documentation.

Out of scope:

- GraphRAG, multi-agent, MCP/A2A, vLLM/GPU, LLM-as-a-Judge, generic fuzzing,
  exploitation, external targets, and successful target mutation.

## Approach

1. Lock down approval publication and request-policy data types with tests.
2. Add literal API-key gateway authentication without removing ACL/OAuth
   boundaries.
3. Make the controller process a complete normalized aggregate before analysis.
4. Preserve deterministic, source-grounded report fields.
5. Validate offline contracts, then run a real local acceptance attempt only
   through the configured safe workflow.
6. Update user-facing documentation only for behavior actually proven.

## Risks And Recovery

- A live run can be blocked by unavailable service health, private credentials,
  scanner image, or approval key. Stop at the failed gate; do not fabricate a
  receipt or substitute fixture output.
- A second gateway credential increases secret surface. Keep it executor-only,
  hidden from proxied/logged traffic, and never commit its value.
- Broader request cases could become a fuzzing mechanism. Use an enum/catalog
  and reject every other shape before signing or transport.
- If a new request fails/causes unknown dispatch, preserve the run and do not
  retry it.

## Progress

- [x] Establish independent evidence baseline and technical research.
- [x] Make approval artifact publication private and create-once.
- [x] Add dedicated API-key gateway boundary and tests.
- [x] Add immutable safe request catalog and tests.
- [x] Connect normalized aggregate to charter controller flow.
- [x] Strengthen grounded report proof and evaluate coverage.
- [x] Run offline regression gates.
- [x] Attempt one real local terminal acceptance run.
- [x] Reconcile documentation and record result.

## Decisions

- 2026-08-04: Charter wording is interpreted literally where it does not weaken
  security: a dedicated API key is added alongside current identity/ACL
  controls.
- 2026-08-04: Safe input coverage is an immutable catalog, not a generic
  request tool.
- 2026-08-04: Synthetic E2E remains regression evidence only.

## Validation

- Focused: signer, request-policy, controller, gateway-template, normalizer,
  report, PII/prompt-injection suites.
- Regression: `tests/sentinel-demo-test.sh`,
  `tests/sentinel-charter-e2e-test.sh`, scanner safety, and the relevant
  Python suite.
- Runtime: `scripts/sentinel-live-preflight.sh base`, then a real
  same-run local controller execution only if all gates pass.

## Result

Completed on 2026-08-04 from current source and current local runtime evidence:

- Focused Python contracts passed (111 tests / 36 subtests); charter HITL,
  scanner-safety, evaluator, synthetic E2E, and controller regression gates
  passed (the latter contains 201 safety cases).
- Kong was rebuilt from a clean Kong DB after policy changes. The injected
  live-gateway boundary test passed 43 assertions: public ACL access, forbidden
  routes, dual executor credentials, exact upstream rewrite, no token-route
  escape, and no credential in the audit stream.
- Fresh local run `charter-live-260804-local-003` completed scan → sanitize →
  import → grounded report → fixed proposal → signed approval → executor →
  response guard → final report → evaluation. It recorded one approved GET,
  HTTP 200, zero LLM/application errors, four true positives and one true
  negative in the current reviewer set, and no false positive/negative.
- The run's artifacts are private (`0600`). One authoritative Kong audit record
  correlated with its immutable request ID, executor consumer, and response
  status; it contained neither Authorization nor the API-key header.

Earlier fresh runs `...-001` and `...-002` are retained as private diagnostic
evidence only. They do not count as acceptance: the first exposed a response
projection/evaluator mismatch, and the second exposed a stale reviewer set.
