# 0001 Benchmark LLM provider and model family

Date: 2026-07-23

## Status

Accepted

## Context

The AI-SAST benchmark's V0 baseline ran on `deepseek/deepseek-chat` through a local
LiteLLM proxy. That round ended prematurely: the account balance was exhausted mid-run,
run 3 returned 2740 silently-empty results, and the arm closed at n=2 instead of the
planned n=3. A replacement inference provider was needed to finish the measurement and
to continue the Sentinel work that depends on it.

The clawcmc agent router (`https://router.clawcmc.io.vn/v1`) was available. Two
questions had to be settled before committing: whether it could serve the engine at
all, and whether results obtained through it would mean anything.

## Decision

Benchmark inference runs through the clawcmc router on the **`cx/*` model family**:
`cx/gpt-5.6-sol`, `cx/gpt-5.6-terra`, `cx/gpt-5.5` (aliases `sast-sol`, `sast-terra`,
`sast-gpt55`).

The frozen DeepSeek arm (`runs/scorecard-v0-final.json`, `runs/v0-metis-owasp-benchmark-run{1,2}/`)
is preserved unmodified as the comparison baseline and is never re-run.

Constraints that are part of this decision:

- **Only the `cx/*` family is usable.** Metis calls `/v1/responses` (hardcoded
  `use_responses_api: True`), and `cx/*` is the only family on this router that
  implements it. The originally selected `ag/gemini-3.5-flash-*` tiers answer that
  endpoint with a `chat.completion` object and empty `usage`, which LiteLLM cannot
  parse — HTTP 500 on every call. `glm/glm-5.2` returns HTTP 429.
- **Public corpora only.** The router publishes no retention or training terms.
  OWASP Benchmark and WebGoat only; private Sentinel code requires a terms review
  first. This is currently enforced by convention and hardcoded target paths, not by
  an assertion — see Follow-Up.
- **Results are not attributable to the base model.** The router injects a fixed
  3,231-token system prompt into every request. Published figures measure
  *Metis + model + gateway prompt*.

## Alternatives Considered

1. **Top up the DeepSeek account and finish the original arm.** Rejected: it would have
   reproduced a baseline already known to be weak (P 0.55) rather than answering
   whether a better provider existed.
2. **Patch Metis to use `/v1/chat/completions`.** This was the path required by the
   `ag/*` family. Rejected once `cx/*` was available: it would have modified the
   vendored engine, weakening the "engine identical to V0" comparability constraint.
3. **Direct Gemini API instead of a router.** Would have restored cost tracking,
   structured output and embeddings, and removed the gateway prompt. Not pursued
   because router credentials were already provisioned; remains the cleaner option if
   base-model attribution is ever needed.

## Consequences

Positive:

- All three `cx/*` tiers beat the DeepSeek baseline on both precision and recall. The
  ordering sol > terra > gpt55 > deepseek is robust across every metric variant tested.
- `trustbound`, a total detection gap for DeepSeek (recall 0.00), is attempted by every
  router tier (sol: 0.65 recall at 0.89 precision).
- n=3 per tier closes the sample-size deviation the DeepSeek round could not.
- Token accounting comes from the response body on the path the engine actually uses,
  which is a better source than the LiteLLM spend database originally planned.

Tradeoffs:

- **No cost data at all.** LiteLLM cannot price these models and the router returns
  `usage.cost: null`. Manifests record `spend_usd: null` with a reason, never `0`.
  Cost is not comparable across arms.
- **Backing model is not observable.** LiteLLM rewrites the response `model` to the
  local alias, so provider-side model drift cannot be detected. Declared as a blind
  spot rather than covered by a check that would always pass.
- **No embeddings model**, so Metis indexing stays off: single-file review, not the
  engine's full capability.
- Throughput is router-capped. Running tiers in parallel yields ~1.17x aggregate, not
  the near-linear scaling initially assumed.

## Follow-Up

- The "public corpora only" boundary has no assertion behind it. Add a preflight check
  on target provenance before any run that could point at private code.
- Rotate the router API key: it was pasted into a chat session on 2026-07-23.
- If base-model attribution is ever required, re-measure through a direct provider API
  to remove the gateway prompt.
