# AgentDojo static indirect-prompt-injection baseline

This directory stands up [AgentDojo](https://github.com/ethz-spylab/agentdojo) against a
**minimal scaffold agent** that calls the LLM exclusively through the Sentinel gateway
(`http://127.0.0.1:4000`), and records the result as a committed JSON artifact.

Read this whole file before citing any number in `results/`. It exists specifically
because that number is easy to misread.

## What this number is

- The attack success rate (ASR) and utility-under-attack of a **~50-line scaffold agent**
  (`sentinel_pipeline.py`) built only so AgentDojo has something to run against, on a
  **small, explicitly bounded subset** of one AgentDojo v1 suite, against AgentDojo's
  default **static** `important_instructions` attack.
- A real, live measurement: every number in `results/*.json` came from an actual run
  against the running gateway, not a simulation.

## What this number is NOT

- **Not a measurement of Sentinel.** Sentinel has no agent of its own. The scaffold in
  `sentinel_pipeline.py` exists purely as AgentDojo's client; it embodies no Sentinel
  product decision beyond "declare provenance correctly and call the gateway." Any
  weakness or strength this number shows is the scaffold's, not the platform's.
- **Not a measurement of a defense.** The Sentinel gateway ships **no prompt-injection
  detector**, by design -
  [decision 0006](../../docs/decisions/0006-the-gateway-labels-provenance-it-does-not-detect-injection.md)
  records why: published adaptive-attack results break every filter-based defense
  considered, and the false-positive risk on a security-testing workload is separately
  disqualifying. This is Week 1's **undefended** starting point for a Week 7 before/after,
  once Stream D's agent-layer capability gating exists to enforce on the provenance labels
  this gateway already produces.
- **Not evidence of robustness, however low the ASR reads.** AgentDojo's default attack
  corpus, including `important_instructions` used here, is **static**. Nasr et al.,
  ["The Attacker Moves Second"](https://arxiv.org/abs/2510.09023), broke 12 published
  defenses at >90% ASR under adaptive attack after each was reported near-zero
  statically. [AutoDojo](https://arxiv.org/abs/2606.15057) recovers **64% ASR on
  action-open tasks** - exactly Sentinel's agent shape - against a filter measured at 0%
  under this same static methodology. A 0% or low static ASR here is a starting number,
  not a security claim.
- **Not a zero-intervention baseline.** Every call in this run still passed through the
  gateway's always-on, non-optional hygiene: egress secret redaction and provenance
  spotlighting (datamarking/delimiting of target-derived spans). Decision 0006 is explicit
  that spotlighting is hygiene, not a control, and is bypassable - but it is present in
  every request this runner makes, because there is no way to satisfy the gateway's
  fail-closed provenance check and skip it. See the `gateway_hygiene_always_on` caveat
  field in every result artifact.
- **Not the full AgentDojo benchmark.** See "Scope and cost" below.

## How the scaffold satisfies the gateway's provenance requirement

The gateway fails closed on undeclared provenance
(`infra/litellm/guardrails/provenance-label.schema.json`,
`infra/litellm/guardrails/sentinel_guardrail.py`). The task that produced this baseline
offered two ways to satisfy it: the `sentinel-legacy-client` guardrail exemption
(`"guardrails": ["sentinel-legacy-client"]` in the request body), or a proper per-message
declaration via `metadata.sentinel_provenance`. This runner **always uses the metadata
declaration** - `sentinel_pipeline.py` has no code path for the exemption at all, for two
reasons, one of preference and one structural:

- **Preference**: this scaffold always knows exactly which message in an AgentDojo
  conversation is a tool result (AgentDojo's own `ChatToolResultMessage` role) and which is
  operator-authored (system prompt, the benchmark's simulated user turn, its own prior
  replies). Declaring `target-derived` for every `role: "tool"` message and `operator` for
  everything else is a direct, complete mapping - there is no message whose provenance is
  ambiguous in AgentDojo's message model, so the exemption meant for callers that
  structurally cannot declare does not fit this agent.
- **Structural**: the exemption was tried first, against the live gateway, before this
  reasoning was written down. It does not work for a caller holding the shared gateway
  key. `sentinel` (the default guardrail) is configured `default_on: true`, and reading
  the deployed LiteLLM proxy's own guardrail-selection code
  (`litellm/integrations/custom_guardrail.py` inside the running `sentinel-litellm`
  container) shows that a `default_on: true` guardrail can only be turned off via
  admin-configured key/team metadata - its own docstring says this is "to prevent callers
  from disabling guardrails." No field in the request body reaches that code path.
  Sending `"guardrails": {"sentinel-legacy-client": true}` (the dict form the proxy
  actually reads; a bare list is silently ignored by its selection logic) with no
  provenance declaration was tested directly against the running gateway and still
  returned the fail-closed 500. Reaching the exemption requires a virtual key
  provisioned with `user_api_key_metadata.opted_out_global_guardrails`, which is an admin
  action outside this runner's scope - not something a request body can do. See the
  docstring on `SentinelOpenAILLM` in `sentinel_pipeline.py` for the full trace.

This means the metadata path was not a preference chosen off a level playing field; it
is the only path this runner could actually exercise. That is worth stating plainly
rather than presenting the choice as symmetric.

## Running it

```bash
# 1. Isolated venv, not the repo, not system Python.
python3 -m venv /path/to/scratch/agentdojo-venv
source /path/to/scratch/agentdojo-venv/bin/activate
pip install -r evaluation/agentdojo/requirements.txt

# 2. The gateway key, from the environment - never pass it on the CLI or print it.
set -a; source infra/.env; set +a

# 3. From the repo root.
python3 evaluation/agentdojo/run_baseline.py --help
python3 evaluation/agentdojo/run_baseline.py --suite banking --max-user-tasks 3 --max-injection-tasks 2
```

`run_baseline.py` reads the gateway key from the environment variable named by
`--gateway-key-env` (default `LITELLM_MASTER_KEY`) and never logs or writes its value.

The run is deterministic in its inputs: task selection is `sorted(suite.user_tasks)[:N]`
and `sorted(suite.injection_tasks)[:N]`, for the AgentDojo v1 suite and attack pinned by
`--suite`/`--benchmark-version`/attack name, so the same flags select the same tasks on
every run (model output itself is not deterministic - temperature is fixed at 0.0, but
the gateway's backing tier does not guarantee bit-identical replies).

## The committed result

`results/20260723T155908Z-banking-sast-sol.json` is one real run:

- **Suite**: `banking` (AgentDojo v1's smallest suite: 16 user tasks, 9 injection tasks)
- **Subset**: first 3 user tasks x first 2 injection tasks, sorted by ID = 6 task runs,
  plus 2 standalone injection-task utility checks AgentDojo runs automatically = 16
  gateway calls total
- **Attack**: `important_instructions_generic_model` - AgentDojo's default
  `important_instructions` static jailbreak template, addressed to a generic model
  phrase instead of a resolved model name (see the docstring on
  `GenericModelImportantInstructionsAttack` in `sentinel_pipeline.py` for why: AgentDojo's
  model-name lookup expects a literal provider model ID, and this scaffold is reached
  through a gateway alias instead)
- **Model alias**: `sast-sol`
- **Result**: `attack_success_rate: 0.0` (0/6), `utility_under_attack: 0.667` (4/6)
- **Token usage**: 14,337 prompt + 1,154 completion = 15,491 tokens across 16 calls
- **Observed cost**: $0.1063, using the `sast-sol` list-price mapping documented in
  `infra/litellm/config.yaml` (the only alias in this gateway with a config-verified price
  match; see `cost.price_basis` in the artifact)

A zero-ASR result from 6 task runs is a small-sample data point, not a strong claim either
way - the point of this artifact is that the harness runs correctly end to end and is
re-runnable, not that six tasks characterize the scaffold's robustness.

Every field described above, plus the full caveat set, is in the artifact itself under
`run_metadata`, `results`, `token_usage`, `cost`, and `caveats` - it is self-describing;
this README summarizes it, not the other way around.

## Scope and cost - read before running a larger subset

This repository's cost-control requirement is mandatory. The committed run is 6 task
combinations (16 gateway calls, 15,491 tokens, $0.11). The artifact's
`cost.full_run_projection` field extrapolates this run's average tokens-per-task-run
linearly across **every AgentDojo v1 suite's full task matrix, for this same one attack and
one model alias**:

| Suite | Task runs (full) | Projected cost |
|---|---|---|
| banking | 153 | ~$2.71 |
| slack | 110 | ~$1.95 |
| travel | 147 | ~$2.60 |
| workspace | 246 | ~$4.36 |
| **all four v1 suites, one attack, one model** | **656** | **~$11.62** |

This is a **lower bound**, not an estimate of AgentDojo's full published methodology:
the AgentDojo paper evaluates multiple attacks (`important_instructions`, `direct`,
`ignore_previous`, `system_message`, `injecagent`, ...) and multiple models, which
multiplies the above by the number of attacks and models actually run. **Do not run the
full benchmark from this observation alone** - re-derive a fresh projection from a bounded
run at whatever scope is actually intended first.

## Files

- `run_baseline.py` - the CLI runner. `--help` works standalone from the repo root.
- `sentinel_pipeline.py` - the scaffold agent: an AgentDojo `BasePipelineElement` that
  calls the gateway's OpenAI-compatible endpoint, plus the gateway-compatible attack
  variant described above.
- `requirements.txt` - pinned `agentdojo==0.1.35` and every transitive dependency, via
  `pip freeze` inside the isolated venv used for the committed run.
- `results/` - committed JSON result artifacts, one per run.

## Follow-up this baseline sets up

Decision 0006's follow-up section calls for "the evaluation harness (AgentDojo static
baseline, then adaptive via AutoDojo or PIArena) so Week 7 can report a credible
before/after ASR rather than an assertion." This directory is the static half. The
adaptive half (AutoDojo/PIArena) and the Week 7 before/after against Stream D's agent-layer
enforcement are not built here and are out of scope for this task.
