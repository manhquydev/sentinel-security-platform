# AI-SAST Benchmark Harness

Provider-agnostic benchmark of AI-SAST engines (Datadog SAIST primary, Arm Metis
cross-check) against OWASP Benchmark (ground-truth) and WebGoat (qualitative).
See `plans/260721-2137-ai-sast-benchmark/plan.md` for full context and decisions.

## Status

The DeepSeek V0 baseline is complete and **frozen** (runs 1–2, P 0.5493 / R 0.7403 —
see `runs/index.md` and `runs/scorecard-v0-final.json`). Never overwrite those.

New runs target the **clawcmc agent router** instead. The step-0 endpoint probe passed
(`runs/spike-router-endpoint.md`); the migration is at its phase 2 viability gate. See
`plans/260722-1519-router-provider-migration/`.

## Models

| Alias | Model | Role |
|---|---|---|
| `sast-sol` | `cx/gpt-5.6-sol` (router) | tier under test |
| `sast-terra` | `cx/gpt-5.6-terra` (router) | tier under test |
| `sast-gpt55` | `cx/gpt-5.5` (router) | tier under test |
| `cheap-sast` | `deepseek/deepseek-chat` | frozen comparison arm — kept only so it stays re-scoreable |

**Only the `cx/*` family is usable.** Metis calls `/v1/responses`, and that is the only
family on this router that implements it. `ag/gemini-3.5-flash-{low,extra-low}` answer
with a `chat.completion` object and empty usage, which LiteLLM cannot parse — HTTP 500 on
every call. `glm/glm-5.2` returns HTTP 429. Both evaluated and dropped 2026-07-22; see
`runs/spike-router-endpoint.md`.

**SAIST remains out of scope** — it hardcodes a strict `json_schema` response_format
that the router silently ignores, on top of the Datadog-account blocker below.

Router notes that affect how results must be read:

- It injects **3,231 prompt tokens into every request** regardless of content (measured
  through the proxy on all three tiers). Results reflect the model *plus* an
  uncontrolled gateway prompt and are not attributable to the base model — that is the
  `gateway_prompt_caveat`.
- It defaults to streaming; the config forces `stream: false` per deployment.
- LiteLLM rewrites the response `model` to the alias, so the **backing model is not
  observable** and drift cannot be detected.
- It has no embedding model, so Metis indexing stays off — the `indexing_caveat`.
- `usage.cost` is `null` and LiteLLM has no pricing entry, so **spend is unavailable**;
  manifests record `spend_usd: null` with a reason rather than a misleading `0`.

## Layout
```
benchmark/
  litellm-config.yaml     # aliases: sast-sol, sast-terra, sast-gpt55, cheap-sast (frozen), judge, embed
  .env.example            # copy to .env, fill in, never commit
  configs/                # one Metis config per router tier
  scripts/
    setup-targets.sh          # clone OWASP Benchmark + WebGoat SOURCE only (no containers)
    setup-tools.sh            # clone + install SAIST + Metis at pinned SHAs; refuses to clobber local patches
    generate-virtual-key.sh   # one scoped virtual key via LiteLLM /key/generate
    provision-benchmark-keys.sh # the per-tier, per-run keys a baseline needs
    preflight.sh              # env/secret presence + vendored-Metis patch assertion (never prints values)
    scan-for-secrets.sh       # filesystem secret scan (this tree has no git, so `git grep` is unavailable)
  tests/                   # config-only + harness tests, no API key/network needed
  targets/                 # git-cloned, gitignored
  tools/                   # git-cloned, gitignored (Metis is PATCHED here — see preflight)
  results/                 # Metis usage summaries, gitignored (host paths + scanned source)
```

## Vendored Metis is patched

`tools/arm-metis/src/metis/usage/runtime.py` carries a local fix: upstream names usage
files with one-second resolution and no PID, so concurrent scans overwrite each other's
token records (~19% loss in the DeepSeek round — which is why that round's token and
cost figures are undercounts, not measurements).

A re-provision or a stray `git checkout` inside `tools/arm-metis` reverts it silently.
`preflight.sh` asserts both the pinned SHA and the patch marker, and `setup-tools.sh`
refuses to check out over a dirty tree. Do not bypass either.

## Setup order
1. `cp .env.example .env` and fill in secrets (see `.env.example` comments per field).
   `ROUTER_API_KEY` + `ROUTER_API_BASE` are what new runs need.
2. `pip install -r requirements.txt && pytest tests/` — should pass with no key set.
3. Start LiteLLM proxy: `litellm --config litellm-config.yaml --port 4000`.
4. `bash scripts/provision-benchmark-keys.sh` — the per-tier, per-run keys. The
   budget argument only binds for models LiteLLM can price; it is inert for router
   models, where per-key model scoping rather than the cap is what bounds a key. Verify each key authenticates before running a gate: a run that
   fails on a missing credential looks exactly like a tier that failed on capability.
5. `bash scripts/preflight.sh` — must show all `[ok]` before continuing.
6. `set -a; . .env; set +a; bash scripts/scan-for-secrets.sh` — must report OK.
7. `bash scripts/setup-targets.sh` (set `WEBGOAT_TAG` from a real release tag first).
8. `bash scripts/setup-tools.sh` — installs only, makes no LLM call, needs no key.
9. Run the step-0 viability spike per the migration plan's phase 2.

## Known blocker discovered during scaffolding (not in original plan docs)
**SAIST requires a Datadog account (`DD_API_KEY` + `DD_APP_KEY`) even for local scans** —
it fetches its detection/validation prompts from a Datadog-hosted API. This is
independent of the DeepSeek/LiteLLM routing question the Step-0 spike was designed
to test. See `runs/spike-engine-endpoint.md` for the decision this forces.

Metis, by contrast, has native LiteLLM support and a separate `embedding_provider`
config block — no equivalent account blocker found.

## Egress note — hard boundary
Source code sent to SAIST/Metis is transmitted to the configured LLM provider. This is
not "offline": only the scan *targets* avoid inbound network exposure.

**This harness may only be pointed at public corpora (OWASP Benchmark, WebGoat).** The
router publishes no terms of service, retention policy, or training policy. Pointing it
at private Sentinel code requires a terms review first.

`turn_off_message_logging` and `redact_user_api_key_info` are *local proxy* controls.
They stop LiteLLM persisting bodies; they do nothing about what the gateway does with
traffic that has already crossed to it. Do not cite them as satisfying this boundary.
