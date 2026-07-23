# Sentinel LLM gateway

Every LLM call in Sentinel goes through this proxy. It exists so that routing, spend,
tracing and the egress boundary are one control point rather than four scattered ones,
and because the architecture makes it the dependency root every other stream calls
through.

It was moved here from `benchmark/` once it stopped being a benchmark component. The
benchmark is now one client among several, and there is exactly one config — a second
copy under `benchmark/` would drift.

## Bring-up

```bash
docker compose --env-file ../.env -f infra/litellm/docker-compose.yml up -d
curl -s http://127.0.0.1:4000/health/liveliness
```

**One-time migration.** The gateway's variables previously lived in `benchmark/.env`,
because the gateway lived under `benchmark/`. They now belong in `infra/.env`, the shared
secrets file the other stacks already use. Compose refuses to start with a message naming
the missing variable rather than booting a half-configured proxy, so a forgotten value
fails loudly rather than quietly.

The proxy binds `127.0.0.1:4000` only. It holds the router credential and every virtual
key, so nothing about it should be reachable from the network.

**The key store is bundled**, on the stack's own compose network with no published port.

An earlier version of this file said the opposite — that the database was deliberately
external because it held the virtual keys reproducing the frozen benchmark arms. That was
wrong, and wrong in an instructive way: it was inferred from a config value rather than
checked. The inherited `LITELLM_DATABASE_URL` pointed at `localhost:5433`, which belongs to
`cmc-e2e-pg`, an unrelated project's end-to-end **test** database bound to `0.0.0.0`. On
2026-07-23 neither the role `litellm` nor the database existed there. Whatever keys the
frozen runs used were provisioned into a disposable test database that has since been
reset.

**Consequence for anyone re-scoring a frozen arm:** the `V0_*_VIRTUAL_KEY` values still
listed in `benchmark/.env` authenticate against nothing. Regenerate them against this
instance with `benchmark/scripts/provision-benchmark-keys.sh`. The frozen *scorecards* are
unaffected — they are committed artifacts — and so is reproducibility, which depends on
the `cheap-sast` alias rather than on any particular key.

## Environment contract

| Variable | Required | Purpose |
|---|---|---|
| `LITELLM_MASTER_KEY` | yes | Admin key; mints virtual keys via `/key/generate`. Never used by a client. |
| `LITELLM_DB_USER`, `LITELLM_DB_PASSWORD` | yes | The bundled key store. Discrete, so the password never rides inside a DSN. |
| `ROUTER_API_BASE`, `ROUTER_API_KEY` | yes | The `cx/*` router. Ends in `/v1`. |
| `DEEPSEEK_API_KEY` | only to re-score the frozen arm | Backs the `cheap-sast` alias. |
| `JUDGE_MODEL`, `JUDGE_API_KEY` | no | Placeholder for the V2 judge variant. |
| `EMBED_MODEL`, `EMBED_API_KEY`, `EMBED_API_BASE` | no | Embeddings. Unused against the router, which exposes none. |

Clients authenticate with **virtual keys**, never the master key. Per-tier, per-run keys
exist because two tiers sharing one key destroys per-arm attribution — which is the only
accounting left while spend is unavailable.

## The guardrail

Wired at `pre_call` and on by default. Two things happen, in this order:

1. **Secrets are redacted** from every outbound prompt. Unconditional; it needs nothing
   from the caller and protects this host from what it sends to a router that publishes
   no retention terms.
2. **Provenance is validated and target-derived spans are spotlighted.** A caller that
   does not declare is refused.

Order is a safety property, not a preference. Spotlighting rewrites the whitespace the
redactor's assignment detector keys on, so marking first lets `token = value` through
untouched. That was measured, not reasoned about.

The gateway does **not** detect prompt injection, deliberately — see
[decision 0006](../../docs/decisions/0006-the-gateway-labels-provenance-it-does-not-detect-injection.md).
Callers declare provenance per
[the hook contract](../../docs/product/guardrail-hook-contract.md).

**There is no exemption, and none is reachable.** LiteLLM refuses to let a caller switch
off a `default_on` guardrail from the request body — a restriction its own code explains
as preventing callers from disabling guardrails. Probed against this deployment: the
guardrail name in `guardrails`, `{"sentinel": false}`, and either of those nested under
`metadata` are all refused.

An earlier version of this file described a `sentinel-legacy-client` entry as a named
exemption for a vendored scanner. That entry never functioned; it only read as though it
did, which is worse than not having it. Its premise was wrong too: a third-party
benchmark harness was taught to declare provenance in this repository, and the vendored
scanner is already patched here for an unrelated reason, so the same route is open to it.

**Consequence for the benchmark client:** it does not declare, so it is refused today.
Teaching it to declare is the fix; weakening the gateway is not.

## Recorded spend is a list-price equivalent, not a bill

**Read the `spend` column as an upper bound, not as money that was charged.**

The benchmark-era documentation said LiteLLM had no pricing for these models and that
spend was unavailable. That was inherited and is no longer true. Measured on this gateway
on 2026-07-23: LiteLLM's cost map contains `gpt-5.6-sol` at **$5.00 in / $30.00 out** per
1M tokens and matches it after stripping the `cx/` prefix. A real call of 103 in / 17 out
recorded `spend = 0.001025`, which is that list price to the cent.

So the number in `LiteLLM_SpendLogs` is the **backing tier's public list price**. This
router is not OpenAI, reports its own model name rather than the backing one, and routers
in this class advertise substantial savings over list — so the figure is an upper bound
whose distance from the real cost is unknown.

**No `model_info` override is set**, and a test asserts that. Overriding it would swap one
unverified number for another; the useful act is labelling what the number is, not
replacing it. For reference the other tiers list at Terra $2.50 / $15.00 per 1M tokens.

Token volume remains the only directly measured quantity. Reconciling the recorded figure
against an actual invoice is open work — see the plan's open questions.

## Tracing

Traces go to the self-hosted Langfuse stack in [`../langfuse`](../langfuse/README.md).
The proxy joins that stack's network because Langfuse publishes only a loopback port,
which a container cannot reach.

**Bodies are in the traces**, and the ordering is what makes that defensible: the
guardrail redacts before anything reaches a callback, so what Langfuse stores is
post-redaction. The stored trace shows it directly — a redacted assignment reads
`password=[redacted:password]`, with the spotlight marker applied around the assignment
but not inside it. Had spotlighting run first the text would read `password▁=`, the
redactor's pattern would not have matched, and the credential would be in ClickHouse.

This reverses the boundary the benchmark-era documentation described. The trade-off is
stated rather than mitigated: every trace's safety now rests on redaction being complete,
and no redactor is provably complete. What bounds the risk is that the store never leaves
this host and that the false-positive measurement in
[`../../evaluation/false-positive`](../../evaluation/false-positive/) exercises the
redactor against the real corpus rather than against fixtures.

Tracing is **best-effort**. A Langfuse outage must not fail an LLM call: the guardrail is
the control, the trace is the record. The tracing network is declared external here so the
proxy starts and serves calls whether or not that stack is up.

Two addressing hazards worth knowing, both already tripped:

- Both stacks have a service named `postgres`. From a container on both networks the name
  resolves to two addresses, so the key store is addressed by its **container name**.
- The UI is published on **3001**, not Langfuse's default 3000, which is already bound on
  this host.

## Topology

The proxy calls outward only, so it joins neither `dd-net` nor `juice-net`. Nothing on
this host reaches it except over loopback.

## Validation

```bash
bash tests/litellm-gateway-test.sh
python3 -m pytest -q tests/test_gateway_guardrails.py
(cd benchmark && python3 -m pytest -q tests)
bash benchmark/scripts/preflight.sh
```

The gateway suite asserts alias parity against the config this was moved from, the
deliberate absence of fabricated pricing, the guardrail's fail-closed default, and the
deployment properties that keep the credential off the network. The benchmark's own tests
are config-only and cannot prove the move — that is why the gateway suite exists.
