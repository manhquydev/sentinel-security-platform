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
secrets file the other stacks already use. Copy the entries listed below across before
first bring-up; compose refuses to start with a clear message naming the missing variable
rather than booting a half-configured proxy, so a forgotten value fails loudly.

The proxy binds `127.0.0.1:4000` only. It holds the router credential and every virtual
key, so nothing about it should be reachable from the network.

**The database is not bundled.** `LITELLM_DATABASE_URL` points at an existing Postgres
that holds the virtual keys reproducing the frozen benchmark arms. Standing up a fresh
database here would invalidate those keys with no error at the point of failure.

## Environment contract

| Variable | Required | Purpose |
|---|---|---|
| `LITELLM_MASTER_KEY` | yes | Admin key; mints virtual keys via `/key/generate`. Never used by a client. |
| `LITELLM_DATABASE_URL` | yes | Where virtual keys and spend persist. Loopback Postgres. |
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

`sentinel-legacy-client` is the one named exemption, off by default. Metis is a vendored
scanner that cannot be taught to send a declaration and is the client that reproduces the
frozen arms; it still gets egress redaction. The exemption is a separate entry rather
than a weaker global default so that any new caller is fail-closed unless someone
deliberately adds it.

## Spend is unavailable, and that is recorded rather than papered over

The router returns `usage.cost: null` and LiteLLM carries no pricing entry for `cx/*`, so
the proxy cannot compute spend. **No `model_info` pricing is set**, and a test asserts its
absence.

Setting a per-token cost would make LiteLLM emit a number, but that number would be
derived from the backing model's public list price rather than what this router charges —
and a confidently wrong figure in a FinOps dashboard is worse than an honest absence. The
repository already follows this rule elsewhere: benchmark manifests record `spend_usd:
null` with a reason instead of a misleading `0`.

For deliberate capacity planning, public list prices for the backing tiers as of
2026-07-23 were **Sol $5.00 in / $30.00 out**, **Terra $2.50 / $15.00** per 1M tokens.
Treat these as an **upper bound, not an estimate**: routers in this class advertise
substantial savings over list, and this one reports its own model name rather than the
backing one, so the mapping is not verifiable from here. Token volume is the measured
quantity; anything in currency is a calculation someone chose to make.

Resolving the real rate is open work — see the plan's open questions.

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
