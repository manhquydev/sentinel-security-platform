# 0019 Week-11 production is a containerised syndicate + per-run FinOps + an on-prem serving path; vLLM production scale is honestly scoped to the hardware

Date: 2026-07-25

## Status

Accepted (Week-11 shipped — the FinOps meter + spike guard, the slim syndicate container, and the
on-prem model-serving path verified live via Ollama; vLLM committed as the datacenter path; real
production throughput / autoscaling deferred with the GPU constraint named).

## Context

Week 11 is "Production Deployment & GPU FinOps": package the multi-agent system into containers, deploy
OSS models via vLLM for high throughput, track latency/error/**token costs per pentest run**, and alert
on cost spikes / model drift. Scouting the real environment corrected the literal charter on two points:

- **The dev GPU is a 4 GB laptop card** (RTX 3050 Ti; ~3.2 GB free) with **no docker NVIDIA runtime**.
  vLLM is engineered for high-throughput server GPUs; on 4 GB it is OOM-marginal and a heavy multi-GB
  install. Running it just to name-match the charter would be theatre.
- **The monitoring substrate already exists** (LiteLLM usage in every response, Phoenix + Langfuse
  traces), but there was **no per-pentest-run cost/latency/error accounting** for the syndicate, and the
  `agent/` layer ran only from a venv, never containerised.

## Decision

**Week-11 delivers the three things that are real and buildable here, each honest about its limits.**

- **Per-run FinOps is measured, cost is a labelled estimate (`agent/finops.py`).** A run-scoped meter
  captures the EXACT prompt/completion tokens + wall latency the gateway returns for every call; the
  dollar figure is a DERIVED estimate from a committed, env-overridable price table (cloud-proxy prices
  are approximate by nature; on-prem models are $0/token — the GPU is the cost). So the report never
  claims billing precision: tokens/latency are measured, cost is flagged an estimate, and an unpriced
  model is surfaced, never silently $0. Metering is **opt-in and non-invasive** — `agent/llm.py`
  records into an active meter or no-ops, so nothing changes for callers that do not opt in;
  `run_syndicate` wraps each run and attaches the report. **Cost-spike / drift alerting** is a
  deterministic threshold guard (`check_thresholds`) over a committed per-run budget (cost, tokens,
  latency, errors) — the run prints an ALERT on any breach.
- **The syndicate is a slim, reproducible container (`infra/agent/`).** A digest-pinned `python:3.12-slim`
  image installs only the agent's direct runtime deps — NOT rag's heavy ML stack — because RAG
  enrichment is lazily imported and best-effort (`agent/recon.py`), so it degrades gracefully inside
  the container. Non-root; `network_mode: host` (the project's documented `--network host` residual) so
  it reaches the loopback planes; secrets from the git-ignored `infra/.env`, never baked; the Ed25519
  HITL **public** key only (the signer stays out-of-process, 0016). **Verified**: the container runs the
  full Recon→Fuzz→Exploit pipeline against the live planes and emits its FinOps line.
- **The on-prem / air-gapped serving path is a gateway alias, verified live via the tool that fits the
  hardware.** Every model call already routes through the LiteLLM gateway; the on-prem path adds one
  alias (`local-onprem`, `openai/…` + `api_base`), no agent change. On the 4 GB GPU it is served by
  **Ollama** (`qwen2.5:0.5b`, ~0.5 GB VRAM) — **verified live**: an agent provenance-labelled `llm.chat`
  drove the on-prem GPU model and the FinOps meter recorded it at $0. **vLLM** (`infra/vllm/`) is the
  committed **datacenter-GPU** production path, swappable by one env var (`ONPREM_API_BASE`).

## Consequences

- Every pentest run carries a measured token/latency/error record + an estimated cost + a fail-on-breach
  budget alert; the syndicate ships as one pinned container; the air-gapped model-serving path is real
  and demonstrated, not asserted. Weeks 1–10 are untouched behaviour-wise (the `llm.py`/`supervisor.py`
  additions are opt-in and backward-compatible; syndicate + HITL suites stay green).
- **Honestly scoped / deferred (each named, not hidden):** vLLM **production throughput + autoscaling
  (KEDA)** need a real server GPU — deferred, config committed. The **gateway-container→host-model live
  hop** could not be shown *in this sandbox* (it forbids non-loopback binds, so the host model bound
  only `127.0.0.1`, unreachable from the gateway container) — the alias + `host.docker.internal`
  `extra_hosts` are committed and resolve on normal hardware; the agent→model path itself is verified
  live. **Model-drift** detection beyond the cost/latency/error budget guard (e.g. output-distribution
  or version drift) is a follow-on. Cloud-proxy cost figures remain list-price estimates until
  reconciled against a real invoice (the pre-existing gateway note).
