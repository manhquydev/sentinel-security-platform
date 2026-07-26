# On-prem / air-gapped LLM serving (Week-11, decision 0019)

Sentinel's every model call already routes through the LiteLLM gateway. The on-prem path just adds a
gateway alias — `local-onprem` (`infra/litellm/config.yaml`) — pointing at a locally-served OSS model
that exposes an **OpenAI-compatible** API. No agent code changes: the provenance-labelled client and
the FinOps meter work unchanged.

## Two serving backends, same gateway alias

| Backend | When | Endpoint | Verified |
|---|---|---|---|
| **Ollama** | laptop / small GPU / air-gapped dev | `:11434/v1` | ✅ live here — `qwen2.5:0.5b` on the 4 GB GPU (~0.5 GB VRAM), an agent provenance-labelled call returned the expected output, FinOps metered it at $0 |
| **vLLM** | datacenter GPU, high throughput | `:8000/v1` | ⏸ `docker-compose.yml` here — the production target; not run on the 4 GB dev GPU |

## Why Ollama here, vLLM there (honest hardware reality)

The charter names vLLM. vLLM is engineered for high-throughput **server** GPUs; on the dev box's
**4 GB laptop GPU** (and with no docker NVIDIA runtime) a real vLLM serve is OOM-marginal and a heavy
multi-GB install — running it just to name-match would be theatre. So the *air-gapped serving path* is
demonstrated with the tool that fits (Ollama, native, uses the host driver), and vLLM is the committed
**production** path for real GPUs. Both present the same OpenAI-compatible contract the gateway needs,
so swapping them is one env var (`ONPREM_API_BASE`).

## Ollama (what was run, reproducible)

```bash
# 1. Standalone Ollama (no root): github.com/ollama/ollama releases -> ollama-linux-amd64.tar.zst
OLLAMA_HOST=127.0.0.1:11434 ollama serve &        # binds loopback (the sandbox forbids 0.0.0.0)
ollama pull qwen2.5:0.5b                            # ~400 MB; runs on GPU (llama-server, ~0.5 GB VRAM)

# 2. Agent -> on-prem model, metered by FinOps (proves the client + provenance + FinOps path live):
LITELLM_BASE=http://127.0.0.1:11434 LITELLM_MASTER_KEY=on-prem-local \
  rag/.venv/bin/python -c "from agent import llm, finops; \
    m=finops.run_meter('demo'); \
    ..."                                            # returns the model output; FinOps: 1 call, $0
```

## Gateway-routed path (the committed integration)

`infra/litellm/config.yaml` → `local-onprem` (`openai/…` + `api_base: ONPREM_API_BASE`), and
`infra/litellm/docker-compose.yml` adds `extra_hosts: host.docker.internal:host-gateway` so the gateway
**container** reaches the **host**-served model:

```bash
ONPREM_API_BASE=http://host.docker.internal:11434/v1 \
  docker compose -f infra/litellm/docker-compose.yml up -d       # gateway now routes local-onprem
```

**Sandbox caveat (decision 0019):** this dev sandbox forbids non-loopback binds, so the host model
could only bind `127.0.0.1`, which the gateway *container* cannot reach — the gateway-routed live call
was therefore not demonstrated *in the sandbox*. It resolves on any host that allows `0.0.0.0` /
host-gateway (the norm). The agent→model path itself is verified live (table above).

## vLLM (datacenter)

`docker-compose.yml` here serves an OSS model on an OpenAI-compatible `:8000/v1`; point the gateway at
it with `ONPREM_API_BASE=http://host.docker.internal:8000/v1`. Requires a real GPU + the NVIDIA
Container Toolkit. Production throughput / autoscaling (KEDA) is deferred with the GPU constraint named.
