# Week-11: package the multi-agent syndicate into a reproducible container (decision 0019).
# Slim image — agent runtime deps only; RAG enrichment degrades gracefully (see requirements-agent.txt).
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

# Non-root: the syndicate needs no privileges; it only makes outbound HTTP to the loopback planes.
RUN useradd --create-home --uid 10001 sentinel
WORKDIR /app

COPY infra/agent/requirements-agent.txt /tmp/requirements-agent.txt
RUN pip install --no-cache-dir -r /tmp/requirements-agent.txt

# Only the code + the on-disk inputs the syndicate actually reads: the agent package, the pinned
# attack-surface baseline (recon reads ../attack-surface/baselines/…), and the Ed25519 PUBLIC key
# for the Week-8 HITL verify (the private signer is out-of-process by design — never in the image).
COPY agent/ /app/agent/
COPY attack-surface/ /app/attack-surface/
RUN mkdir -p /app/agent/out && chown -R sentinel:sentinel /app/agent/out

USER sentinel
# Endpoints default to the host loopback planes; the compose runs with network_mode: host so these
# resolve to the running LiteLLM/Kong/DefectDojo/Phoenix stacks. Override via env as needed.
ENV LITELLM_BASE=http://127.0.0.1:4000 \
    DD_URL=http://127.0.0.1:8080 \
    KONG_PROXY=https://127.0.0.1:18443 \
    PHOENIX_COLLECTOR_ENDPOINT=127.0.0.1:4317 \
    PYTHONUNBUFFERED=1

# Default: a deterministic (no-LLM, no-cost) syndicate run that still emits the FinOps line. Override
# the command to pass --model / drop --no-llm for a real gateway-backed run.
ENTRYPOINT ["python", "-m", "agent.supervisor"]
CMD ["--no-llm", "--thread", "container-demo"]
