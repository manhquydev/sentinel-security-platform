# Containerised syndicate (Week-11, decision 0019)

Packages the multi-agent syndicate (`agent/`) into one reproducible container that runs against the
existing loopback planes (LiteLLM gateway, Kong, DefectDojo, Phoenix).

- **Slim by design.** `requirements-agent.txt` installs only the agent's direct runtime deps — NOT
  rag's ML stack (onnxruntime/fastembed/numpy). RAG enrichment is lazily imported + best-effort
  (`agent/recon.py`), so inside the container it degrades to empty with a stderr note; everything else
  runs. Image ~340 MB.
- **Safe.** Digest-pinned `python:3.12-slim`; non-root; secrets from the git-ignored `infra/.env`,
  never baked; only the Ed25519 HITL **public** key is in the image (the signer stays out-of-process,
  decision 0016). `network_mode: host` is the project's documented `--network host` residual — the
  container only makes OUTBOUND calls to loopback and binds nothing.
- **FinOps built in.** Every run emits the per-run cost/token/latency line + budget alerts (decision
  0019, `agent/finops.py`).

## Run

```bash
# Build:
docker build -f infra/agent/Dockerfile -t sentinel-syndicate:local .

# Deterministic, no-cost demo (default CMD) — verified to run the full Recon->Fuzz->Exploit pipeline:
docker compose -f infra/agent/docker-compose.yml run --rm syndicate

# A real gateway-backed run (needs infra/.env with the gateway + lake creds):
docker compose -f infra/agent/docker-compose.yml run --rm syndicate --model sast-sol --thread run1
```

Checkpoints persist in the `syndicate-out` volume so a `--thread` can resume across restarts.
