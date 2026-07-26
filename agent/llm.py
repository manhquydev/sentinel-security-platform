"""Provenance-aware LLM client — the Recon agent's only door to a model.

The Sentinel gateway is fail-closed on the provenance contract (docs/product/guardrail-hook-
contract.md, decision 0006): every request must declare, per message, whether it is `operator`
(authored by Sentinel) or `target-derived` (from a source Sentinel does not control). This module
makes that declaration mandatory in code — every message MUST carry a trust label — so the agent
physically cannot send target-derived text (a lake finding, a RAG chunk, a target response) to
the model without labelling it untrusted. That labelling is the whole point: it keeps attacker-
influenced content as DATA, and the gateway spotlights it.

Honest labelling is the caller's responsibility (the gateway cannot verify it): a finding
description or a retrieved chunk is `target-derived`; only the agent's own instructions/analysis
are `operator`.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

import requests

BASE = os.environ.get("LITELLM_BASE", "http://127.0.0.1:4000")
SCHEMA_VERSION = "1.0"


def operator() -> str:
    """Trust label for Sentinel-authored content."""
    return "operator"


def target_derived(source: str, target: str, collected_at: str | None = None) -> dict:
    """Trust label for content from a source Sentinel does not control. source+target required."""
    span = {"trust": "target-derived", "source": source, "target": target}
    if collected_at:
        span["collected_at"] = collected_at
    return span


@dataclass
class Msg:
    role: str            # "system" | "user" | "assistant"
    content: str
    trust: str | dict    # operator() or target_derived(...)


def _spans(msgs: list[Msg]) -> list[dict]:
    spans = []
    for i, m in enumerate(msgs):
        if m.trust == "operator":
            spans.append({"message_index": i, "trust": "operator"})
        elif isinstance(m.trust, dict) and m.trust.get("trust") == "target-derived":
            spans.append({"message_index": i, **m.trust})
        else:
            raise ValueError(f"message {i} has no valid trust label: {m.trust!r}")
    return spans


def chat(msgs: list[Msg], model: str, max_tokens: int = 1024,
         temperature: float = 0.0, timeout: int = 90) -> str:
    """Send a provenance-declared chat request and return the assistant text. Raises on transport
    error or a gateway refusal (fail-closed), which the caller must not swallow."""
    key = os.environ.get("LITELLM_MASTER_KEY")
    if not key:
        raise RuntimeError("LITELLM_MASTER_KEY is not set (source infra/.env)")
    payload = {
        "model": model,
        "metadata": {"sentinel_provenance": {"schema_version": SCHEMA_VERSION, "spans": _spans(msgs)}},
        "messages": [{"role": m.role, "content": m.content} for m in msgs],
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    import time

    from . import finops  # function-local import: avoids a module-load cycle (finops imports no agent)

    start = time.monotonic()
    try:
        r = requests.post(f"{BASE}/v1/chat/completions",
                          headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                          json=payload, timeout=timeout)
        r.raise_for_status()
        body = r.json()
        content = body["choices"][0]["message"]["content"]  # a malformed 200 raises here -> error path
    except Exception:
        # Week-11 FinOps: a failed OR malformed call still counts toward the run's error budget.
        finops.record(model, 0, 0, time.monotonic() - start, error=True)
        raise
    usage = body.get("usage") or {}
    finops.record(model, usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0),
                  time.monotonic() - start)
    return content
