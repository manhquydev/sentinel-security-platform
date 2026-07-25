"""Week-11 FinOps: per-pentest-run cost / token / latency accounting + spike alerting.

The charter's Week-11 asks to "track token costs per pentest run" and "alert on unexpected cost
spikes". This module meters every gateway call a run makes — the EXACT prompt/completion token counts
and wall latency the gateway returns are the load-bearing facts; the dollar figure is a DERIVED
ESTIMATE from a committed, overridable price table (cloud-proxy prices are approximate by nature, and
the on-prem vLLM model is priced at $0/token — see decision 0019). So the report never claims billing
precision it does not have: tokens and latency are measured, cost is labelled an estimate.

Non-invasive: `agent/llm.py` calls `record()` after each response; it is a no-op unless a run has an
active meter (`with run_meter(run_id): ...`), so nothing changes for callers that do not opt in.

    from agent import finops
    with finops.run_meter("run-123") as m:
        ... run the syndicate ...
    report = m.report()                      # {tokens, cost_estimate_usd, latency, per_model, calls}
    alerts = finops.check_thresholds(report) # cost/latency/error spikes vs a committed budget
"""

from __future__ import annotations

import contextvars
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator

# Price table: USD per 1M tokens (input, output). ESTIMATE for cloud-proxied aliases; the on-prem
# vLLM model is $0/token (no per-call billing — compute cost is the GPU, tracked separately). Override
# with a JSON file at $FINOPS_PRICING or evaluation/../infra as needed. Unknown models -> (0,0) + flag.
_DEFAULT_PRICING: dict[str, tuple[float, float]] = {
    # alias            (input/1M, output/1M)  — approximate public list prices, 2026-07; override freely
    "cheap-sast": (0.27, 1.10),      # deepseek-chat
    "sast-sol": (1.25, 10.0),        # gpt-5.6-sol (proxy estimate)
    "sast-terra": (1.25, 10.0),
    "sast-gpt55": (1.25, 10.0),
    "sast-grok45": (3.0, 15.0),      # grok-4.5 via the router (proxy ESTIMATE; the router charges its own rate)
    "judge": (1.25, 10.0),
    # On-prem models: no per-token cost — the GPU is the cost, tracked separately (decision 0019).
    "local-onprem": (0.0, 0.0),
    "local-vllm": (0.0, 0.0),
    "qwen2.5:0.5b": (0.0, 0.0),
}


def _pricing() -> dict[str, tuple[float, float]]:
    path = os.environ.get("FINOPS_PRICING")
    if path and os.path.exists(path):
        raw = json.load(open(path, encoding="utf-8"))
        return {k: (float(v[0]), float(v[1])) for k, v in raw.items()}
    return dict(_DEFAULT_PRICING)


@dataclass
class _Call:
    model: str
    prompt_tokens: int
    completion_tokens: int
    latency_s: float
    error: bool = False


@dataclass
class RunMeter:
    run_id: str
    calls: list[_Call] = field(default_factory=list)

    def _record(self, call: _Call) -> None:
        self.calls.append(call)

    def report(self) -> dict:
        pricing = _pricing()
        per_model: dict[str, dict] = {}
        cost = 0.0
        unpriced: set[str] = set()
        for c in self.calls:
            inp, out = pricing.get(c.model, (0.0, 0.0))
            if c.model not in pricing:
                unpriced.add(c.model)
            call_cost = c.prompt_tokens / 1e6 * inp + c.completion_tokens / 1e6 * out
            cost += call_cost
            m = per_model.setdefault(c.model, {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0,
                                               "cost_estimate_usd": 0.0, "errors": 0})
            m["calls"] += 1
            m["prompt_tokens"] += c.prompt_tokens
            m["completion_tokens"] += c.completion_tokens
            m["cost_estimate_usd"] += call_cost   # accumulate raw; round once below (L2)
            m["errors"] += int(c.error)
        for m in per_model.values():
            m["cost_estimate_usd"] = round(m["cost_estimate_usd"], 6)
        lat = [c.latency_s for c in self.calls]
        return {
            "run_id": self.run_id,
            "calls": len(self.calls),
            "errors": sum(c.error for c in self.calls),
            "prompt_tokens": sum(c.prompt_tokens for c in self.calls),
            "completion_tokens": sum(c.completion_tokens for c in self.calls),
            "total_tokens": sum(c.prompt_tokens + c.completion_tokens for c in self.calls),
            "cost_estimate_usd": round(cost, 6),
            "cost_is_estimate": True,
            "latency_s": {"total": round(sum(lat), 3), "max": round(max(lat), 3) if lat else 0.0,
                          "mean": round(sum(lat) / len(lat), 3) if lat else 0.0},
            "per_model": per_model,
            "unpriced_models": sorted(unpriced),
        }


_ACTIVE: contextvars.ContextVar[RunMeter | None] = contextvars.ContextVar("finops_active", default=None)


@contextmanager
def run_meter(run_id: str) -> Iterator[RunMeter]:
    """Activate a run-scoped meter. Nesting is supported (inner restores the outer on exit)."""
    meter = RunMeter(run_id=run_id)
    token = _ACTIVE.set(meter)
    try:
        yield meter
    finally:
        _ACTIVE.reset(token)


def record(model: str, prompt_tokens: int, completion_tokens: int, latency_s: float,
           error: bool = False) -> None:
    """Called by agent/llm.py after each gateway response. No-op if no run meter is active."""
    meter = _ACTIVE.get()
    if meter is not None:
        meter._record(_Call(model, int(prompt_tokens), int(completion_tokens), float(latency_s), error))


# Committed default budget for a single pentest run. Override via $FINOPS_BUDGET (JSON). A run that
# breaches any ceiling raises an alert — the charter's "alert on unexpected cost spikes".
_DEFAULT_BUDGET = {"cost_estimate_usd": 1.00, "total_tokens": 200_000, "latency_total_s": 600.0,
                   "errors": 0}


def _budget() -> dict:
    path = os.environ.get("FINOPS_BUDGET")
    if path and os.path.exists(path):
        return {**_DEFAULT_BUDGET, **json.load(open(path, encoding="utf-8"))}
    return dict(_DEFAULT_BUDGET)


def check_thresholds(report: dict, budget: dict | None = None) -> list[dict]:
    """Return one alert per breached ceiling (cost / tokens / latency / errors). Empty = within budget.
    This is the deterministic 'cost-spike / drift' guard a CI or a run wrapper asserts on."""
    b = budget or _budget()
    alerts: list[dict] = []
    checks = [
        ("cost_estimate_usd", report["cost_estimate_usd"], b["cost_estimate_usd"]),
        ("total_tokens", report["total_tokens"], b["total_tokens"]),
        ("latency_total_s", report["latency_s"]["total"], b["latency_total_s"]),
        ("errors", report["errors"], b["errors"]),
    ]
    for name, actual, ceiling in checks:
        if actual > ceiling:
            alerts.append({"metric": name, "actual": actual, "ceiling": ceiling,
                           "over_by": round(actual - ceiling, 6)})
    return alerts
