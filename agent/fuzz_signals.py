"""Deterministic signal detection for fuzzing responses (decision 0013).

Whether a response is "interesting" is decided here, by code, against a per-target benign
baseline — never by an LLM. A 5xx is a fact; a stack trace is a fact; the LLM's role is to
interpret a batch of these facts and choose the next payloads, not to declare interestingness.

Detectors are conservative and explainable: each returns a short reason so a finding says WHY it
was flagged.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Error/stack-trace signatures across the stacks the targets use (Node/Express/Sequelize/SQLite
# for Juice Shop; Java for WebGoat) plus generic ones. Matching any is a strong signal.
_ERROR_SIGNATURES = re.compile(
    r"(SequelizeDatabaseError|SQLITE_ERROR|SQLITE_|syntax error|"
    r"\bat Object\.<anonymous>|\bat Function\.|Error: |ReferenceError|TypeError: |"
    r"Traceback \(most recent call last\)|java\.lang\.|javax\.|\bORA-\d{5}|"
    r"org\.hibernate|com\.mysql|Warning: |Fatal error|stack trace)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Baseline:
    status: int
    size: int
    content_type: str


@dataclass(frozen=True)
class Signal:
    kind: str      # 'server_error' | 'stack_trace' | 'reflected' | 'size_drift' | 'ctype_drift'
    reason: str


def baseline_of(status: int, body: str, content_type: str) -> Baseline:
    return Baseline(status=status, size=len(body), content_type=(content_type or "").split(";")[0])


def detect(baseline: Baseline, status: int, body: str, content_type: str,
           payload_value: str) -> list[Signal]:
    """Return every signal this response trips versus the baseline. Empty == uninteresting."""
    signals: list[Signal] = []
    ctype = (content_type or "").split(";")[0]

    # A server error is the primary fuzzing signal.
    if status >= 500:
        signals.append(Signal("server_error", f"HTTP {status}"))

    # An error/stack-trace signature leaking into the body — even under a 200 — is high value.
    m = _ERROR_SIGNATURES.search(body or "")
    if m:
        signals.append(Signal("stack_trace", f"error signature: {m.group(0)[:40]!r}"))

    # The payload reflected verbatim in the response indicates a reflection/XSS surface. Ignore
    # trivial payloads that would match by chance.
    if len(payload_value) >= 6 and payload_value in (body or ""):
        signals.append(Signal("reflected", "payload reflected in response body"))

    # A large deviation from the benign response size can indicate a different code path (an error
    # page, a dump). Guard against tiny baselines.
    if baseline.size >= 50 and body is not None:
        ratio = len(body) / max(baseline.size, 1)
        if ratio >= 3.0 or ratio <= 0.2:
            signals.append(Signal("size_drift", f"size {len(body)} vs baseline {baseline.size}"))

    # The content type changing (e.g. JSON baseline -> HTML error page) is a code-path change.
    if ctype and baseline.content_type and ctype != baseline.content_type:
        signals.append(Signal("ctype_drift", f"{baseline.content_type} -> {ctype}"))

    return signals
