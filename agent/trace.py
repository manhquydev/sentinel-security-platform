"""Graph-flow tracing to a self-hosted Phoenix plane (Week 6, decisions D5/D10).

This is a DISTINCT concern from `infra/litellm/.../egress_redaction.py`: that module
deliberately PRESERVES attack/target payloads on the LLM-call path so a finding stays legible
(decision 0006). This module does the opposite — the Supervisor graph's spans are diagnostic
telemetry about the RUN (which node ran, how many requests, how many findings of which kind),
never a copy of the target's traffic, so nothing here has a reason to carry raw target text or
a secret in the first place. The redaction below is the belt-and-suspenders check on top of
that: attributes are scrubbed before they are attached to a span (the primary defense), and a
`SpanProcessor` scrubs whatever a span still carries when it ends (the backstop, in case a
future node attaches something it shouldn't).

Tracing is best-effort and FAILS OPEN: `agent/fuzz.py` and `agent/recon.py` reach the target
through the Kong gateway directly with `requests` (not instrumented), so nothing here sits on
that path, and `node_span()` swallows any tracer/exporter setup failure rather than let a dead
or unreachable Phoenix container block a pentest run. Whatever a span DOES carry, it carries
redacted — Phoenix being down changes nothing about that guarantee.
"""
from __future__ import annotations

import os
import re
from contextlib import contextmanager
from typing import Any, Iterator

from opentelemetry import trace as trace_api
from opentelemetry.attributes import BoundedAttributes
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

SERVICE_NAME = "sentinel-agent-syndicate"
# Loopback only (D10) — mirrors the Kong/Langfuse convention of never publishing a plane that
# holds anything derived from a scanned target beyond 127.0.0.1.
DEFAULT_COLLECTOR_ENDPOINT = "127.0.0.1:4317"

# --- redaction ------------------------------------------------------------------------------
# Deliberately narrow and structural (a known credential prefix, an assignment keyword, PEM
# framing) rather than "anything suspicious looking" — the same reasoning egress_redaction.py
# documents: a pattern tuned to attack-shaped content either misses real secrets or mangles the
# legitimate SQLi/XSS/traversal vocabulary this system's spans might otherwise want to name.
_SECRET_PATTERNS = re.compile(
    # Scoped `(?s:...)` (not a module-wide DOTALL) so ONLY the PEM body's `.*?` spans newlines —
    # the keyword rule below deliberately stops at end-of-line (see its own comment).
    r"(?s:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----)"
    r"|\bsk-[A-Za-z0-9_-]{10,}"
    r"|\bghp_[A-Za-z0-9]{20,}"
    r"|\bgithub_pat_[A-Za-z0-9_]{20,}"
    r"|\bAKIA[0-9A-Z]{16}"
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}"
    # The value after the keyword runs to end-of-line, not just the first whitespace-delimited
    # token — `\S+` alone left `Authorization: Bearer <JWT>` with only "Bearer" redacted and the
    # token itself in clear text (MF1). `[^\r\n]+` stops at the line break instead of DOTALL's
    # "the rest of the whole blob", so a multi-line narrative field still only loses one line.
    r"|\b(?:token|secret|password|passwd|api[_-]?key|client[_-]secret|access[_-]token"
    r"|refresh[_-]token|private[_-]key|authorization|cookie)[\"']?\s*[:=]\s*[^\r\n]+",
    re.IGNORECASE,
)

# Shapes of the target-derived text this graph must never let a span/checkpoint carry: the
# fuzz payload corpus's own markers (agent/fuzz_payloads.py) and the stack-trace/error
# signatures the signal detector matches (agent/fuzz_signals.py). A span attribute is never
# built from raw response bodies in the first place (see supervisor.py's redaction helpers);
# this is the defense-in-depth check that a marker like these never slipped through anyway.
_TARGET_RAW_PATTERNS = re.compile(
    r"<script|javascript:|UNION\s+SELECT|SequelizeDatabaseError|SQLITE_ERROR"
    r"|Traceback \(most recent call last\)|\bat Object\.<anonymous>|ORA-\d{5}"
    r"|org\.hibernate|com\.mysql|\.\./\.\./|\{\{.*?\}\}|\$\{.*?\}",
    re.IGNORECASE,
)


def scrub_secrets(text: str | None) -> str | None:
    """Strip secret-shaped substrings only. Kept as the scalar-scrub building block for span
    attributes (`_scrub_value` below layers the target-raw pass on top for those). Free-text
    narrative fields the checkpoint PERSISTS (recon `analysis`, endpoint `notes`, finding
    `title`, fuzz `guidance`) are LLM narrative over target-derived input (MF2/0006) and must go
    through `redact_persisted`, not this function alone — see that docstring."""
    if not text:
        return text
    return _SECRET_PATTERNS.sub("[redacted:secret]", text)


def _scrub_target_raw(text: str) -> str:
    return _TARGET_RAW_PATTERNS.sub("[redacted:target-raw]", text)


def redact_persisted(text: str | None) -> str | None:
    """Full scrub (secrets AND target-raw) for every free-text field the Supervisor checkpoint
    persists to disk (D5/HF1). These fields are LLM narrative synthesized over target-derived
    input — a scanner finding title, a fuzz stack-trace signal — so the model can and does echo
    attack-shaped substrings (`UNION SELECT`, a traversal string, a stack-trace signature) into
    its own prose. The span path already runs both passes via `_scrub_value`; this is the same
    two-stage scrub for the DURABLE checkpoint path, which previously only ran `scrub_secrets`."""
    if not text:
        return text
    return _scrub_target_raw(scrub_secrets(text) or "")


def _scrub_value(value: Any) -> Any:
    if isinstance(value, str):
        return _scrub_target_raw(scrub_secrets(value) or "")
    return value  # numeric/bool attributes carry no target text or secret shape


class RedactingSpanProcessor(SpanProcessor):
    """Backstop redactor, registered BEFORE the exporting processor so it runs first on every
    `on_end`. `ReadableSpan.attributes` is documented as a read-only view, but the SDK backs it
    with the SAME `BoundedAttributes` instance the live `Span` wrote to — reassigning
    `span._attributes` here is the accessor OTel itself exposes for a redacting processor (there
    is no public "replace this span's attributes" API), and it is verified end-to-end by
    tests/syndicate-test.sh (I5): a planted secret/payload marker never reaches the exporter.
    """

    def on_start(self, span: Any, parent_context: Any = None) -> None:
        return None

    def on_end(self, span: ReadableSpan) -> None:
        attrs = span.attributes
        if not attrs:
            return
        scrubbed = {k: _scrub_value(v) for k, v in attrs.items()}
        if any(scrubbed[k] != attrs[k] for k in attrs):
            span._attributes = BoundedAttributes(attributes=scrubbed)  # noqa: SLF001 - see docstring

    def shutdown(self) -> None:
        return None

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


# --- provider / tracer -----------------------------------------------------------------------

_provider: TracerProvider | None = None


def _build_provider() -> TracerProvider:
    resource = Resource.create({"service.name": SERVICE_NAME})
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(RedactingSpanProcessor())  # must run before export (D5)
    endpoint = os.environ.get("PHOENIX_COLLECTOR_ENDPOINT", DEFAULT_COLLECTOR_ENDPOINT)
    # insecure=True: loopback-only plaintext gRPC (D10), matching KONG_PROXY/LITELLM_BASE's own
    # loopback-only trust model in this repo. A short timeout keeps a down Phoenix from ever
    # stalling the export thread for long, on top of BatchSpanProcessor already being async.
    exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True, timeout=5)
    provider.add_span_processor(BatchSpanProcessor(exporter, schedule_delay_millis=500))
    return provider


def get_tracer() -> trace_api.Tracer:
    """Idempotent: builds the provider once per process. Building it touches no network (only
    an export attempt does, and that happens async in BatchSpanProcessor's background thread),
    so this alone cannot fail because Phoenix is down."""
    global _provider
    if _provider is None:
        _provider = _build_provider()
        trace_api.set_tracer_provider(_provider)
    return _provider.get_tracer(SERVICE_NAME)


@contextmanager
def node_span(name: str, **attrs: Any) -> Iterator[Any]:
    """Span for one Supervisor graph node. Attributes are scrubbed before they are attached
    (the primary defense; `RedactingSpanProcessor` is the on_end backstop for anything added
    later via `span.set_attribute`). Getting/starting the span is isolated in its own
    try/except so a tracing failure degrades to a no-op — it must never block or fail the node
    body running inside the `with` block (fail-open, see module docstring)."""
    span_cm = None
    span = None
    try:
        tracer = get_tracer()
        scrubbed = {k: _scrub_value(v) for k, v in attrs.items()}
        span_cm = tracer.start_as_current_span(name, attributes=scrubbed)
        span = span_cm.__enter__()
    except Exception:  # noqa: BLE001 - tracing is best-effort; never blocks the pentest (D5)
        span_cm = None
    try:
        yield span
    finally:
        if span_cm is not None:
            try:
                span_cm.__exit__(None, None, None)
            except Exception:  # noqa: BLE001 - same fail-open rule on the way out
                pass
