"""Regression tests for the narrowly labeled Week-5 redaction additions."""

from __future__ import annotations

import importlib
import pathlib
import sys
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
GUARDRAILS = ROOT / "infra" / "litellm" / "guardrails"
sys.path.insert(0, str(GUARDRAILS))

from agent import pii  # noqa: E402
import egress_redaction  # noqa: E402


def _install_otel_stubs() -> None:
    """Keep the pure persisted-redaction unit test independent of optional OTel."""

    def module(name: str) -> types.ModuleType:
        existing = sys.modules.get(name)
        if existing is not None:
            return existing
        created = types.ModuleType(name)
        sys.modules[name] = created
        if "." in name:
            parent, child = name.rsplit(".", 1)
            setattr(module(parent), child, created)
        return created

    for name in (
        "opentelemetry",
        "opentelemetry.trace",
        "opentelemetry.attributes",
        "opentelemetry.exporter",
        "opentelemetry.exporter.otlp",
        "opentelemetry.exporter.otlp.proto",
        "opentelemetry.exporter.otlp.proto.grpc",
        "opentelemetry.exporter.otlp.proto.grpc.trace_exporter",
        "opentelemetry.sdk",
        "opentelemetry.sdk.resources",
        "opentelemetry.sdk.trace",
        "opentelemetry.sdk.trace.export",
    ):
        module(name)

    sys.modules["opentelemetry.exporter.otlp.proto.grpc.trace_exporter"].OTLPSpanExporter = object
    sys.modules["opentelemetry.attributes"].BoundedAttributes = dict
    sys.modules["opentelemetry.sdk.resources"].Resource = type(
        "Resource", (), {"create": staticmethod(lambda *args, **kwargs: None)}
    )
    sys.modules["opentelemetry.sdk.trace"].ReadableSpan = object
    sys.modules["opentelemetry.sdk.trace"].SpanProcessor = object
    sys.modules["opentelemetry.sdk.trace"].TracerProvider = object
    sys.modules["opentelemetry.sdk.trace.export"].BatchSpanProcessor = object


def _trace_module():
    _install_otel_stubs()
    return importlib.import_module("agent.trace")


def test_user_phone_assignment_is_redacted_but_unlabelled_phone_remains_a_gap():
    redacted, findings = pii.redact("user_phone=+12025550143")
    if "[redacted:pii:phone]" not in redacted:
        pytest.fail("user_phone assignment was not redacted")
    assert any(finding.cls == "phone" for finding in findings)

    gap = "phone +1-202-555-0143 on file"
    assert pii.redact(gap)[0] == gap


@pytest.mark.parametrize(
    "label, value",
    [
        pytest.param("db password", "db_password=synthetic-db-password", id="db-password"),
        pytest.param("stripe live", "sk_live_" + "A" * 24, id="stripe-live"),
        pytest.param("stripe test", "sk_test_" + "B" * 24, id="stripe-test"),
        pytest.param("google api", "AIzaSy" + "C" * 33, id="google-api"),
        pytest.param("gitlab PAT", "glpat-" + "D" * 20, id="gitlab-pat"),
    ],
)
def test_persisted_trace_redacts_labeled_secret_shapes(label: str, value: str):
    redacted = _trace_module().redact_persisted(value)
    if value in redacted:
        pytest.fail(f"{label} survived persisted redaction")


@pytest.mark.parametrize(
    "label, value",
    [
        pytest.param("db password", "db_password=synthetic-db-password", id="db-password"),
        pytest.param("stripe live", "sk_live_" + "A" * 24, id="stripe-live"),
        pytest.param("stripe test", "sk_test_" + "B" * 24, id="stripe-test"),
        pytest.param("google api", "AIzaSy" + "C" * 33, id="google-api"),
        pytest.param("gitlab PAT", "glpat-" + "D" * 20, id="gitlab-pat"),
    ],
)
def test_egress_redacts_labeled_secret_shapes(label: str, value: str):
    redacted, audit = egress_redaction.redact(value)
    if value in redacted:
        pytest.fail(f"{label} survived egress redaction")
    assert audit


@pytest.mark.parametrize(
    "value",
    [
        "sk_live_" + "A" * 23,
        "sk_test_" + "B" * 23,
        "AIzaSy" + "C" * 32,
        "glpat-" + "D" * 19,
        "hf_" + "E" * 40,
    ],
)
def test_egress_preserves_below_floor_prefixes_and_hf(value: str):
    redacted, audit = egress_redaction.redact(value)
    assert redacted == value
    assert audit == []
