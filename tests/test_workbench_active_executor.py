from __future__ import annotations

import pytest

from workbench.active_executor import ActiveExecutorViolation, execute_catalog_request
from workbench.cmc_runtime_identity import CmcRuntimeIdentity


def identity():
    return CmcRuntimeIdentity(
        container_image_digest="a" * 64,
        container_id="container-1",
        published_port=8088,
        started_at="2026-08-04T00:00:00+00:00",
    )


def test_active_executor_rejects_nonliteral_loopback_and_proxy_or_redirect_configuration(monkeypatch):
    catalog = {"origin": "http://localhost:8088", "method": "GET", "request_path": "/health", "identity": identity().to_mapping()}
    monkeypatch.setenv("HTTP_PROXY", "http://evil.example")
    with pytest.raises(ActiveExecutorViolation):
        execute_catalog_request(catalog, approval={"status": "approved"})

    catalog["origin"] = "http://127.0.0.1:8088"
    with pytest.raises(ActiveExecutorViolation):
        execute_catalog_request(catalog, approval={"status": "rejected"})
