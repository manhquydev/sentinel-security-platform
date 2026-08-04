from __future__ import annotations

import pytest

from workbench.contracts import ContractViolation
from workbench.host_broker import HostBroker
from workbench.web.session import validate_browser_request, bootstrap_from_fragment


UI = "http://127.0.0.1:4173"
CAPABILITY = "capability-once-opaque-32-bytes"


def broker():
    return HostBroker(
        ui_origin=UI,
        startup_capability=CAPABILITY,
        config_digest="a" * 64,
        allowed_profiles={"fixture"},
        allowed_pair_digests={"b" * 64},
        session_ttl_seconds=300,
    )


def test_browser_bootstrap_only_accepts_exact_loopback_origin_and_fragment_capability():
    assert validate_browser_request(
        host="127.0.0.1:4173",
        origin=UI,
        method="POST",
        content_type="application/json",
        fetch_site="same-origin",
        fetch_mode="cors",
        request_target="/api/bootstrap",
    )
    session = bootstrap_from_fragment(
        broker(),
        fragment="#startup_capability=capability-once-opaque-32-bytes",
        request_target="/api/bootstrap",
        headers={"content-type": "application/json"},
        origin=UI,
    )
    assert "HttpOnly" in session.cookie_header


@pytest.mark.parametrize(
    "kwargs",
    [
        {"host": "evil.example:4173", "origin": UI},
        {"host": "127.0.0.1:4173", "origin": "http://evil.example"},
        {"host": "127.0.0.1:4173", "origin": UI, "fetch_site": "cross-site"},
        {"host": "127.0.0.1:4173", "origin": UI, "content_type": "text/plain"},
    ],
)
def test_browser_rejects_cross_site_non_loopback_or_form_requests(kwargs):
    values = {
        "host": "127.0.0.1:4173",
        "origin": UI,
        "method": "POST",
        "content_type": "application/json",
        "fetch_site": "same-origin",
        "fetch_mode": "cors",
        "request_target": "/api/bootstrap",
    }
    values.update(kwargs)
    with pytest.raises(ContractViolation):
        validate_browser_request(**values)


def test_capability_fragment_is_single_use_and_never_accepted_from_query_or_header():
    service = broker()
    with pytest.raises(ContractViolation):
        bootstrap_from_fragment(
            service,
            fragment="",
            request_target="/api/bootstrap?startup_capability=" + CAPABILITY,
            headers={"content-type": "application/json"},
            origin=UI,
        )
    first = bootstrap_from_fragment(
        service,
        fragment="#startup_capability=" + CAPABILITY,
        request_target="/api/bootstrap",
        headers={"content-type": "application/json"},
        origin=UI,
    )
    assert first.csrf_token
    with pytest.raises(ContractViolation):
        bootstrap_from_fragment(
            service,
            fragment="#startup_capability=" + CAPABILITY,
            request_target="/api/bootstrap",
            headers={"content-type": "application/json"},
            origin=UI,
        )
