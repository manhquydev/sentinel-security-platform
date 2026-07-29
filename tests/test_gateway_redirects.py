"""Offline regression coverage for Gateway redirect handling."""
from __future__ import annotations

import json

import pytest
import requests

from agent import gateway


BASE = "https://127.0.0.1:18443"


def response(
    status: int,
    body: str = "",
    *,
    headers: dict[str, str] | None = None,
) -> requests.Response:
    """Build a Requests response without involving a transport."""
    result = requests.Response()
    result.status_code = status
    result._content = body.encode()
    result.headers.update(headers or {})
    result.url = BASE
    return result


@pytest.fixture(autouse=True)
def gateway_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway, "BASE", BASE)
    monkeypatch.setenv("AGENT_RECON_SECRET", "test-secret")


def test_token_keeps_its_body_and_transport_options(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_post(url: str, **kwargs: object) -> requests.Response:
        captured["url"] = url
        captured.update(kwargs)
        return response(200, json.dumps({"access_token": "token-123"}))

    monkeypatch.setattr(gateway.requests, "post", fake_post)

    assert gateway._token() == "token-123"
    assert captured == {
        "url": f"{BASE}/oauth/oauth2/token",
        "json": {
            "client_id": "agent-recon",
            "client_secret": "test-secret",
            "grant_type": "client_credentials",
        },
        "verify": False,
        "timeout": gateway.TIMEOUT,
        "allow_redirects": False,
    }


def test_token_redirect_without_token_keeps_existing_gateway_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_post(url: str, **kwargs: object) -> requests.Response:
        assert url == f"{BASE}/oauth/oauth2/token"
        assert kwargs["allow_redirects"] is False
        return response(307, "{}", headers={"Location": "https://hostile.invalid/token"})

    monkeypatch.setattr(gateway.requests, "post", fake_post)

    with pytest.raises(gateway.GatewayError, match="no access_token"):
        gateway._token()


def test_token_401_keeps_existing_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_post(url: str, **kwargs: object) -> requests.Response:
        assert url == f"{BASE}/oauth/oauth2/token"
        assert kwargs["allow_redirects"] is False
        return response(401, "unauthorized")

    monkeypatch.setattr(gateway.requests, "post", fake_post)

    with pytest.raises(requests.HTTPError):
        gateway._token()


def test_get_returns_original_redirect_and_keeps_request_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    def fake_post(url: str, **kwargs: object) -> requests.Response:
        return response(200, json.dumps({"access_token": "token-123"}))

    def fake_get(url: str, **kwargs: object) -> requests.Response:
        calls.append((url, kwargs))
        return response(302, "redirect body", headers={"Location": "https://hostile.invalid/next"})

    monkeypatch.setattr(gateway.requests, "post", fake_post)
    monkeypatch.setattr(gateway.requests, "get", fake_get)

    assert gateway.Gateway().get("/rest/products/search?q=apple") == (302, "redirect body")
    assert calls == [
        (
            f"{BASE}/rest/products/search?q=apple",
            {
                "headers": {"Authorization": "Bearer token-123"},
                "verify": False,
                "timeout": gateway.TIMEOUT,
                "allow_redirects": False,
            },
        )
    ]


def test_probe_returns_original_redirect_with_case_variant_content_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instance = gateway.Gateway.__new__(gateway.Gateway)
    instance._tok = "fixed-token"

    def fake_get(url: str, **kwargs: object) -> requests.Response:
        assert url == f"{BASE}/probe"
        assert kwargs == {
            "headers": {"Authorization": "Bearer fixed-token"},
            "verify": False,
            "timeout": gateway.TIMEOUT,
            "allow_redirects": False,
        }
        return response(
            308,
            "<html>redirect</html>",
            headers={"Content-Type": "text/html; charset=utf-8", "Location": "https://hostile.invalid/"},
        )

    monkeypatch.setattr(gateway.requests, "get", fake_get)

    assert instance.probe("/probe") == (308, "<html>redirect</html>", "text/html; charset=utf-8")


def test_reachable_is_false_for_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    instance = gateway.Gateway.__new__(gateway.Gateway)
    instance._tok = "fixed-token"
    calls = 0

    def fake_get(url: str, **kwargs: object) -> requests.Response:
        nonlocal calls
        calls += 1
        return response(302, "redirect")

    monkeypatch.setattr(gateway.requests, "get", fake_get)

    assert instance.reachable("/rest/products") is False
    assert calls == 1


def test_adapter_seam_does_not_follow_token_307(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[str] = []

    def fake_send(adapter: requests.adapters.HTTPAdapter, request: requests.PreparedRequest, **kwargs: object) -> requests.Response:
        sent.append(request.url)
        result = response(307, "{}", headers={"Location": "https://hostile.invalid/token"})
        result.request = request
        result.url = request.url
        return result

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", fake_send)

    with pytest.raises(gateway.GatewayError, match="no access_token"):
        gateway._token()
    assert sent == [f"{BASE}/oauth/oauth2/token"]


@pytest.mark.parametrize(
    ("method", "path", "status"),
    [("get", "/target?x=1", 302), ("probe", "/target?x=1", 307)],
)
def test_adapter_seam_does_not_follow_gateway_target_redirect(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    path: str,
    status: int,
) -> None:
    sent: list[str] = []

    def fake_send(
        adapter: requests.adapters.HTTPAdapter,
        request: requests.PreparedRequest,
        **kwargs: object,
    ) -> requests.Response:
        sent.append(request.url)
        if request.url == f"{BASE}/oauth/oauth2/token":
            result = response(200, json.dumps({"access_token": "adapter-token"}))
        else:
            result = response(
                status,
                "original",
                headers={"Location": "https://hostile.invalid/target"},
            )
        result.request = request
        result.url = request.url
        return result

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", fake_send)
    assert gateway.Gateway()._tok == "adapter-token"
    assert sent == [f"{BASE}/oauth/oauth2/token"]
    sent.clear()

    instance = gateway.Gateway.__new__(gateway.Gateway)
    instance._tok = "fixed-token"

    getattr(instance, method)(path)

    assert sent == [f"{BASE}{path}"]


def test_adapter_seam_control_without_redirect_flag_observes_follow_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[str] = []

    def fake_send(adapter: requests.adapters.HTTPAdapter, request: requests.PreparedRequest, **kwargs: object) -> requests.Response:
        sent.append(request.url)
        if len(sent) == 1:
            result = response(302, "", headers={"Location": "https://hostile.invalid/follow-up"})
        else:
            result = response(200, "followed")
        result.request = request
        result.url = request.url
        return result

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", fake_send)

    result = requests.get(f"{BASE}/control")

    assert result.status_code == 200
    assert sent == [f"{BASE}/control", "https://hostile.invalid/follow-up"]
