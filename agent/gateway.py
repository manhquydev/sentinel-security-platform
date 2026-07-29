"""Reach the staging target only through the Kong gateway, as the agent-recon identity.

The Recon agent never touches the app directly; it mints a short-TTL OAuth2 token for the
`agent-recon` consumer (Week-2 Agent IAM) and calls through Kong, which enforces the ACL. So the
agent physically inherits its scope from the gateway: it can probe public read endpoints and is
refused admin/state-changing ones (403). Responses are target-derived and untrusted — callers
must label them accordingly before any of that text reaches a model.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse

import requests
import urllib3

# The gateway serves a self-signed cert on loopback; verify=False is intentional (a disclosed
# residual, see infra/kong/README.md), so silence the one expected warning rather than let it
# clutter every agent run.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = os.environ.get("KONG_PROXY", "https://127.0.0.1:18443")
TIMEOUT = 10


class GatewayError(RuntimeError):
    pass


def _assert_loopback() -> None:
    """verify=False is only acceptable on loopback. If KONG_PROXY is (mis)pointed at a non-loopback
    host, refuse rather than silently accept a MITM'able TLS connection."""
    host = urlparse(BASE).hostname or ""
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise RuntimeError(
            f"refusing TLS-unverified requests to non-loopback host {host!r}; set KONG_PROXY to loopback")


def _token() -> str:
    _assert_loopback()
    secret = os.environ.get("AGENT_RECON_SECRET")
    if not secret:
        raise RuntimeError("AGENT_RECON_SECRET not set (source infra/.env)")
    r = requests.post(f"{BASE}/oauth/oauth2/token",
                      json={"client_id": "agent-recon", "client_secret": secret,
                            "grant_type": "client_credentials"},
                      verify=False, timeout=TIMEOUT, allow_redirects=False)  # loopback self-signed cert
    r.raise_for_status()
    tok = r.json().get("access_token")
    if not tok:
        raise GatewayError("no access_token in token response")
    return tok


class Gateway:
    """One token per instance (a token is good for the agent's run)."""

    def __init__(self):
        self._tok = _token()

    def get(self, path: str) -> tuple[int, str]:
        """GET a path through the gateway. Returns (status, body). A 403 is a real authorization
        result (the ACL refused the path), not an error to retry — surfaced as the status."""
        r = requests.get(f"{BASE}{path}", headers={"Authorization": f"Bearer {self._tok}"},
                         verify=False, timeout=TIMEOUT, allow_redirects=False)
        return r.status_code, r.text

    def probe(self, path: str) -> tuple[int, str, str]:
        """Like get(), but also returns the response Content-Type — the fuzzing signal detector
        needs it to spot a content-type change (e.g. a JSON endpoint returning an HTML error)."""
        r = requests.get(f"{BASE}{path}", headers={"Authorization": f"Bearer {self._tok}"},
                         verify=False, timeout=TIMEOUT, allow_redirects=False)
        return r.status_code, r.text, r.headers.get("content-type", "")

    def reachable(self, path: str) -> bool:
        """True if the agent-recon identity may read this path (2xx), False if the gateway
        refuses it (401/403) — a cheap liveness+authorization probe."""
        try:
            code, _ = self.get(path)
        except requests.RequestException:
            return False
        return 200 <= code < 300
