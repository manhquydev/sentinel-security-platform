"""Host-native direct-loopback CMC smoke request boundary."""
from __future__ import annotations

import os
from typing import Mapping
from urllib.parse import urlsplit


class ActiveExecutorViolation(ValueError):
    """Raised before unsafe CMC traffic can be attempted."""


def execute_catalog_request(catalog: Mapping[str, object], *, approval: Mapping[str, object]) -> dict[str, object]:
    if approval.get("status") != "approved":
        raise ActiveExecutorViolation("CMC dispatch lacks an approved one-time authorization")
    origin = catalog.get("origin")
    if not isinstance(origin, str):
        raise ActiveExecutorViolation("CMC catalog origin is missing")
    parsed = urlsplit(origin)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.username or parsed.password:
        raise ActiveExecutorViolation("CMC executor only permits literal direct loopback origins")
    if any(os.environ.get(name) for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")):
        raise ActiveExecutorViolation("CMC executor refuses proxy-configured dispatch")
    if catalog.get("method") != "GET" or not isinstance(catalog.get("request_path"), str):
        raise ActiveExecutorViolation("CMC catalog request is not the exact non-mutating GET contract")
    # Transport is intentionally not attempted until a runtime-identity/approval
    # bridge supplies a connected loopback socket in a later integration phase.
    raise ActiveExecutorViolation("CMC runtime identity is not verified; zero traffic dispatched")
