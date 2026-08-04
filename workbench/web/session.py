"""Browser bootstrap and request-boundary validation."""
from __future__ import annotations

import re
from urllib.parse import parse_qs

from ..contracts import ContractViolation
from ..host_broker import BrokerSession, HostBroker


def validate_browser_request(
    *,
    host: str,
    origin: str,
    method: str,
    content_type: str,
    fetch_site: str,
    fetch_mode: str,
    request_target: str,
) -> bool:
    if (
        not isinstance(host, str)
        or not re.fullmatch(r"127\.0\.0\.1:\d+", host)
        or not isinstance(origin, str)
        or not origin.startswith("http://127.0.0.1:")
        or method != "POST"
        or content_type != "application/json"
        or fetch_site not in {"same-origin", "same-site"}
        or fetch_mode != "cors"
        or "?" in request_target
        or "#" in request_target
    ):
        raise ContractViolation("browser request is outside the exact loopback POST contract")
    return True


def bootstrap_from_fragment(
    broker: HostBroker,
    *,
    fragment: str,
    request_target: str,
    headers: dict[str, str],
    origin: str,
) -> BrokerSession:
    if "?" in request_target or "#" in request_target:
        raise ContractViolation("bootstrap capability must not appear in the request target")
    if not isinstance(fragment, str) or not fragment.startswith("#"):
        raise ContractViolation("bootstrap capability must arrive in the URL fragment")
    values = parse_qs(fragment[1:], strict_parsing=True)
    capabilities = values.get("startup_capability")
    if capabilities is None or len(capabilities) != 1:
        raise ContractViolation("bootstrap fragment is missing its one-time capability")
    if any(key.lower() in {"authorization", "x-startup-capability"} for key in headers):
        raise ContractViolation("bootstrap capability cannot be copied into a header")
    return broker.bootstrap(
        origin=origin,
        body={"startup_capability": capabilities[0]},
        request_target=request_target,
        request_headers=headers,
    )
