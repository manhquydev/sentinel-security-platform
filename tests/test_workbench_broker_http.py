from __future__ import annotations

import http.client
import json
import threading
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from typing import Iterator

from workbench.broker_http import make_handler
from workbench.host_broker import HostBroker


UI_ORIGIN = "http://127.0.0.1:4173"
CONFIG_DIGEST = "a" * 64
PAIR_DIGEST = "b" * 64
CAPABILITY = "capability-once-opaque-32-bytes"


@contextmanager
def broker_server(state_path=None) -> Iterator[tuple[HostBroker, ThreadingHTTPServer]]:
    broker = HostBroker(
        ui_origin=UI_ORIGIN,
        startup_capability=CAPABILITY,
        config_digest=CONFIG_DIGEST,
        allowed_profiles={"fixture-typescript"},
        allowed_pair_digests={PAIR_DIGEST},
        session_ttl_seconds=300,
        state_path=state_path,
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(broker))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield broker, server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request(
    server: ThreadingHTTPServer,
    method: str,
    target: str,
    *,
    body: object | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], object]:
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    payload = None if body is None else json.dumps(body)
    request_headers = {
        "Host": f"127.0.0.1:{server.server_port}",
        "Origin": UI_ORIGIN,
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        **(headers or {}),
    }
    connection.request(method, target, body=payload, headers=request_headers)
    response = connection.getresponse()
    decoded = response.read().decode("utf-8")
    result = (response.status, dict(response.getheaders()), json.loads(decoded) if decoded else None)
    connection.close()
    return result


def test_http_broker_bootstraps_once_then_accepts_only_csrf_bound_typed_commands_and_status():
    with broker_server() as (_, server):
        status, headers, body = request(
            server,
            "POST",
            "/api/bootstrap",
            body={"startup_capability": CAPABILITY},
            headers={"Content-Type": "application/json"},
        )
        assert status == 201
        assert set(body) == {"csrf_token"}
        cookie = headers["Set-Cookie"]
        assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Path=/api/" in cookie
        assert headers["Access-Control-Allow-Origin"] == UI_ORIGIN
        assert headers["Vary"] == "Origin"

        status, _, command = request(
            server,
            "POST",
            "/api/commands",
            body={
                "schema_version": "sentinel-workbench-broker-command/v1",
                "command": "run-fixture-scan",
                "profile": "fixture-typescript",
                "pair_digest": PAIR_DIGEST,
                "config_digest": CONFIG_DIGEST,
            },
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-Workbench-CSRF": body["csrf_token"],
            },
        )
        assert status == 202
        assert command["status"] == "queued"
        assert set(command) == {"schema_version", "command_id", "status"}

        status, _, result = request(
            server,
            "POST",
            "/api/status",
            body={"command_id": command["command_id"]},
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-Workbench-CSRF": body["csrf_token"],
            },
        )
        assert status == 200
        assert result == command


def test_http_broker_rejects_replay_wrong_origin_and_unsafe_methods_without_exposing_status():
    with broker_server() as (_, server):
        status, _, _ = request(
            server,
            "POST",
            "/api/bootstrap",
            body={"startup_capability": CAPABILITY},
            headers={"Content-Type": "application/json"},
        )
        assert status == 201
        status, _, error = request(
            server,
            "POST",
            "/api/bootstrap",
            body={"startup_capability": CAPABILITY},
            headers={"Content-Type": "application/json"},
        )
        assert status == 400
        assert error == {"error": "invalid-request"}

        status, _, error = request(
            server,
            "POST",
            "/api/status",
            body={"command_id": "untrusted"},
            headers={"Content-Type": "application/json"},
        )
        assert status == 400
        assert error == {"error": "invalid-request"}

        status, _, error = request(server, "GET", "/api/status")
        assert status == 405
        assert error == {"error": "method-not-allowed"}


def test_http_broker_uses_the_private_durable_queue_from_request_threads(tmp_path):
    with broker_server(tmp_path / "private" / "broker.sqlite") as (_, server):
        status, headers, body = request(
            server,
            "POST",
            "/api/bootstrap",
            body={"startup_capability": CAPABILITY},
            headers={"Content-Type": "application/json"},
        )
        assert status == 201
        status, _, command = request(
            server,
            "POST",
            "/api/commands",
            body={
                "schema_version": "sentinel-workbench-broker-command/v1",
                "command": "run-fixture-scan",
                "profile": "fixture-typescript",
                "pair_digest": PAIR_DIGEST,
                "config_digest": CONFIG_DIGEST,
            },
            headers={
                "Content-Type": "application/json",
                "Cookie": headers["Set-Cookie"],
                "X-Workbench-CSRF": body["csrf_token"],
            },
        )
        assert status == 202
        assert command["status"] == "queued"
