"""Loopback-only HTTP adapter for the host-owned Workbench broker."""
from __future__ import annotations

import json
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .contracts import ContractViolation
from .host_broker import HostBroker
from .web.session import validate_browser_request


_JSON_TYPE = "application/json"
_CSRF_HEADER = "x-workbench-csrf"
_MAX_BODY_BYTES = 16 * 1024


class BrokerHTTPViolation(ValueError):
    """Raised for malformed HTTP adapter input before it reaches the broker."""


def make_handler(broker: HostBroker) -> type[BaseHTTPRequestHandler]:
    """Build a narrowly scoped handler; no source, worker, or key path is exposed."""

    class Handler(BaseHTTPRequestHandler):
        def _origin(self) -> str:
            values = self.headers.get_all("Origin")
            if values is None or len(values) != 1:
                raise BrokerHTTPViolation("request needs one Origin")
            return values[0]

        def _header(self, name: str, *, required: bool = True) -> str:
            values = self.headers.get_all(name)
            if values is None:
                if required:
                    raise BrokerHTTPViolation(f"missing {name}")
                return ""
            if len(values) != 1:
                raise BrokerHTTPViolation(f"duplicate {name}")
            return values[0]

        def _validate_post(self) -> str:
            origin = self._origin()
            validate_browser_request(
                host=self._header("Host"),
                origin=origin,
                method="POST",
                content_type=self._header("Content-Type"),
                fetch_site=self._header("Sec-Fetch-Site"),
                fetch_mode=self._header("Sec-Fetch-Mode"),
                request_target=self.path,
            )
            return origin

        def _body(self) -> dict[str, Any]:
            raw_length = self._header("Content-Length")
            try:
                length = int(raw_length)
            except ValueError as error:
                raise BrokerHTTPViolation("invalid Content-Length") from error
            if length < 1 or length > _MAX_BODY_BYTES:
                raise BrokerHTTPViolation("invalid JSON body size")
            try:
                value = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise BrokerHTTPViolation("invalid JSON body") from error
            if not isinstance(value, dict):
                raise BrokerHTTPViolation("JSON body must be an object")
            return value

        def _session(self) -> tuple[str, str]:
            raw = self._header("Cookie")
            if raw.count("workbench_session=") != 1:
                raise BrokerHTTPViolation("request needs one broker session cookie")
            cookie = SimpleCookie()
            try:
                cookie.load(raw)
            except (CookieError, KeyError) as error:
                raise BrokerHTTPViolation("invalid broker session cookie") from error
            item = cookie.get("workbench_session")
            if item is None or not item.value:
                raise BrokerHTTPViolation("missing broker session cookie")
            return item.value, self._header(_CSRF_HEADER)

        def _cors(self, origin: str, *, requested_headers: tuple[str, ...] = ("content-type", "x-workbench-csrf")) -> dict[str, str]:
            return broker.cors_headers(
                origin,
                method="POST",
                requested_headers=requested_headers,
            )

        def _json(
            self,
            status: HTTPStatus,
            value: object,
            *,
            origin: str | None = None,
            cookie: str | None = None,
            requested_headers: tuple[str, ...] = ("content-type", "x-workbench-csrf"),
        ) -> None:
            body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", _JSON_TYPE)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            if origin is not None:
                for key, item in self._cors(origin, requested_headers=requested_headers).items():
                    self.send_header(key, item)
            if cookie is not None:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(body)

        def _reject(self, status: HTTPStatus = HTTPStatus.BAD_REQUEST) -> None:
            self._json(status, {"error": "invalid-request"})

        def do_OPTIONS(self) -> None:
            try:
                origin = self._origin()
                if self.path not in {"/api/bootstrap", "/api/commands", "/api/status"}:
                    raise BrokerHTTPViolation("unknown endpoint")
                if self._header("Access-Control-Request-Method") != "POST":
                    raise BrokerHTTPViolation("unsupported CORS method")
                requested = tuple(
                    item.strip().lower()
                    for item in self._header("Access-Control-Request-Headers").split(",")
                )
                expected = ("content-type",) if self.path == "/api/bootstrap" else ("content-type", "x-workbench-csrf")
                if requested != expected:
                    raise BrokerHTTPViolation("unsupported CORS headers")
                self._json(HTTPStatus.NO_CONTENT, None, origin=origin, requested_headers=requested)
            except (BrokerHTTPViolation, ContractViolation):
                self._reject()

        def do_POST(self) -> None:
            try:
                origin = self._validate_post()
                body = self._body()
                if self.path == "/api/bootstrap":
                    session = broker.bootstrap(
                        origin=origin,
                        body=body,
                        request_target=self.path,
                        request_headers={key.lower(): value for key, value in self.headers.items()},
                    )
                    self._json(
                        HTTPStatus.CREATED,
                        {"csrf_token": session.csrf_token},
                        origin=origin,
                        cookie=session.cookie_header,
                    )
                    return
                session_id, csrf_token = self._session()
                if self.path == "/api/commands":
                    status = broker.submit_command(
                        origin=origin,
                        session_id=session_id,
                        csrf_token=csrf_token,
                        envelope=body,
                    )
                    self._json(HTTPStatus.ACCEPTED, status.to_mapping(), origin=origin)
                    return
                if self.path == "/api/status":
                    if set(body) != {"command_id"}:
                        raise BrokerHTTPViolation("invalid status request")
                    status = broker.status_for_session(
                        origin=origin,
                        session_id=session_id,
                        csrf_token=csrf_token,
                        command_id=body["command_id"],
                    )
                    self._json(HTTPStatus.OK, status.to_mapping(), origin=origin)
                    return
                raise BrokerHTTPViolation("unknown endpoint")
            except (BrokerHTTPViolation, ContractViolation, TypeError):
                self._reject()

        def do_GET(self) -> None:
            self._json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "method-not-allowed"})

        def log_message(self, *_args: object) -> None:
            return

    return Handler


def serve(broker: HostBroker, *, host: str = "127.0.0.1", port: int = 4174) -> None:
    """Run the broker only on literal loopback; the Compose UI is never this process."""
    if host != "127.0.0.1":
        raise BrokerHTTPViolation("broker must bind literal IPv4 loopback")
    ThreadingHTTPServer((host, port), make_handler(broker)).serve_forever()
