#!/usr/bin/env python3
"""Loopback teaching facade for Week-5 IPI / HITL / PII.

This process is a demo sidecar. It is not the Charter executor: it never
imports the signer, never reads infra/.env, and never opens a socket to Kong
or Juice Shop. Approve in this facade is recorded as not_sent.

Bind only 127.0.0.1. Compose must publish 127.0.0.1:<port>:<port>.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.charter_requests import CharterRequestError, safe_request_case  # noqa: E402
from agent.charter_response_guard import guard_http_response  # noqa: E402
from agent.pii import redact  # noqa: E402

HOST = "127.0.0.1"
PORT = 18055
MAX_BODY = 64 * 1024
FIXTURE_DIR = ROOT / "tests" / "fixtures"


def _json_bytes(payload: dict[str, Any], status: int = 200) -> tuple[int, bytes]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return status, body


def handle_ipi(data: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    text = data.get("text")
    fixture = data.get("fixture")
    if fixture in {"goal", "secrets"}:
        path = FIXTURE_DIR / f"charter-response-ipi-{fixture}.json"
        text = json.loads(path.read_text(encoding="utf-8"))["response"]
    if type(text) is not str:
        return 400, {"error": "text string or fixture goal|secrets required"}
    result = guard_http_response(text)
    return 200, {
        "status": result.status,
        "reasons": list(result.reasons),
        "persisted_text": result.persisted_text,
        "sent": False,
    }


def handle_pii(data: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    text = data.get("text")
    if type(text) is not str:
        return 400, {"error": "text string required"}
    redacted, findings = redact(text)
    return 200, {
        "redacted": redacted,
        "findings": [{"cls": f.cls, "count": f.count} for f in findings],
        "sent": False,
    }


def handle_hitl_preview(data: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    case_id = data.get("case_id")
    if type(case_id) is not str:
        return 400, {"error": "case_id required"}
    try:
        case = safe_request_case(case_id)
    except CharterRequestError:
        return 400, {"error": "request outside immutable charter policy"}
    return 200, {
        "case_id": case.case_id,
        "method": case.method,
        "path": case.path,
        "query": case.query,
        "body": case.body,
        "purpose": case.purpose,
        "sent": False,
    }


def handle_hitl_decide(data: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    case_id = data.get("case_id")
    decision = data.get("decision")
    if type(case_id) is not str or decision not in {"approve", "reject"}:
        return 400, {"error": "case_id and decision approve|reject required"}
    try:
        safe_request_case(case_id)
    except CharterRequestError:
        return 400, {"error": "request outside immutable charter policy"}
    return 200, {
        "case_id": case_id,
        "decision": decision,
        "sent": False,
        "note": "facade does not send; Charter HITL remains the CLI signer",
    }


ROUTES = {
    ("POST", "/demo/ipi"): handle_ipi,
    ("POST", "/demo/pii"): handle_pii,
    ("POST", "/demo/hitl/preview"): handle_hitl_preview,
    ("POST", "/demo/hitl/decide"): handle_hitl_decide,
}


class DemoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    listen_bind = HOST
    listen_port = PORT

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/health":
            bind = f"{self.listen_bind}:{self.listen_port}"
            status, body = _json_bytes({"ok": True, "bind": bind, "sent": False})
            self._send(status, body)
            return
        self._send(*_json_bytes({"error": "not found"}, 404))

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        handler = ROUTES.get(("POST", path))
        if handler is None:
            self._send(*_json_bytes({"error": "not found"}, 404))
            return
        length = self.headers.get("Content-Length", "")
        try:
            n = int(length)
        except ValueError:
            self._send(*_json_bytes({"error": "content-length required"}, 400))
            return
        if n < 0 or n > MAX_BODY:
            self._send(*_json_bytes({"error": "body too large"}, 413))
            return
        raw = self.rfile.read(n)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(*_json_bytes({"error": "json required"}, 400))
            return
        if type(data) is not dict:
            self._send(*_json_bytes({"error": "json object required"}, 400))
            return
        code, payload = handler(data)
        self._send(*_json_bytes(payload, code))


def main() -> int:
    parser = argparse.ArgumentParser(description="Week-5 loopback demo facade")
    parser.add_argument("--bind", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    in_container = os.environ.get("SENTINEL_WEEK5_DEMO_CONTAINER") == "1"
    if args.bind == "0.0.0.0" and not in_container:
        print("FATAL: 0.0.0.0 bind is only for the published container (host still 127.0.0.1)", file=sys.stderr)
        return 2
    if args.bind not in {"127.0.0.1", "0.0.0.0"}:
        print("FATAL: bind must be 127.0.0.1 (host) or 0.0.0.0 (container)", file=sys.stderr)
        return 2
    DemoHandler.listen_bind = args.bind
    DemoHandler.listen_port = args.port
    server = ThreadingHTTPServer((args.bind, args.port), DemoHandler)
    print(f"week5-demo listening on http://{args.bind}:{args.port} (facade, not executor)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
