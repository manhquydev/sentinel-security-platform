"""Minimal loopback WSGI-free app factory used by the local demo launcher."""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from .api import WorkbenchAPI


def make_handler(api: WorkbenchAPI) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _json(self, status: int, value: object) -> None:
            body = json.dumps(value, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/api/view":
                self._json(200, api.view())
                return
            static = {
                "/": ("index.html", "text/html; charset=utf-8"),
                "/app.js": ("app.js", "application/javascript; charset=utf-8"),
                "/app.css": ("app.css", "text/css; charset=utf-8"),
            }.get(self.path)
            if static is None:
                self._json(404, {"error": "not-found"})
                return
            path = Path(__file__).with_name("static") / static[0]
            body = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", static[1])
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            self._json(405, {"error": "broker-mediated-post-required"})

        def log_message(self, *_args: object) -> None:
            return

    return Handler


def serve(api: WorkbenchAPI, *, host: str = "127.0.0.1", port: int = 4173) -> None:
    HTTPServer((host, port), make_handler(api)).serve_forever()


if __name__ == "__main__":
    serve(
        WorkbenchAPI(
            registry=__import__("workbench.web.api", fromlist=["ProfileRegistry"]).ProfileRegistry(profiles={}),
            cmc_gate={"status": "not-run", "reason": "no-timed-census-record"},
            broker_origin=os.environ.get("WORKBENCH_BROKER_ORIGIN") or None,
        ),
        host=os.environ.get("WORKBENCH_BIND", "127.0.0.1"),
    )
