#!/usr/bin/env bash
# Offline regression for the Recon LiteLLM readiness boundary.  It uses only a local stub and
# proves that a 404 at the old `/health` endpoint never permits a chat attempt.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
ok() { echo "  PASS $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL $1" >&2; FAIL=$((FAIL+1)); }

start_stub() {
  local live_code="$1" marker="$2" port_file="$3"
  python3 - "$live_code" "$marker" "$port_file" <<'PY' &
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

status, marker, port_file = int(sys.argv[1]), sys.argv[2], sys.argv[3]
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_GET(self):
        code = status if self.path == "/health/liveliness" else 404
        self.send_response(code); self.end_headers()
    def do_POST(self):
        if self.path == "/v1/chat/completions":
            open(marker, "w").write("chat")
            body = json.dumps({"choices": [{"message": {"content": "acknowledged"}}], "usage": {}}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
            return
        self.send_response(404); self.end_headers()
server = HTTPServer(("127.0.0.1", 0), Handler)
open(port_file, "w").write(str(server.server_port))
server.serve_forever()
PY
  STUB_PID=$!
  for _ in $(seq 1 30); do [ -s "$port_file" ] && break; sleep 0.05; done
  PORT="$(cat "$port_file")"
}

run_recon() {
  local required="$1"
  ENV_FILE="$WORK/missing.env" LITELLM_MASTER_KEY="stub-key" REQUIRE_LITELLM="$required" \
    REQUIRE_AGENT=0 DD_URL="http://127.0.0.1:9" LITELLM_BASE="http://127.0.0.1:$PORT" \
    bash "$ROOT/tests/recon-agent-test.sh" >"$WORK/recon.out" 2>&1
}

# Optional mode deliberately performs no transport at all; it cannot accidentally
# dispatch a chat merely because a legacy/incorrect health endpoint is present.
start_stub 404 "$WORK/no-chat" "$WORK/port-a"
if run_recon 0 && ! [ -e "$WORK/no-chat" ] && grep -q 'SKIP.*credentialed LiteLLM round-trip' "$WORK/recon.out"; then
  ok "optional mode makes no preflight or chat request"
else
  bad "optional branch attempted chat or did not skip"
fi
kill "$STUB_PID"; wait "$STUB_PID" 2>/dev/null || true

# Required mode turns exactly the same failed preflight into a test failure, still before chat.
start_stub 404 "$WORK/required-no-chat" "$WORK/port-b"
if ! run_recon 1 && ! [ -e "$WORK/required-no-chat" ] && grep -q 'FAIL.*REQUIRE_LITELLM=1' "$WORK/recon.out"; then
  ok "404 liveliness is fatal in required mode before chat"
else
  bad "required 404 did not fail closed"
fi
kill "$STUB_PID"; wait "$STUB_PID" 2>/dev/null || true

# A 200 same-base liveliness endpoint enables the controlled provenance-labelled route.
start_stub 200 "$WORK/chat" "$WORK/port-c"
if run_recon 1 && [ -f "$WORK/chat" ] && grep -q 'PASS.*same-base live HTTP 200' "$WORK/recon.out"; then
  ok "200 liveliness permits the controlled one-suffix chat branch"
else
  cat "$WORK/recon.out" >&2
  bad "200 liveliness did not permit controlled chat"
fi
kill "$STUB_PID"; wait "$STUB_PID" 2>/dev/null || true

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
