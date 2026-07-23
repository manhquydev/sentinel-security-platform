#!/usr/bin/env bash
# Fail-closed allowlist guard (phase-03). Uses literal-IP URLs so no DNS is
# needed. Each REJECT case is a negative control: the guard must block it.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AL="$REPO_ROOT/scanners/target-allowlist.sh"

PASS=0; FAIL=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }

# expect_allow <label> <allowlist> <url> [<expected pinned ip>]
expect_allow() {
  local label="$1" al="$2" url="$3" want="${4:-}"
  local got rc
  got="$(ALLOWLIST="$al" "$AL" validate "$url" 2>/dev/null)"; rc=$?
  if [ "$rc" -ne 0 ]; then bad "$label (expected allow, got reject)"; return; fi
  if [ -n "$want" ] && [ "$got" != "$want" ]; then bad "$label (pinned '$got' != '$want')"; return; fi
  ok "$label"
}
# expect_reject <label> <allowlist> <url>
expect_reject() {
  local label="$1" al="$2" url="$3" rc
  ALLOWLIST="$al" "$AL" validate "$url" >/dev/null 2>&1; rc=$?
  if [ "$rc" -eq 0 ]; then bad "$label (expected reject, got allow)"; else ok "$label"; fi
}

printf '\n== allow: explicitly-listed loopback harness ==\n'
expect_allow  "Juice Shop 127.0.0.1:13000 allowed by exact entry" "127.0.0.1:13000" "http://127.0.0.1:13000/rest/products/search" "127.0.0.1"

printf '\n== fail-closed: dangerous ranges not in allowlist ==\n'
expect_reject "loopback with empty allowlist"          ""                "http://127.0.0.1:13000/"
expect_reject "cloud metadata 169.254.169.254"         "127.0.0.1:13000" "http://169.254.169.254/latest/meta-data/"
expect_reject "RFC1918 10.5.5.5"                       "127.0.0.1:13000" "http://10.5.5.5:8080/"
expect_reject "RFC1918 192.168.1.1"                    "127.0.0.1:13000" "http://192.168.1.1/"
expect_reject "link-local 169.254.10.10"               "127.0.0.1:13000" "http://169.254.10.10/"
expect_reject "IPv6 loopback [::1] not listed"         "127.0.0.1:13000" "http://[::1]:13000/"

printf '\n== port enforcement when the entry pins a port ==\n'
expect_reject "same IP, wrong port (entry has :13000)" "127.0.0.1:13000" "http://127.0.0.1:9999/"
expect_allow  "IP-only entry permits any port"         "127.0.0.1"       "http://127.0.0.1:9999/" "127.0.0.1"

printf '\n== summary ==\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
