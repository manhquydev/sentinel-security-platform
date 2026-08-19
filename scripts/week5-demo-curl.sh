#!/usr/bin/env bash
# Source-of-truth curl talk track for the Week-5 facade. Host = 127.0.0.1 only.
set -euo pipefail
BASE="${WEEK5_DEMO_URL:-http://127.0.0.1:18055}"
case "$BASE" in
  http://127.0.0.1:*|https://127.0.0.1:*) ;;
  *) echo "FATAL: WEEK5_DEMO_URL must be 127.0.0.1" >&2; exit 2 ;;
esac

curl -fsS "$BASE/health" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("ok") is True'

curl -fsS -H 'Content-Type: application/json' -d '{"fixture":"goal"}' "$BASE/demo/ipi" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["status"]=="quarantined" and d["sent"] is False; print("ipi", d["status"])'

curl -fsS -H 'Content-Type: application/json' -d '{"text":"user_phone=+12025550143"}' "$BASE/demo/pii" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "+12025550143" not in d["redacted"] and d["sent"] is False; print("pii redacted")'

curl -fsS -H 'Content-Type: application/json' -d '{"case_id":"post-empty-object"}' "$BASE/demo/hitl/preview" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["method"]=="POST" and d["sent"] is False; print("hitl preview", d["path"])'

curl -fsS -H 'Content-Type: application/json' -d '{"case_id":"post-empty-object","decision":"reject"}' "$BASE/demo/hitl/decide" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["decision"]=="reject" and d["sent"] is False; print("hitl reject not_sent")'
