#!/usr/bin/env bash
# Smoke-test the public Sentinel docs site (HTML + text charset + UTF-8 body).
set -euo pipefail

BASE="${1:-https://vinsoc.manhquy.id.vn}"
FAIL=0
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAIL=$((FAIL + 1)); }

check_http() {
  local path="$1" expect_ct="$2"
  local code ct
  code=$(curl -sS -D "$TMPDIR/h" -o "$TMPDIR/b" -w '%{http_code}' "$BASE$path")
  ct=$(tr -d '\r' <"$TMPDIR/h" | awk -F': ' 'BEGIN{IGNORECASE=1} tolower($1)=="content-type"{print $2}' | tail -1)
  if [[ "$code" != "200" ]]; then
    fail "$path status=$code"
    return
  fi
  if [[ -n "$expect_ct" && "$ct" != *"$expect_ct"* ]]; then
    fail "$path content-type='$ct' (want contains '$expect_ct')"
    return
  fi
  if [[ "$path" == *.txt || "$path" == *.md || "$expect_ct" == *charset=utf-8* ]]; then
    if ! iconv -f utf-8 -t utf-8 <"$TMPDIR/b" >/dev/null 2>&1; then
      fail "$path body not valid UTF-8"
      return
    fi
    if grep -q 'BÃ¡o\|tuáº§n\|â€”' "$TMPDIR/b"; then
      fail "$path looks mojibake-decoded"
      return
    fi
  fi
  pass "$path ($code; $ct)"
}

# WORKER=1: assert Content-Type charset from CF Worker (production).
# astro preview does not run worker.js — path/body checks still apply.
WORKER_CT=""
if [[ "${WORKER:-0}" == "1" ]]; then
  WORKER_CT="charset=utf-8"
fi

echo "Base: $BASE (WORKER=${WORKER:-0})"
check_http "/" "text/html"
check_http "/reports/" "text/html"
check_http "/reports/week-01/" "text/html"
check_http "/reports/week-02/" "text/html"
check_http "/reports/week-03/" "text/html"
check_http "/reports/week-04/" "text/html"
check_http "/reports/week-05/" "text/html"
check_http "/reports/week-06/" "text/html"
check_http "/reports/week-01/markdown/" "text/html"
check_http "/reports/week-02/markdown/" "text/html"
check_http "/reports/week-03/markdown/" "text/html"
check_http "/reports/week-04/markdown/" "text/html"
check_http "/reports/week-05/markdown/" "text/html"
check_http "/reports/week-06/markdown/" "text/html"
check_http "/reports/index/markdown/" "text/html"
check_http "/llms.txt" "$WORKER_CT"
check_http "/raw/reports/index.md" "$WORKER_CT"

# Interactive demo (static fixtures) — path/body checks work on any BASE
check_http "/demo/" "text/html"
check_http "/demo/charter/" "text/html"
check_http "/demo/week-03/" "text/html"
check_http "/demo/week-03/meta.json" "application/json"
check_http "/demo/week-03/report.jsonl" ""
check_http "/demo/week-03/aggregate.jsonl" ""
check_http "/demo/week-03/fail-closed.json" "application/json"

# Honesty banner + fail-closed CLI shape + llms discovery
if curl -sS "$BASE/demo/week-03/" | grep -q 'sample đã sanitize\|sample đã sanitize\|không phải lab'; then
  pass "/demo/week-03/ honesty banner"
else
  # also accept ASCII-normalized or entity forms via broader keywords
  if curl -sS "$BASE/demo/week-03/" | grep -qiE 'sanitize|không phải lab|khong phai lab|LLM live|Juice Shop'; then
    pass "/demo/week-03/ honesty banner (keyword)"
  else
    fail "/demo/week-03/ missing honesty banner text"
  fi
fi

if curl -sS "$BASE/demo/week-03/fail-closed.json" | grep -q '"failure"'; then
  pass "fail-closed.json has failure code"
else
  fail "fail-closed.json missing failure field"
fi

if curl -sS "$BASE/llms.txt" | grep -q '/demo/week-03'; then
  pass "llms.txt lists demo"
else
  fail "llms.txt missing demo path"
fi

# Fixture secret-shape guard (public samples must stay synthetic)
FIXTURE_BODY=$(curl -sS "$BASE/demo/week-03/aggregate.jsonl"; echo; curl -sS "$BASE/demo/week-03/report.jsonl"; echo; curl -sS "$BASE/demo/week-03/meta.json")
if printf '%s' "$FIXTURE_BODY" | grep -qE 'eyJ[A-Za-z0-9_-]{10,}\.|Bearer [A-Za-z0-9._-]{8,}|BEGIN (RSA |EC )?PRIVATE KEY|api_key\s*='; then
  fail "demo fixtures look like they contain secrets"
else
  pass "demo fixtures secret-shape clean"
fi

# Fail-closed contract shape
if curl -sS "$BASE/demo/week-03/fail-closed.json" | grep -q '"status"[[:space:]]*:[[:space:]]*"failed"'; then
  pass "fail-closed status=failed"
else
  fail "fail-closed missing status=failed"
fi

# manifest present
check_http "/demo/week-03/manifest.json" "application/json"

# Verify meta.sha256 pins via curl (urllib often gets CF 403 bot block)
if command -v python3 >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
  META_TMP="$TMPDIR/meta.json"
  if curl -sS -A 'SentinelWebsiteSmoke/1.0' -o "$META_TMP" "$BASE/demo/week-03/meta.json" \
    && python3 - "$META_TMP" "$BASE" "$TMPDIR" <<'PY'
import hashlib, json, subprocess, sys
meta_path, base, tmp = sys.argv[1], sys.argv[2].rstrip("/"), sys.argv[3]
meta = json.load(open(meta_path, encoding="utf-8"))
pins = meta.get("sha256") or {}
ok = True
for name, expected in pins.items():
    dest = f"{tmp}/{name.replace('/', '_')}"
    r = subprocess.run(
        ["curl", "-sS", "-A", "SentinelWebsiteSmoke/1.0", "-o", dest, f"{base}/demo/week-03/{name}"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        print(f"FETCH_FAIL {name}: {r.stderr}")
        ok = False
        continue
    got = hashlib.sha256(open(dest, "rb").read()).hexdigest()
    if got != expected:
        print(f"PIN_FAIL {name} got={got} want={expected}")
        ok = False
if not ok:
    raise SystemExit(1)
print("PIN_OK")
PY
  then
    pass "demo fixture sha256 pins match meta"
  else
    fail "demo fixture sha256 pins mismatch"
  fi
fi

# Group story copy present in HTML shell
if curl -sS "$BASE/demo/week-03/" | grep -q 'Nhóm cảnh báo'; then
  pass "/demo/week-03/ group map heading"
else
  fail "/demo/week-03/ missing group map heading"
fi

# Worker charset for JSONL demo fixtures (production only)
if [[ "${WORKER:-0}" == "1" ]]; then
  check_http "/demo/week-03/report.jsonl" "charset=utf-8"
  check_http "/demo/week-03/aggregate.jsonl" "charset=utf-8"
fi
check_http "/raw/reports/week-01.md" "$WORKER_CT"
check_http "/raw/reports/week-02.md" "$WORKER_CT"
check_http "/raw/reports/week-03.md" "$WORKER_CT"
check_http "/raw/reports/week-04.md" "$WORKER_CT"
check_http "/raw/reports/week-05.md" "$WORKER_CT"
check_http "/raw/reports/week-06.md" "$WORKER_CT"
check_http "/favicon.svg" ""
check_http "/sitemap-index.xml" ""

if curl -sS "$BASE/llms.txt" | grep -q 'Báo cáo tuần'; then
  pass "llms.txt contains Vietnamese title"
else
  fail "llms.txt missing Vietnamese title"
fi
if curl -sS "$BASE/llms.txt" | grep -q 'week-03'; then
  pass "llms.txt lists week-03"
else
  fail "llms.txt missing week-03"
fi
if curl -sS "$BASE/llms.txt" | grep -q 'week-04'; then
  pass "llms.txt lists week-04"
else
  fail "llms.txt missing week-04"
fi
if curl -sS "$BASE/llms.txt" | grep -q 'week-05'; then
  pass "llms.txt lists week-05"
else
  fail "llms.txt missing week-05"
fi
if curl -sS "$BASE/llms.txt" | grep -q 'week-06'; then
  pass "llms.txt lists week-06"
else
  fail "llms.txt missing week-06"
fi
if curl -sS "$BASE/llms.txt" | grep -q '1–6 / 6'; then
  pass "llms.txt records 1–6 / 6"
else
  fail "llms.txt progress is not 1–6 / 6"
fi

# Week 6 is published with the rest of the reports.
for published in /reports/week-06/ /reports/week-06/markdown/ /raw/reports/week-06.md; do
  published_code=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE$published")
  if [[ "$published_code" == "200" ]]; then
    pass "$published public (status=200)"
  else
    fail "$published not public (status=$published_code)"
  fi
done

if curl -sS "$BASE/raw/reports/week-06.md" | grep -q 'sentinel-charter-demo-runbook'; then
  fail "week-06 still links the personal 15-minute runbook"
else
  pass "week-06 does not link the personal runbook"
fi
if curl -sS "$BASE/raw/reports/week-06.md" | grep -q 'Prompt injection bị chặn'; then
  pass "week-06 demo section lists the seven scenes"
else
  fail "week-06 demo section missing the seven scenes"
fi
if curl -sS "$BASE/demo/charter/" | grep -q 'data-access-login'; then
  pass "/demo/charter/ has Access copy UI"
else
  fail "/demo/charter/ missing Access copy UI"
fi
if curl -sS "$BASE/demo/charter/" | grep -q 'vinsoc@manhquy.id.vn'; then
  pass "/demo/charter/ shows Access email"
else
  fail "/demo/charter/ missing Access email"
fi
if curl -sS "$BASE/demo/charter/" | grep -q 'DD_ADMIN_PASSWORD trong infra/.env'; then
  fail "/demo/charter/ still treats infra/.env as a public password"
else
  pass "/demo/charter/ does not point testers at gitignored infra/.env"
fi
if curl -sS "$BASE/demo/charter/" | grep -q 'data-copy="admin"'; then
  pass "/demo/charter/ has copy for DefectDojo admin"
else
  fail "/demo/charter/ missing admin copy button"
fi
if curl -sS "$BASE/" -o "$TMPDIR/home.html" && grep -q 'TTS Nguyễn Mạnh Quý' "$TMPDIR/home.html"; then
  pass "home footer/credit TTS"
else
  fail "home missing TTS credit"
fi
if grep -q 'Thực tập sinh' "$TMPDIR/home.html"; then
  fail "home still contains removed phrase Thực tập sinh"
else
  pass "home free of removed Thực tập sinh label"
fi

echo
if [[ "$FAIL" -eq 0 ]]; then
  echo "website-smoke-check: ALL PASS"
  exit 0
fi
echo "website-smoke-check: $FAIL failure(s)"
exit 1
