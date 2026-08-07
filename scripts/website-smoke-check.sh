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

echo "Base: $BASE"
check_http "/" "text/html"
check_http "/reports/" "text/html"
check_http "/reports/week-01/" "text/html"
check_http "/reports/week-02/" "text/html"
check_http "/reports/week-03/" "text/html"
check_http "/reports/week-01/markdown/" "text/html"
check_http "/reports/week-02/markdown/" "text/html"
check_http "/reports/week-03/markdown/" "text/html"
check_http "/reports/index/markdown/" "text/html"
check_http "/llms.txt" "charset=utf-8"
check_http "/raw/reports/index.md" "charset=utf-8"
check_http "/raw/reports/week-01.md" "charset=utf-8"
check_http "/raw/reports/week-02.md" "charset=utf-8"
check_http "/raw/reports/week-03.md" "charset=utf-8"
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
