#!/usr/bin/env bash
# Native-path redaction guarantee (phase-03, TDD step 1 = RED).
#
# For each of the 4 native parsers, runs redact-report.sh over a fixture that
# carries a PLANTED secret and asserts:
#   (a) every planted secret VALUE is GONE from the sanitized output, and
#   (b) the endpoint / file LOCATOR survives (P1 endpoint-dedup hashes on it).
#
# Against the RED no-op stub, every (a) assertion must FAIL — that is the point.
# The redactor is only believed once this suite has been seen red, then green.
#
# Exit 0 only if all assertions pass.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIX="$REPO_ROOT/tests/fixtures"
REDACT="$REPO_ROOT/scanners/redact-report.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
sect(){ printf '\n== %s ==\n' "$1"; }

# assert a string is ABSENT from the sanitized file (secret redacted)
absent() { # <label> <file> <needle>
  if grep -qF -- "$3" "$2"; then bad "$1 (secret survived: $3)"; else ok "$1"; fi
}
# assert a string is PRESENT in the sanitized file (locator preserved)
present() { # <label> <file> <needle>
  if grep -qF -- "$3" "$2"; then ok "$1"; else bad "$1 (locator lost: $3)"; fi
}

run() { # <scan_type> <fixture> -> sanitized path on stdout
  local out="$WORK/$1.out"
  "$REDACT" "$1" "$FIX/$2" "$out" >/dev/null 2>&1 || { echo ""; return 1; }
  echo "$out"
}

sect "ZAP XML — secrets redacted (incl evidence/otherinfo), endpoint locator preserved"
z="$(run zap zap-planted-token.xml)" || bad "zap redactor ran"
if [ -n "$z" ]; then
  absent  "ZAP Authorization bearer token removed" "$z" "PLANTED_ZAP_TOKEN_abc123"
  absent  "ZAP Cookie value removed"               "$z" "PLANTED_ZAP_COOKIE_def456"
  absent  "ZAP CSRF token removed"                 "$z" "PLANTED_ZAP_CSRF_ghi789"
  absent  "ZAP request-body password removed"      "$z" "PLANTED_ZAP_BODYPW_jkl012"
  absent  "ZAP Set-Cookie value removed"           "$z" "PLANTED_ZAP_SETCOOKIE_mno345"
  absent  "ZAP evidence field removed"             "$z" "PLANTED_ZAP_EVIDENCE_pqr678"
  absent  "ZAP otherinfo field removed"            "$z" "PLANTED_ZAP_OTHERINFO_stu901"
  present "ZAP endpoint path preserved"            "$z" "/rest/products/search"
  present "ZAP host:port preserved"                "$z" "127.0.0.1:13000"
  present "ZAP param name preserved"               "$z" "<param>q</param>"
fi

sect "Nuclei JSONL — extracted-results/auth/curl-command/meta redacted, matched-at preserved"
n="$(run nuclei nuclei-planted-secret.jsonl)" || bad "nuclei redactor ran"
if [ -n "$n" ]; then
  absent  "Nuclei extracted API key removed"   "$n" "PLANTED_NUCLEI_APIKEY_xyz789"
  absent  "Nuclei request auth token removed"  "$n" "PLANTED_NUCLEI_AUTH_pqr456"
  absent  "Nuclei git token removed"           "$n" "PLANTED_NUCLEI_GITTOKEN_stu012"
  absent  "Nuclei curl-command token removed"  "$n" "PLANTED_NUCLEI_CURL_abc111"
  absent  "Nuclei meta value removed"          "$n" "PLANTED_NUCLEI_META_def222"
  present "Nuclei matched-at /api/keys kept"    "$n" "/api/keys"
  present "Nuclei matched-at /.git/config kept" "$n" "/.git/config"
  present "Nuclei host kept"                    "$n" "127.0.0.1:13000"
fi

sect "Semgrep JSON — code/message/fix/dataflow dropped, file:line pointer preserved"
s="$(run semgrep semgrep-planted-secret.json)" || bad "semgrep redactor ran"
if [ -n "$s" ]; then
  absent  "Semgrep extra.lines secret removed"  "$s" "PLANTED_SEMGREP_SECRET_key123"
  absent  "Semgrep extra.message secret removed" "$s" "PLANTED_SEMGREP_MSG_key123"
  absent  "Semgrep extra.fix secret removed"    "$s" "PLANTED_SEMGREP_FIX_key123"
  absent  "Semgrep dataflow_trace secret removed" "$s" "PLANTED_SEMGREP_TAINT_key123"
  present "Semgrep file path preserved"  "$s" "src/main/java/org/owasp/benchmark/LoginController.java"
  present "Semgrep line number preserved" "$s" "42"
fi

sect "Trivy JSON — secret match AND misconfig code redacted, target/component preserved"
t="$(run trivy trivy-planted-secret.json)" || bad "trivy redactor ran"
if [ -n "$t" ]; then
  absent  "Trivy secret match removed"       "$t" "PLANTED_TRIVY_SECRET_tok456"
  absent  "Trivy misconfig code removed"     "$t" "PLANTED_TRIVY_MISCONF_cfg789"
  present "Trivy target preserved"           "$t" "package-lock.json"
  present "Trivy rule id preserved"          "$t" "generic-api-key"
  present "Trivy misconfig id preserved"     "$t" "DS002"
fi

printf '\n== summary ==\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
