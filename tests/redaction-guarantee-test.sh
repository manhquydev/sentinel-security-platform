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
  # Keep the real extension: the DefectDojo ZAP parser rejects any filename not
  # ending in .xml, so a generic ".out" would fail the round-trip for a reason
  # that has nothing to do with redaction.
  local ext; case "$1" in zap) ext=xml ;; nuclei) ext=jsonl ;; *) ext=json ;; esac
  local out="$WORK/$1.san.$ext"
  "$REDACT" "$1" "$FIX/$2" "$out" >/dev/null 2>&1 || { echo ""; return 1; }
  echo "$out"
}

# --- parser round-trip -------------------------------------------------------
# Grep assertions cannot see a report that redacts perfectly and imports never.
# A whitelist that drops a field the DefectDojo parser dereferences produces
# exactly that: every planted secret gone, and an AttributeError on import.
# These assertions feed the sanitized report to the REAL parser instead.
DD_C="${DD_CONTAINER:-dd-uwsgi}"
dd_up() { [ "$(docker inspect -f '{{.State.Running}}' "$DD_C" 2>/dev/null)" = "true" ]; }

probe() { # <file> <dd_scan_type> -> "<count>|<severity>|<cwe>|<component>" or "ERR:..."
  local f="$1" st="$2" b="probe-$$-$(basename "$1")"
  docker cp "$f" "$DD_C:/tmp/$b" >/dev/null 2>&1 || { echo "ERR:docker cp failed"; return; }
  docker exec "$DD_C" python -c '
import os, sys, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dojo.settings.settings")
django.setup()
from dojo.tools.factory import get_parser
try:
    parser = get_parser(sys.argv[1])
    with open(sys.argv[2], "rb") as fh:
        fs = parser.get_findings(fh, None)
except Exception as exc:
    print("RESULT ERR:%s: %s" % (type(exc).__name__, exc)); raise SystemExit(0)
f0 = fs[0] if fs else None
print("RESULT %d|%s|%s|%s" % (len(fs), getattr(f0, "severity", None),
                              getattr(f0, "cwe", None), getattr(f0, "component_name", None)))
' "$st" "/tmp/$b" 2>/dev/null | sed -n 's/^RESULT //p'
  # -u root: docker cp lands root-owned files and uwsgi runs unprivileged, so a
  # plain exec rm fails silently and leaves probe files behind every run.
  docker exec -u root "$DD_C" rm -f "/tmp/$b" >/dev/null 2>&1 || true
}

# assert the sanitized report survives the real parser with usable findings
parses() { # <label> <file> <dd_scan_type>
  local r; r="$(probe "$2" "$3")"
  case "$r" in
    ERR:*) bad "$1 ($r)"; return ;;
    "")    bad "$1 (parser probe returned nothing)"; return ;;
  esac
  local n="${r%%|*}" sev; sev="$(printf '%s' "$r" | cut -d'|' -f2)"
  if [ "${n:-0}" -gt 0 ] 2>/dev/null && [ "$sev" != "None" ]; then
    ok "$1 ($n findings, severity=$sev)"
  else
    bad "$1 (parsed $n findings, severity=$sev)"
  fi
}

# assert the fields DefectDojo's dedup hashes on survived redaction
dedup_field() { # <label> <file> <dd_scan_type> <cwe|component>
  local r; r="$(probe "$2" "$3")"
  case "$r" in ERR:*|"") bad "$1 ($r)"; return ;; esac
  local cwe comp
  cwe="$(printf '%s' "$r" | cut -d'|' -f3)"; comp="$(printf '%s' "$r" | cut -d'|' -f4)"
  case "$4" in
    cwe)       [ "$cwe"  != "0" ] && [ "$cwe" != "None" ] && ok "$1 (cwe=$cwe)"   || bad "$1 (cwe=$cwe — dedup input lost)" ;;
    component) [ "$comp" != "None" ] && [ -n "$comp" ]    && ok "$1 (component=$comp)" || bad "$1 (component_name=None — dedup input lost)" ;;
  esac
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
  absent  "ZAP root-element attribute removed"     "$z" "PLANTED_ZAP_ROOTATTR_vw1234"
  absent  "ZAP element outside alertitem removed"  "$z" "PLANTED_ZAP_OUTSIDE_xy5678"
  absent  "ZAP instance attribute removed"         "$z" "PLANTED_ZAP_INSTATTR_za9012"
  absent  "ZAP uri query-string credential removed" "$z" "PLANTED_ZAP_URIQUERY_bc3456"
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

sect "Semgrep run-semgrep.sh — finding identity independent of run mode"
# DefectDojo hashes Semgrep findings on file_path + line + vuln_id_from_tool
# (path/check_id here). Semgrep computes both from where the config/target
# happen to sit on disk, so a docker mount ("/rules","/src") and a local
# checkout ("scanners/rulesets","<host tree>") produce two different
# identities for the same source — a later run-mode switch would silently
# auto-mitigate every existing finding as "remediated" and recreate it.
# run-semgrep.sh neutralises this (cwd pinned to the ruleset's own directory,
# config referenced by basename, path stripped of its target-argument
# prefix). No docker image is available to exercise the docker branch
# directly, so "mode B" below issues the *same command shape* the docker
# branch issues (cwd == mounted ruleset dir, config by basename, absolute
# target) against a differently-named directory pair, run outside the
# wrapper with the local binary — proving the identity-producing mechanism
# itself, not just one invocation of it, is mount-name-independent.
RUN_SEMGREP="$REPO_ROOT/scanners/run-semgrep.sh"
RULESET="$REPO_ROOT/scanners/rulesets/owasp-local.yml"
SEMGREP_BIN_FOR_TEST="${SEMGREP_BIN:-$(command -v semgrep 2>/dev/null || true)}"
if [ -z "$SEMGREP_BIN_FOR_TEST" ]; then
  if [ "${REQUIRE_SEMGREP:-0}" = "1" ]; then
    bad "semgrep identity check required (REQUIRE_SEMGREP=1) but no semgrep binary found"
  else
    printf '  \033[33mSKIP\033[0m semgrep identity check: no local semgrep binary (set SEMGREP_BIN or REQUIRE_SEMGREP=1)\n'
  fi
else
  IDW="$WORK/semgrep-identity"
  mkdir -p "$IDW/mode-a-src" "$IDW/mode-b-src"
  cat >"$IDW/mode-a-src/Foo.java" <<'JAVA'
package demo;
public class Foo { public Foo() { new java.util.Random(); } }
JAVA
  cp "$IDW/mode-a-src/Foo.java" "$IDW/mode-b-src/Foo.java"

  # Mode A: the wrapper's real local-binary branch.
  a_raw="$IDW/mode-a-raw.json"
  SEMGREP_BIN="$SEMGREP_BIN_FOR_TEST" TARGET_SRC="$IDW/mode-a-src" SEMGREP_RULESET="$RULESET" \
    "$RUN_SEMGREP" "$a_raw" >/dev/null 2>&1
  a_check_id="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["results"][0]["check_id"] if d["results"] else "")' "$a_raw" 2>/dev/null)"
  a_path="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["results"][0]["path"] if d["results"] else "")' "$a_raw" 2>/dev/null)"

  if [ -z "$a_check_id" ] || [ -z "$a_path" ]; then
    bad "wrapper local-binary run produced a finding to compare"
  else
    [ "$a_check_id" = "java-insecure-random" ] && ok "local-binary check_id is bare (java-insecure-random)" \
      || bad "local-binary check_id carries a prefix ($a_check_id)"
    case "$a_path" in
      /*) bad "local-binary path is host-absolute, leaks the scan host ($a_path)" ;;
      *)  ok "local-binary path is target-relative, no host path leaked ($a_path)" ;;
    esac

    # Mode B: the docker branch's command shape (cwd == mounted ruleset dir,
    # config by basename, absolute target), against a directory pair with
    # different basenames than mode A's — same mechanism, different names.
    b_raw="$IDW/mode-b-raw.json"
    ( cd "$(dirname "$RULESET")" && "$SEMGREP_BIN_FOR_TEST" scan --json --error --disable-version-check --metrics=off \
        --config "$(basename "$RULESET")" "$IDW/mode-b-src" ) >"$b_raw" 2>/dev/null
    b_check_id="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["results"][0]["check_id"] if d["results"] else "")' "$b_raw" 2>/dev/null)"
    b_path_suffix="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["results"][0]["path"] if d["results"] else "")' "$b_raw" 2>/dev/null | sed 's#.*/mode-b-src/##')"

    [ "$b_check_id" = "$a_check_id" ] && ok "check_id matches across mount-name-independent invocations ($b_check_id)" \
      || bad "check_id diverges by invocation geometry (mode A=$a_check_id mode B=$b_check_id)"
    [ "$b_path_suffix" = "$a_path" ] && ok "target-relative path matches across invocations ($a_path)" \
      || bad "target-relative path diverges (mode A=$a_path mode B=$b_path_suffix)"
  fi
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

sect "Parser round-trip — sanitized reports must still import into DefectDojo"
if dd_up; then
  [ -n "$z" ] && parses "ZAP sanitized report parses"     "$z" "ZAP Scan"
  [ -n "$n" ] && parses "Nuclei sanitized report parses"  "$n" "Nuclei Scan"
  [ -n "$s" ] && parses "Semgrep sanitized report parses" "$s" "Semgrep JSON Report"
  [ -n "$t" ] && parses "Trivy sanitized report parses"   "$t" "Trivy Scan"

  sect "Dedup inputs — fields the hash_code is computed from must survive redaction"
  [ -n "$n" ] && dedup_field "Nuclei cwe survives (info.classification)" "$n" "Nuclei Scan" cwe
  [ -n "$n" ] && dedup_field "Nuclei component survives (matcher-name)"  "$n" "Nuclei Scan" component
elif [ "${REQUIRE_DD:-0}" = "1" ]; then
  bad "parser round-trip required (REQUIRE_DD=1) but container $DD_C is not running"
else
  printf '  \033[33mSKIP\033[0m parser round-trip: container %s not running\n' "$DD_C"
  printf '  (these are the only assertions that can catch a parser-breaking whitelist —\n'
  printf '   set REQUIRE_DD=1 so a skip fails instead of passing silently)\n'
fi

printf '\n== summary ==\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
