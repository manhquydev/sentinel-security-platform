#!/usr/bin/env bash
# verify-lake.sh must catch a lake that has drifted from its baseline, across
# any number of Products (docs/decisions/0007: a Product is exactly one
# application, so the baseline is now a products[] list).
#
# Most cases drift the BASELINE rather than the live lake: a baseline claiming
# the wrong count, naming a scan_type that is not in the engagement, or naming
# a Product that does not exist, must all make verify-lake fail. A
# verification script that cannot fail proves nothing. Most cases here run
# directly against the live lake — verify-lake.sh never writes, so nothing
# here needs SKIP_REIMPORT to stay safe, but the variable is honoured (as a
# no-op) for callers that set it out of habit from other suites in this repo.
#
# Three scenarios cannot be built from the live lake without a write this
# suite is not allowed to make (a stray sibling engagement, a finding whose
# file_path points into a scoring corpus, a transport/parse failure on one
# Product while another succeeds) and instead run verify-lake.sh against a
# minimal fixture DefectDojo (see start_mock/run_mock below).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFY="$REPO_ROOT/scripts/verify-lake.sh"
WORK="$(mktemp -d)"
MOCK_PID=""
trap 'rm -rf "$WORK"; [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null; true' EXIT

PASS=0; FAIL=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
sect(){ printf '\n== %s ==\n' "$1"; }

# verify-lake is read-only, so every live case runs it directly against the live lake.
run() { BASELINE="$1" "$VERIFY" >/dev/null 2>&1; }

# The two REAL, live Products with their correct baseline data. Every
# scenario below that targets a per-Product mechanism (a source omission, a
# drifted count, an absent scan_type, an absent Product name) splices these in
# unchanged, so the lake-coverage check (hole 1: every live Product must be
# named in the baseline) stays quiet and the scenario isolates exactly the
# mechanism it names instead of also tripping on an unrelated, unlisted
# Product.
juice_entry()   { printf '{"product":"juice-shop-harness","engagement":"week1-baseline","expected":{"Trivy Scan":%s,"Nuclei Scan":%s}}' "${1:-4}" "${2:-21}"; }
webgoat_entry() { printf '{"product":"webgoat","engagement":"week1-baseline","expected":{"Semgrep JSON Report":%s}}' "${1:-11}"; }
write_baseline() { printf '{"products": [%s]}' "$2" > "$1"; } # <file> <comma-joined product entries>
join_products() { local IFS=,; echo "$*"; } # each arg is one product-entry JSON object

sect "the committed baseline reports today's real migration debt as drift"
# infra/defectdojo/lake-baseline.json describes the POST-split target: the
# juice-shop-harness Product carries Trivy and Nuclei only. The live lake has
# not been migrated yet — the 221-finding OWASP Benchmark Semgrep test is
# still sitting in this Product's engagement (docs/decisions/0007) — so
# verify-lake must currently reject the live lake, precisely on that stale
# test. This is real evidence, not a synthetic fixture: it is exactly the
# "first timer firing fails the drift check" state the migration plan exists
# to resolve.
if BASELINE="$REPO_ROOT/infra/defectdojo/lake-baseline.json" "$VERIFY" >/dev/null 2>&1; then
  ok "the committed baseline matches the live lake"
else
  bad "the committed baseline no longer matches the live lake"
fi

sect "a baseline that omits a real source fails (the engagement has an extra type)"
write_baseline "$WORK/partial.json" "$(join_products '{"product":"juice-shop-harness","engagement":"week1-baseline","expected":{"Trivy Scan":4}}' "$(webgoat_entry)")"
run "$WORK/partial.json" && bad "accepted a baseline missing Nuclei Scan while the lake has it" \
  || ok "rejected a baseline that omits a source present in the lake"

sect "a drifted baseline count fails"
write_baseline "$WORK/high.json" "$(join_products "$(juice_entry 5 21)" "$(webgoat_entry)")"
run "$WORK/high.json" && bad "accepted Trivy=5 against a lake of 4" || ok "rejected an inflated count"
write_baseline "$WORK/low.json" "$(join_products "$(juice_entry 4 20)" "$(webgoat_entry)")"
run "$WORK/low.json" && bad "accepted Nuclei=20 against a lake of 21" || ok "rejected a deflated count"

sect "a baseline naming an absent scan_type fails"
write_baseline "$WORK/ghost.json" "$(join_products '{"product":"juice-shop-harness","engagement":"week1-baseline","expected":{"Nonexistent Scan":1}}' "$(webgoat_entry)")"
run "$WORK/ghost.json" && bad "accepted a scan_type not in the engagement" || ok "rejected an unknown scan_type"

sect "a baseline naming an absent Product fails"
# Observed failing first without the guard: DefectDojo's engagements endpoint
# ignores an EMPTY product= filter rather than matching zero rows — verified
# live, `GET /api/v2/engagements/?product=&name=week1-baseline` returned the
# real engagement (id=1) that belongs to juice-shop-harness. A verifier that
# skips the explicit product-existence check and passes an empty id straight
# into that filter would silently validate against the WRONG Product's
# engagement instead of rejecting the baseline. verify-lake.sh looks the
# Product up by name first and fails closed when that lookup is empty, before
# ever querying engagements. Both real Products are also listed correctly so
# this isolates the "named Product does not exist" mechanism from the
# lake-coverage check (hole 1), which is about the opposite direction: a live
# Product the baseline never mentions at all.
write_baseline "$WORK/ghost-product.json" \
  "$(join_products "$(juice_entry)" "$(webgoat_entry)" '{"product":"sentinel-nonexistent-product","engagement":"week1-baseline","expected":{"Trivy Scan":4}}')"
run "$WORK/ghost-product.json" && bad "accepted a Product that does not exist" || ok "rejected an absent Product"

sect "a multi-Product baseline reports each Product independently"
# One entry names a real Product with a real, verifiable count; another names
# an absent Product. Both must be checked and reported — a Product lookup
# failure must not abort the rest of the baseline.
write_baseline "$WORK/mixed.json" \
  "$(join_products "$(juice_entry)" "$(webgoat_entry)" '{"product":"sentinel-nonexistent-product","engagement":"week1-baseline","expected":{"Trivy Scan":4}}')"
mixed_out="$(BASELINE="$WORK/mixed.json" "$VERIFY" 2>&1)"
if BASELINE="$WORK/mixed.json" "$VERIFY" >/dev/null 2>&1; then
  bad "accepted a baseline containing an absent Product"
elif printf '%s' "$mixed_out" | grep -q "Trivy Scan: 4 active (baseline 4)" \
  && printf '%s' "$mixed_out" | grep -q "product 'sentinel-nonexistent-product' not found"; then
  ok "checked the real Products and reported the absent one, in the same run"
else
  bad "did not check both Products independently:"$'\n'"$mixed_out"
fi

sect "an unreadable baseline fails closed"
BASELINE="$WORK/does-not-exist.json" "$VERIFY" >/dev/null 2>&1 \
  && bad "accepted a missing baseline file" || ok "missing baseline file rejected"

sect "hole 1 — a baseline that omits a real, live Product fails"
# The verifier used to enumerate only baseline.products[]; a whole second
# Product could sit in DefectDojo, unmentioned, and it would never be looked
# at. This baseline is real evidence of the fix, not a synthetic fixture: it
# names the real juice-shop-harness Product correctly and simply never
# mentions webgoat, which really exists in the live lake right now.
write_baseline "$WORK/omits-webgoat.json" "$(juice_entry)"
omit_out="$(BASELINE="$WORK/omits-webgoat.json" "$VERIFY" 2>&1)"
if BASELINE="$WORK/omits-webgoat.json" "$VERIFY" >/dev/null 2>&1; then
  bad "accepted a baseline that never mentions the live webgoat Product"
elif printf '%s' "$omit_out" | grep -q "undeclared Product(s) exist in DefectDojo: webgoat"; then
  ok "rejected a baseline that omits a real, live Product"
else
  bad "failed for the wrong reason:"$'\n'"$omit_out"
fi

sect "hole 3 — freshness is fatal by default, not only when an operator opts in"
# MAX_IMPORT_AGE_SECONDS used to be undocumented-nowhere-set, so the freshness
# branch never fired and those lines were PASS by construction. It now
# defaults to 129600s (36h — see verify-lake.sh for the cadence math) and
# applies unconditionally. Observed red first: an absurdly small override
# must fail every freshness line against the real, hours-old imports; the
# baked-in default must then pass those same real imports without any
# override at all.
tiny_out="$(MAX_IMPORT_AGE_SECONDS=1 BASELINE="$REPO_ROOT/infra/defectdojo/lake-baseline.json" "$VERIFY" 2>&1)"
tiny_fails="$(printf '%s' "$tiny_out" | grep -c 'exceeds MAX_IMPORT_AGE_SECONDS=1$')"
[ "$tiny_fails" -ge 3 ] \
  && ok "MAX_IMPORT_AGE_SECONDS=1 fails all 3 freshness lines against real (hours-old) imports" \
  || bad "MAX_IMPORT_AGE_SECONDS=1 did not fail the freshness lines it should have:"$'\n'"$tiny_out"
default_out="$(BASELINE="$REPO_ROOT/infra/defectdojo/lake-baseline.json" "$VERIFY" 2>&1)"
default_fresh="$(printf '%s' "$default_out" | grep -c 'PASS.*last import')"
[ "$default_fresh" -ge 3 ] \
  && ok "the baked-in default (36h) still passes the real, fresh imports" \
  || bad "the default MAX_IMPORT_AGE_SECONDS rejected real, fresh imports:"$'\n'"$default_out"

# ---------------------------------------------------------------------------
# Minimal fixture DefectDojo for the three scenarios above that a healthy,
# single-writer live lake cannot produce without a write this suite may not
# make. verify-lake.sh is pointed at it via DD_URL like any other HTTP API;
# it cannot tell it apart from the real thing.
# ---------------------------------------------------------------------------
MOCK_SERVER_PY="$WORK/mock_dd_server.py"
cat >"$MOCK_SERVER_PY" <<'PY'
import http.server, json, socketserver, sys

fixture = json.load(open(sys.argv[1]))
port = int(sys.argv[2])


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        route = fixture.get(self.path)
        if route is None:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"detail":"no fixture route for this request"}')
            return
        status, body = route.get("status", 200), route.get("body", {})
        payload = body if isinstance(body, str) else json.dumps(body)
        data = payload.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", port), Handler) as httpd:
    httpd.serve_forever()
PY

free_port() {
  python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}

now_iso() { python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat())'; }

# <fixture-json-file> -> prints "<port> <pid>" on success.
start_mock() {
  local fixture="$1" port pid i
  port="$(free_port)"
  python3 "$MOCK_SERVER_PY" "$fixture" "$port" >/dev/null 2>&1 &
  pid=$!
  for i in $(seq 1 50); do
    curl -sS -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null && break
    kill -0 "$pid" 2>/dev/null || { echo "mock server exited before it came up" >&2; return 1; }
    sleep 0.1
  done
  echo "$port $pid"
}

# <fixture-json-file> <baseline-file> -> prints verify-lake's combined
# output; exit status is verify-lake's own. DD_API_TOKEN is set to a dummy
# value so verify-lake never reads infra/.env or exchanges a password for
# these fixture runs.
run_mock() {
  local fixture="$1" baseline="$2" port pid out rc
  read -r port pid < <(start_mock "$fixture") || { echo "mock server failed to start"; return 2; }
  MOCK_PID="$pid"
  out="$(DD_URL="http://127.0.0.1:$port" DD_API_TOKEN="mock-token" BASELINE="$baseline" "$VERIFY" 2>&1)"
  rc=$?
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  MOCK_PID=""
  printf '%s' "$out"
  return "$rc"
}

sect "hole 2 — an undeclared sibling engagement inside an authorized Product fails"
# scanners/import-report.sh sends auto_create_context=true, so a typo'd
# ENGAGEMENT_NAME silently creates a sibling engagement inside an otherwise
# authorized Product; nothing checked its findings. Fixture: one Product with
# TWO engagements — the baseline's "week1-baseline" and an unrelated
# "week1-baseline-typo" that stands in for that auto-created sibling.
NOW="$(now_iso)"
python3 - "$WORK/hole2-fixture.json" "$NOW" <<'PY'
import json, sys
path, now = sys.argv[1], sys.argv[2]
fixture = {
    "/api/v2/products/?limit=1000": {"body": {"count": 1, "results": [{"id": 900, "name": "mock-product-a"}]}},
    "/api/v2/findings/?active=true&limit=1000": {"body": {"count": 1, "results": [{"file_path": "/mock/lib/safe.ts"}]}},
    "/api/v2/products/?name=mock-product-a": {"body": {"count": 1, "results": [{"id": 900, "name": "mock-product-a"}]}},
    "/api/v2/engagements/?product=900&limit=1000": {"body": {"count": 2, "results": [
        {"id": 700, "name": "week1-baseline"},
        {"id": 701, "name": "week1-baseline-typo"},
    ]}},
    "/api/v2/tests/?engagement=700&limit=1000": {"body": {"count": 1, "results": [{"id": 500, "scan_type": "Trivy Scan"}]}},
    "/api/v2/findings/?test=500&active=true&duplicate=false&limit=1": {"body": {"count": 4}},
    "/api/v2/test_imports/?test=500&limit=1": {"body": {"count": 1, "results": [{"created": now}]}},
}
json.dump(fixture, open(path, "w"))
PY
write_baseline "$WORK/hole2-baseline.json" '{"product":"mock-product-a","engagement":"week1-baseline","expected":{"Trivy Scan":4}}'
hole2_out="$(run_mock "$WORK/hole2-fixture.json" "$WORK/hole2-baseline.json")"
hole2_rc=$?
if [ "$hole2_rc" -eq 0 ]; then
  bad "accepted a Product with an undeclared sibling engagement"
elif printf '%s' "$hole2_out" | grep -q "extra engagement(s) in product 'mock-product-a': week1-baseline-typo"; then
  ok "caught the undeclared sibling engagement inside the authorized Product"
else
  bad "failed for the wrong reason:"$'\n'"$hole2_out"
fi

sect "corpus invariant — now checked in verify-lake.sh itself, not only in this test suite"
# docs/decisions/0007: no active finding may point into a scoring corpus. This
# property used to be proven only by a docker-exec ORM query in this test
# file — not by scripts/verify-lake.sh, the thing the scheduler actually
# runs. verify-lake.sh now checks it over the same read-only HTTP API as
# everything else. Fixture: one active finding whose file_path points into
# OWASP Benchmark.
python3 - "$WORK/corpus-fixture.json" "$NOW" <<'PY'
import json, sys
path, now = sys.argv[1], sys.argv[2]
fixture = {
    "/api/v2/products/?limit=1000": {"body": {"count": 1, "results": [{"id": 910, "name": "mock-product-b"}]}},
    "/api/v2/findings/?active=true&limit=1000": {"body": {"count": 1, "results": [
        {"file_path": "/repo/benchmark/targets/owasp-benchmark/src/BenchmarkTest00023.java"},
    ]}},
    "/api/v2/products/?name=mock-product-b": {"body": {"count": 1, "results": [{"id": 910, "name": "mock-product-b"}]}},
    "/api/v2/engagements/?product=910&limit=1000": {"body": {"count": 1, "results": [{"id": 710, "name": "week1-baseline"}]}},
    "/api/v2/tests/?engagement=710&limit=1000": {"body": {"count": 1, "results": [{"id": 510, "scan_type": "Trivy Scan"}]}},
    "/api/v2/findings/?test=510&active=true&duplicate=false&limit=1": {"body": {"count": 1}},
    "/api/v2/test_imports/?test=510&limit=1": {"body": {"count": 1, "results": [{"created": now}]}},
}
json.dump(fixture, open(path, "w"))
PY
write_baseline "$WORK/corpus-baseline.json" '{"product":"mock-product-b","engagement":"week1-baseline","expected":{"Trivy Scan":1}}'
corpus_out="$(run_mock "$WORK/corpus-fixture.json" "$WORK/corpus-baseline.json")"
corpus_rc=$?
if [ "$corpus_rc" -eq 0 ]; then
  bad "accepted a lake with an active finding inside the OWASP Benchmark corpus"
elif printf '%s' "$corpus_out" | grep -q "1 active finding(s) point into a scoring corpus"; then
  ok "caught the corpus-tainted finding via verify-lake.sh's own API check"
else
  bad "failed for the wrong reason:"$'\n'"$corpus_out"
fi

sect "a transport/parse failure on one Product does not abort the rest of the run"
# Observed failing first without the guard: this exact fixture, run against
# the pre-fix script, terminated on an uncaught JSONDecodeError from the
# broken Product's lookup and never reached the healthy one. verify-lake.sh
# must now report the broken Product cleanly (no raw traceback) and still
# check the healthy one in the same run.
python3 - "$WORK/transport-fixture.json" "$NOW" <<'PY'
import json, sys
path, now = sys.argv[1], sys.argv[2]
fixture = {
    "/api/v2/products/?limit=1000": {"body": {"count": 2, "results": [
        {"id": 920, "name": "mock-product-ok"}, {"id": 921, "name": "mock-product-broken"},
    ]}},
    "/api/v2/findings/?active=true&limit=1000": {"body": {"count": 0, "results": []}},
    "/api/v2/products/?name=mock-product-ok": {"body": {"count": 1, "results": [{"id": 920, "name": "mock-product-ok"}]}},
    "/api/v2/engagements/?product=920&limit=1000": {"body": {"count": 1, "results": [{"id": 720, "name": "week1-baseline"}]}},
    "/api/v2/tests/?engagement=720&limit=1000": {"body": {"count": 1, "results": [{"id": 520, "scan_type": "Trivy Scan"}]}},
    "/api/v2/findings/?test=520&active=true&duplicate=false&limit=1": {"body": {"count": 2}},
    "/api/v2/test_imports/?test=520&limit=1": {"body": {"count": 1, "results": [{"created": now}]}},
    # Simulates the crash a review reproduced: a 500 with a non-JSON body.
    "/api/v2/products/?name=mock-product-broken": {"status": 500, "body": "Internal Server Error"},
}
json.dump(fixture, open(path, "w"))
PY
write_baseline "$WORK/transport-baseline.json" \
  "$(join_products '{"product":"mock-product-ok","engagement":"week1-baseline","expected":{"Trivy Scan":2}}' '{"product":"mock-product-broken","engagement":"week1-baseline","expected":{"Trivy Scan":2}}')"
transport_out="$(run_mock "$WORK/transport-fixture.json" "$WORK/transport-baseline.json")"
transport_rc=$?
if [ "$transport_rc" -eq 0 ]; then
  bad "accepted a lake where a Product could not be verified at all"
elif printf '%s' "$transport_out" | grep -qi "traceback"; then
  bad "a raw Python traceback leaked into the report instead of a clean FAIL line:"$'\n'"$transport_out"
elif printf '%s' "$transport_out" | grep -q "product 'mock-product-broken': could not read the Product list from DefectDojo" \
  && printf '%s' "$transport_out" | grep -q "Trivy Scan: 2 active (baseline 2)"; then
  ok "reported the broken Product cleanly and still checked the healthy one in the same run"
else
  bad "did not degrade cleanly:"$'\n'"$transport_out"
fi

printf '\n== summary ==\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
