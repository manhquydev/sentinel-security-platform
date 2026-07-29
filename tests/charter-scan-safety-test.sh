#!/usr/bin/env bash
# Offline contract for the literal charter scanner/import boundary.  This test
# never invokes Nuclei, Docker, curl, or DefectDojo.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AL="$REPO_ROOT/scanners/target-allowlist.sh"
REDACT="$REPO_ROOT/scanners/redact-report.sh"
CORE="$REPO_ROOT/scripts/scan-and-import.sh"
MANIFEST="$REPO_ROOT/scanners/charter-template-manifest.json"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0
ok() { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
sect() { printf '\n== %s ==\n' "$1"; }

expect_charter_reject() {
  local label="$1" value="$2"
  if "$AL" charter-validate "$value" >/dev/null 2>&1; then
    bad "$label (accepted)"
  else
    ok "$label"
  fi
}

sect "literal charter origin is a separate fail-closed policy"
if [ "$("$AL" charter-validate http://127.0.0.1:13000 2>/dev/null)" = "http://127.0.0.1:13000" ]; then
  ok "only the exact origin is accepted"
else
  bad "exact origin was rejected"
fi
for value in \
  '' \
  'https://127.0.0.1:13000' \
  'http://127.0.0.1' \
  'http://127.0.0.1:13001' \
  'http://127.0.0.1:13000/' \
  'http://127.0.0.1:13000/a' \
  'http://user@127.0.0.1:13000' \
  'http://127.0.0.1:13000?x=1' \
  'http://[::1]:13000' \
  'http://localhost:13000' \
  'http://8.8.8.8:13000'; do
  expect_charter_reject "rejects '$value' before readiness/scanner I/O" "$value"
done

mkdir "$WORK/bin"
cat >"$WORK/bin/curl" <<'EOF'
#!/usr/bin/env sh
printf '%s' "${FAKE_CURL_CODE:-200}"
EOF
chmod 700 "$WORK/bin/curl"
if PATH="$WORK/bin:$PATH" FAKE_CURL_CODE=302 TARGET_READY_TIMEOUT=1 \
    "$AL" charter-ready http://127.0.0.1:13000 >/dev/null 2>&1; then
  bad "redirect response was treated as charter readiness"
else
  ok "a redirect fails charter readiness without following it"
fi

sect "committed template set is complete, reviewed, http-only, and hash-bound"
if python3 - "$MANIFEST" "$REPO_ROOT/scanners" <<'PY'
import hashlib, json, pathlib, sys
manifest, root = map(pathlib.Path, sys.argv[1:])
doc = json.loads(manifest.read_text())
rows = doc.get("templates")
assert doc.get("version") == 1 and isinstance(rows, list) and rows
listed = set()
for row in rows:
    path = row.get("path")
    assert isinstance(path, str) and path.startswith("charter-templates/")
    assert row.get("review_status") == "approved"
    assert row.get("protocol") == "http"
    file = root / path
    assert file.is_file()
    assert hashlib.sha256(file.read_bytes()).hexdigest() == row.get("sha256")
    text = file.read_text(encoding="utf-8")
    assert "http:" in text and "dns:" not in text and "oast" not in text.lower()
    listed.add(file.resolve())
actual = {p.resolve() for p in (root / "charter-templates").rglob("*") if p.is_file()}
assert listed == actual
PY
then ok "manifest binds exactly the approved local HTTP templates"; else bad "manifest/template integrity contract failed"; fi

if grep -q -- 'redirect_egress_flags=(-dr -ni)' "$REPO_ROOT/scanners/run-nuclei.sh" \
  && grep -q -- 'redirect_egress_flags+=(-no-interactsh)' "$REPO_ROOT/scanners/run-nuclei.sh" \
  && grep -q -- 'charter-template-manifest.json' "$REPO_ROOT/scanners/run-nuclei.sh" \
  && ! grep -q 'hostile-template network isolation' "$REPO_ROOT/scanners/run-nuclei.sh"; then
  ok "charter wrapper retains redirect/OAST flags without claiming hostile-template isolation"
else
  bad "charter wrapper flags or scope statement missing"
fi

cat >"$WORK/bin/nuclei" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' "$@" >"$NUCLEI_ARGS_FILE"
EOF
chmod 700 "$WORK/bin/nuclei"
mkdir -m 700 "$WORK/redirect-run"
if PATH="$WORK/bin:$PATH" FAKE_CURL_CODE=302 NUCLEI_BIN="$WORK/bin/nuclei" \
    NUCLEI_ARGS_FILE="$WORK/redirect.args" SENTINEL_PROFILE=charter \
    CHARTER_RUN_ROOT="$WORK/redirect-run" TARGET_URL=http://127.0.0.1:13000 \
    "$REPO_ROOT/scanners/run-nuclei.sh" "$WORK/redirect-run/raw" >/dev/null 2>&1; then
  bad "redirecting charter target invoked Nuclei"
elif [ -e "$WORK/redirect.args" ]; then
  bad "redirecting charter target reached Nuclei before rejection"
else
  ok "redirecting charter target is rejected before Nuclei invocation"
fi
mkdir -m 700 "$WORK/nuclei-run"
raw="$WORK/nuclei-run/raw"
if PATH="$WORK/bin:$PATH" FAKE_CURL_CODE=200 NUCLEI_BIN="$WORK/bin/nuclei" \
    NUCLEI_ARGS_FILE="$WORK/nuclei.args" SENTINEL_PROFILE=charter \
    CHARTER_RUN_ROOT="$WORK/nuclei-run" TARGET_URL=http://127.0.0.1:13000 \
    "$REPO_ROOT/scanners/run-nuclei.sh" "$raw" >/dev/null 2>&1 \
  && python3 - "$WORK/nuclei.args" "$MANIFEST" <<'PY'
import json, pathlib, sys
args = pathlib.Path(sys.argv[1]).read_text().splitlines()
manifest = json.loads(pathlib.Path(sys.argv[2]).read_text())
expected = [str(pathlib.Path(sys.argv[2]).parent / row["path"]) for row in manifest["templates"]]
selected = [args[i + 1] for i, arg in enumerate(args[:-1]) if arg == "-t"]
assert selected == expected
for flag in ("-disable-update-check", "-dr", "-ni", "-no-interactsh"):
    assert flag in args
PY
then ok "wrapper selects only manifest-verified local templates with DNS/OAST protections"; else bad "wrapper selected an unverified/bundled template or omitted a required flag"; fi
if [ "$(stat -c %a "$WORK/nuclei-run")" = 700 ] && [ "$(stat -c %a "$raw")" = 600 ]; then
  ok "charter raw output stays in a 0700 run root at mode 0600"
else
  bad "charter raw lifecycle modes are not private"
fi

sect "Nuclei URLs are rebuilt to the approved origin and path"
cat >"$WORK/raw.jsonl" <<'EOF'
{"template-id":"test","type":"http","host":"http://evil.example/?email=alice@example.test","matched-at":"http://user:token@evil.example/a%2fb?token=eyJhbGciOiJIUzI1NiJ9&pan=4532015112830366#fragment","matcher-name":"m","info":{"name":"n","severity":"low"}}
{"template-id":"test","type":"http","host":"http://evil.example/a%3Femail%3Dalice%40example.test%26token%3Dtopsecret","matched-at":"http://evil.example/a%253Femail%253Dalice%2540example.test%2526token%253Dnestedsecret","matcher-name":"m","info":{"name":"n","severity":"low"}}
{"template-id":"test","type":"http","host":"http://evil.example/a%23fragmentsecret","matched-at":"http://evil.example/a%40userinfosecret%3Apassword","matcher-name":"m","info":{"name":"n","severity":"low"}}
EOF
python3 - "$WORK/raw.jsonl" <<'PY'
import json, sys
from urllib.parse import quote
payload = "a?email=deep@example.test&token=deepsecret"
for _ in range(12):
    payload = quote(payload, safe="")
row = {"template-id":"test", "type":"http", "host":"http://evil.example/" + payload,
       "matched-at":"http://evil.example/" + payload, "matcher-name":"m",
       "info":{"name":"n", "severity":"low"}}
with open(sys.argv[1], "a") as fh:
    fh.write(json.dumps(row) + "\n")
PY
if CHARTER_ORIGIN=http://127.0.0.1:13000 "$REDACT" nuclei "$WORK/raw.jsonl" "$WORK/sanitized.jsonl" \
  && python3 - "$WORK/sanitized.jsonl" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
assert rows[0]["host"] == "http://127.0.0.1:13000/a/b"
assert rows[0]["matched-at"] == "http://127.0.0.1:13000/a/b"
assert all(row["host"].startswith("http://127.0.0.1:13000/") for row in rows)
assert all(row["matched-at"].startswith("http://127.0.0.1:13000/") for row in rows)
blob = open(sys.argv[1]).read()
for secret in ("evil.example", "alice@example.test", "token", "eyJhbGci", "4532015112830366", "fragment", "user:", "topsecret", "nestedsecret", "userinfosecret", "password", "deep@example.test", "deepsecret"):
    assert secret not in blob
PY
then ok "query, fragment, userinfo, encoded path tricks, and planted values are absent"; else bad "Nuclei charter URL canonicalization leaked or failed"; fi

sect "charter import state never permits blind reimport"
mkdir -m 700 "$WORK/run"
printf 'sanitized artifact\n' >"$WORK/run/nuclei.sanitized.jsonl"
chmod 600 "$WORK/run/nuclei.sanitized.jsonl"
digest="$(sha256sum "$WORK/run/nuclei.sanitized.jsonl" | awk '{print $1}')"
printf '{"run_id":"r1","sanitized_sha256":"%s","scanner":"nuclei","scan_type":"Nuclei Scan","request":{"close_old_findings":false}}\n' "$digest" >"$WORK/run/import-intent.json"
chmod 600 "$WORK/run/import-intent.json"
if "$CORE" charter-state "$WORK/run" >/dev/null 2>&1; then
  bad "intent without observation was treated as resumable"
else
  ok "unobserved intent stops as import-outcome-unknown"
fi
printf '{"state":"completed","sanitized_sha256":"%s","remote_test_id":"17","response_sha256":"def"}\n' "$digest" >"$WORK/run/import-observation.json"
chmod 600 "$WORK/run/import-observation.json"
if "$CORE" charter-state "$WORK/run" >/dev/null 2>&1; then
  bad "ungated observation was treated as completed"
else
  ok "ungated observation stops without a second import"
fi
printf '{"state":"completed","sanitized_sha256":"%s","remote_test_id":"17","response_sha256":"def","gate":{"state":"passed","reported":0}}\n' "$digest" >"$WORK/run/import-observation.json"
if "$CORE" charter-state "$WORK/run" >/dev/null 2>&1; then
  ok "gate-passed observation reconciles without a second import"
else
  bad "valid gate-passed observation was not reconciled"
fi

if grep -q 'CLOSE_OLD_FINDINGS=false' "$CORE" \
  && grep -q 'chmod 700' "$CORE" \
  && grep -q 'chmod 600' "$CORE" \
  && grep -q 'import-outcome-unknown' "$CORE"; then
  ok "charter controller declares private lifecycle and forced no-close"
else
  bad "charter controller lifecycle/no-close contract missing"
fi

sect "charter import serialization, failure quarantine, and gate-aware completion"
mkdir "$WORK/fake-scanners" "$WORK/charter-runs"
cat >"$WORK/fake-scanners/run-nuclei.sh" <<'EOF'
#!/usr/bin/env sh
printf '{"raw":"only-private"}\n' >"$1"
printf 'private stderr\n' >"$(dirname "$1")/.nuclei-stderr.fake"
EOF
cat >"$WORK/fake-scanners/redact-report.sh" <<'EOF'
#!/usr/bin/env sh
cp "$2" "$3"
EOF
cat >"$WORK/fake-scanners/import-report.sh" <<'EOF'
#!/usr/bin/env sh
printf 'post\n' >>"$CHARTER_POST_LOG"
[ "${CHARTER_IMPORT_SLEEP:-0}" = 0 ] || sleep "$CHARTER_IMPORT_SLEEP"
[ "${CHARTER_IMPORT_FAIL:-0}" = 0 ] || exit 1
if [ "${CHARTER_EMPTY_REPORT:-0}" = 1 ]; then
  printf '{"test":17,"deduplication_complete":true,"statistics":{"after":{"total":{"total":0}}}}\n'
  exit 0
fi
printf '{"test":17,"deduplication_complete":true,"statistics":{"after":{"total":{"total":1}}}}\n'
EOF
printf '{"version":1,"templates":[]}' >"$WORK/fake-scanners/charter-template-manifest.json"
chmod 700 "$WORK/fake-scanners/"*.sh
post_log="$WORK/posts"
: >"$post_log"

# The import command receives only a previously admitted artifact.  If that
# file changes after the durable prepared intent, it must stop before invoking
# even the test importer (which is our observable POST seam).
prepared_root="$WORK/prepared-import"; mkdir -m 700 "$prepared_root"
printf '%s\n' '{"template-id":"fixture"}' >"$prepared_root/nuclei.sanitized.jsonl"; chmod 600 "$prepared_root/nuclei.sanitized.jsonl"
prepared_digest="$(sha256sum "$prepared_root/nuclei.sanitized.jsonl" | awk '{print $1}')"
printf '{"schema_version":"sentinel-scan-admission/v1","run_id":"prepared","sanitized_path":"nuclei.sanitized.jsonl","sanitized_sha256":"%s","template_manifest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","runtime":"nuclei"}\n' "$prepared_digest" >"$prepared_root/scan-admission.json"
printf '{"state":"intent","run_id":"prepared","scanner":"nuclei","scan_type":"Nuclei Scan","test_title":"Sentinel charter nuclei","sanitized_sha256":"%s","request":{"close_old_findings":false,"deduplication_execution_mode":"async_wait"}}\n' "$prepared_digest" >"$prepared_root/import-intent.json"
chmod 600 "$prepared_root/scan-admission.json" "$prepared_root/import-intent.json"
printf '%s\n' '{"template-id":"mutated-after-intent"}' >"$prepared_root/nuclei.sanitized.jsonl"; chmod 600 "$prepared_root/nuclei.sanitized.jsonl"
: >"$post_log"
if SCANNERS_DIR="$WORK/fake-scanners" CHARTER_IMPORT_REPORT="$WORK/fake-scanners/import-report.sh" CHARTER_POST_LOG="$post_log" "$CORE" charter-import --run-root "$prepared_root" >/dev/null 2>&1; then
  bad "mutated prepared artifact reached charter import"
elif [ ! -s "$post_log" ]; then
  ok "mutated prepared artifact is refused before importer POST seam"
else
  bad "mutated prepared artifact invoked importer"
fi

mkdir "$WORK/real-charter-runs"
PATH="$WORK/bin:$PATH" FAKE_CURL_CODE=200 NUCLEI_BIN="$WORK/bin/nuclei" NUCLEI_ARGS_FILE="$WORK/real-nuclei.args" \
  CHARTER_RUNS_DIR="$WORK/real-charter-runs" CHARTER_IMPORT_REPORT="$WORK/fake-scanners/import-report.sh" \
  CHARTER_POST_LOG="$post_log" CHARTER_IMPORT_FAIL=1 TARGET_URL=http://127.0.0.1:13000 \
  "$CORE" charter --run-id real-wrapper-fail >/dev/null 2>&1; real_fail_rc=$?
real_failure_root="$(find "$WORK/real-charter-runs" -maxdepth 1 -type d -name 'real-wrapper-fail.*' -print -quit)"
if [ "$real_fail_rc" -ne 0 ] && find "$real_failure_root" -maxdepth 1 -name '.raw.*' -print -quit | grep -q . \
  && find "$real_failure_root" -maxdepth 1 -name '.nuclei-stderr.*' -print -quit | grep -q .; then
  ok "actual Nuclei wrapper retains private stderr through a later import failure"
else
  bad "actual Nuclei stderr was erased before failed charter completion"
fi
PATH="$WORK/bin:$PATH" FAKE_CURL_CODE=200 NUCLEI_BIN="$WORK/bin/nuclei" NUCLEI_ARGS_FILE="$WORK/real-nuclei-success.args" \
  CHARTER_RUNS_DIR="$WORK/real-charter-runs" CHARTER_IMPORT_REPORT="$WORK/fake-scanners/import-report.sh" \
  CHARTER_POST_LOG="$post_log" CHARTER_EMPTY_REPORT=1 TARGET_URL=http://127.0.0.1:13000 \
  "$CORE" charter --run-id real-wrapper-success >/dev/null 2>&1; real_success_rc=$?
real_success_root="$(find "$WORK/real-charter-runs" -maxdepth 1 -type d -name 'real-wrapper-success.*' -print -quit)"
if [ "$real_success_rc" -eq 0 ] && ! find "$real_success_root" -maxdepth 1 -name '.raw.*' -o -name '.nuclei-stderr.*' | grep -q .; then
  ok "actual Nuclei raw/stderr are erased after complete charter success"
else
  bad "successful charter completion retained actual Nuclei raw/stderr"
fi
: >"$post_log"
SCANNERS_DIR="$WORK/fake-scanners" CHARTER_RUNS_DIR="$WORK/charter-runs" CHARTER_POST_LOG="$post_log" CHARTER_IMPORT_SLEEP=2 TARGET_URL=http://127.0.0.1:13000 \
  "$CORE" charter --run-id first >/dev/null 2>&1 & first_pid=$!
sleep 1
SCANNERS_DIR="$WORK/fake-scanners" CHARTER_RUNS_DIR="$WORK/charter-runs" CHARTER_POST_LOG="$post_log" TARGET_URL=http://127.0.0.1:13000 \
  "$CORE" charter --run-id second >/dev/null 2>&1; second_rc=$?
wait "$first_pid"; first_rc=$?
if [ "$first_rc" -eq 0 ] && [ "$second_rc" -eq 75 ] && [ "$(wc -l <"$post_log")" -eq 1 ]; then
  ok "second charter controller stops at the lock before a second POST"
else
  bad "charter import lock allowed a concurrent POST (first=$first_rc second=$second_rc posts=$(wc -l <"$post_log"))"
fi
SCANNERS_DIR="$WORK/fake-scanners" CHARTER_RUNS_DIR="$WORK/charter-runs" CHARTER_POST_LOG="$post_log" CHARTER_IMPORT_FAIL=1 TARGET_URL=http://127.0.0.1:13000 \
  "$CORE" charter --run-id import-fail >/dev/null 2>&1; fail_rc=$?
failure_root="$(find "$WORK/charter-runs" -maxdepth 1 -type d -name 'import-fail.*' -print -quit)"
if [ "$fail_rc" -ne 0 ] && find "$failure_root" -maxdepth 1 -name '.raw.*' -print -quit | grep -q . \
  && find "$failure_root" -maxdepth 1 -name '.nuclei-stderr.*' -print -quit | grep -q . \
  && ! "$CORE" charter --resume "$failure_root" >/dev/null 2>&1; then
  ok "failed import retains private raw/stderr quarantine and resume stops"
else
  bad "failed import lost quarantine or resume treated it as complete"
fi

printf '\n== summary ==\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
