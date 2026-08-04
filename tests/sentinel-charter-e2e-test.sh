#!/usr/bin/env bash
# Hermetic controller E2E: terminal action evidence is a synthetic adapter result,
# never a Docker, Kong, LLM, transport, or target dispatch.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO="$ROOT/scripts/sentinel-demo.sh"
PROJECT_PYTHON="$ROOT/rag/.venv/bin/python"
FIXTURE_DIGEST="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
STAGE_ORDER='preflight labelled-chat topology-ready scan-redact-import analysis-report proposal approval executor response-guard final-report evaluation finalize'

fail() { echo "FAIL $*" >&2; exit 1; }
expect_status() {
  local wanted=$1 actual
  shift
  if "$@"; then actual=0; else actual=$?; fi
  [ "$actual" -eq "$wanted" ] || fail "expected exit $wanted, got $actual: $*"
}
expect_mode() { [ "$(stat -c '%a' "$1")" = "$2" ] || fail "unexpected mode for $1"; }
expect_stage_log() {
  local file=$1 expected=$2 actual
  actual=$(tr '\n' ' ' <"$file" | sed 's/ $//')
  [ "$actual" = "$expected" ] || fail "unexpected stage order: $actual"
}

tmp=$(TMPDIR=/tmp mktemp -d)
chmod 700 "$tmp"
trap 'rm -rf "$tmp"' EXIT
mkdir -m 700 "$tmp/home" "$tmp/tmp" "$tmp/runs" "$tmp/guards"

fixture_env="$tmp/kong.env"
umask 077
cat >"$fixture_env" <<'EOF'
KONG_PROVISION_KEY=test-provision
AGENT_RECON_SECRET=test-recon
PROBE_ADMIN_SECRET=test-probe
SENTINEL_CHARTER_EXECUTOR_SECRET=test-executor
SENTINEL_CHARTER_EXECUTOR_API_KEY=test-executor-api-key
EOF
chmod 600 "$fixture_env"

# Every command that could cross the controller boundary resolves here first.
# This tests the adapter-only boundary; it is not a generic network sandbox claim.
guard_log="$tmp/guard.log"
guard="$tmp/guards/blocked-command"
cat >"$guard" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$(basename "$0")" >>"$SENTINEL_E2E_GUARD_LOG"
exit 97
EOF
chmod 700 "$guard"
for command in docker docker-compose compose curl wget nuclei scan-and-import.sh run-nuclei.sh sentinel-charter-executor.py sentinel-component-runner; do
  cp "$guard" "$tmp/guards/$command"
  chmod 700 "$tmp/guards/$command"
done

adapter="$tmp/adapter"
cat >"$adapter" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

stage=$1
run=$2
for forbidden in KONG_PROXY LITELLM_MASTER_KEY REQUIRE_SENTINEL_LIVE PYTHONPATH PYTHONHOME; do
  [ -z "${!forbidden+x}" ] || { echo "ambient $forbidden reached fixture" >&2; exit 70; }
done
printf '%s\n' "$stage" >>"$SENTINEL_E2E_STAGE_LOG"

seed_analysis() {
  umask 077
  printf '%s\n' '{"schema_version":"1.0","finding_id":"finding:charter-nuclei-header","source_ids":["nuclei:one"],"tool":"nuclei","scanner":"DAST","title":"Missing content security policy","severity":"Low","location":"http://127.0.0.1:13000/rest/products","evidence":["template-id=header"]}' >"$run/normalized.jsonl"
  printf '%s\n' '{"schema_version":"1.0","finding_id":"finding:charter-trivy-secret","source_ids":["trivy:one"],"tool":"trivy","scanner":"SAST","title":"Generic API key","severity":"High","location":"file:package-lock.json","evidence":["rule-id=generic-api-key"]}' >>"$run/normalized.jsonl"
  printf '%s\n' '{"schema_version":"1.0","finding_id":"finding:charter-nuclei-header","name":"Missing content security policy","severity":"Low","location":"http://127.0.0.1:13000/rest/products","scanner_evidence":["template-id=header"],"explanation":"Scanner observed a missing header.","remediation":"Set the documented header.","confidence":"high","source_ids":["nuclei:one"],"knowledge_provenance":["owasp:headers"]}' >"$run/report.jsonl"
  chmod 600 "$run/normalized.jsonl" "$run/report.jsonl"
}

seed_scan_import() {
  mkdir -m 700 "$run/phase1"
  "$SENTINEL_PYTHON" - "$run/phase1" "$run" <<'PY'
import hashlib, json, pathlib, sys
phase, run = map(pathlib.Path, sys.argv[1:])
sanitized = phase / "nuclei.sanitized.jsonl"
sanitized.write_text('{"template-id":"fixture"}\n', encoding="utf-8")
digest = hashlib.sha256(sanitized.read_bytes()).hexdigest()
documents = {
    "scan-admission.json": {"schema_version":"sentinel-scan-admission/v1", "run_id":run.name,
        "sanitized_path":"nuclei.sanitized.jsonl", "sanitized_sha256":digest,
        "template_manifest_sha256":"a" * 64, "runtime":"nuclei"},
    "import-intent.json": {"state":"intent", "run_id":run.name, "scanner":"nuclei",
        "scan_type":"Nuclei Scan", "test_title":"Sentinel charter nuclei", "sanitized_sha256":digest,
        "request":{"close_old_findings":False, "deduplication_execution_mode":"async_wait"}},
    "import-observation.json": {"state":"completed", "sanitized_sha256":digest, "remote_test_id":"fixture",
        "response_sha256":"b" * 64, "gate":{"state":"passed", "reported":1}},
}
for name, document in documents.items():
    (phase / name).write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
  chmod 600 "$run/phase1/"*.json "$run/phase1/"*.jsonl
  record_effect scan-redact-import defectdojo-import
}

seed_proposal() {
  "$SENTINEL_PYTHON" - "$run" "$SENTINEL_E2E_PROPOSAL_MODE" <<'PY'
import json, os, sys
from dataclasses import asdict
from pathlib import Path
from agent.charter_requests import make_spec

run_dir, mode = Path(sys.argv[1]), sys.argv[2]
spec = make_spec(run_id=run_dir.name, method="GET", path="/sentinel-charter/rest/products/search", query="q=apple", ttl=-1 if mode == "expired" else 300)
document = asdict(spec)
document["headers"] = [list(pair) for pair in spec.headers]
fd = os.open(run_dir / "request-spec.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as output:
    json.dump(document, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
    output.flush()
    os.fsync(output.fileno())
PY
}

seed_approval() {
  "$SENTINEL_PYTHON" - "$run" <<'PY'
import json, os, sys
from dataclasses import asdict
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from agent.charter_approval import sign
from agent.charter_requests import load_spec

run_dir = Path(sys.argv[1])
spec = load_spec(json.loads((run_dir / "request-spec.json").read_text(encoding="utf-8")))
approval = sign(spec, Ed25519PrivateKey.generate(), decision="approve")
fd = os.open(run_dir / "approval.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as output:
    json.dump(asdict(approval), output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
    output.flush()
    os.fsync(output.fileno())
PY
}

seed_executor() {
  "$SENTINEL_PYTHON" - "$run" <<'PY'
import json, os, sys
from pathlib import Path
from agent.charter_requests import load_spec

run_dir = Path(sys.argv[1])
spec = load_spec(json.loads((run_dir / "request-spec.json").read_text(encoding="utf-8")))
receipt = {"schema_version":"sentinel-charter-receipt/v2", "request_id":spec.request_id,
           "status":200, "bytes":0, "receipt_digest":"a" * 64,
           "preview":"synthetic fixture only", "preview_truncated":False}
descriptor = {"schema_version":"sentinel-request-descriptor/v1", "receipt":"receipt.json"}
for name, document in (("receipt.json", receipt), ("request-descriptor.json", descriptor)):
    fd = os.open(run_dir / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(document, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
PY
  record_effect executor charter-request
}

record_effect() {
  local effect_stage=$1 effect=$2
  "$SENTINEL_PYTHON" - "$SENTINEL_MANIFEST_PY" "$run" "$effect_stage" "$effect" <<'PY'
import hashlib, json, subprocess, sys
from pathlib import Path

tool, run, stage, effect = sys.argv[1:]
root = Path(run)
if stage == "executor":
    intent, observation = root / "request-spec.json", root / "receipt.json"
    intent_path, observation_path = "request-spec.json", "receipt.json"
else:
    intent, observation = root / "phase1/import-intent.json", root / "phase1/import-observation.json"
    intent_path, observation_path = "phase1/import-intent.json", "phase1/import-observation.json"
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
for state in ("prepared", "observed"):
    event = {"stage":stage, "effect":effect, "state":state,
             "intent_path":intent_path, "intent_sha256":digest(intent)}
    if state == "observed":
        event.update({"observation_path":observation_path, "observation_sha256":digest(observation)})
    subprocess.run([sys.executable, tool, "effect", str(root / "manifest.json"), json.dumps(event)], check=True)
PY
}

if [ "$stage" = "$SENTINEL_E2E_FAIL_STAGE" ]; then
  printf 'failed\n'
  exit 0
fi
case "$stage" in
  scan-redact-import) seed_scan_import ;;
  analysis-report) seed_analysis ;;
  proposal) seed_proposal ;;
  approval) seed_approval ;;
  executor) seed_executor; printf 'passed\n{"request_count":1}\n'; exit 0 ;;
esac
printf 'passed\n'
EOF
chmod 700 "$adapter"

# Deliberately poison the parent process.  `controller` below must discard all
# of these inherited controls before the controller or adapter starts.
export SENTINEL_NUCLEI_IMAGE_DIGEST=not-a-digest
export SENTINEL_LITELLM_ALIAS=not-a-configured-alias
export SENTINEL_PYTHON=/bin/false
export SENTINEL_STAGE_ADAPTER=/does/not/exist
export LITELLM_MASTER_KEY=ambient-test-value
export KONG_PROXY=https://ambient.invalid
export REQUIRE_SENTINEL_LIVE=1
export PYTHONPATH=/ambient/pythonpath

# One controller runner: no ambient Sentinel, LiteLLM, Python, proxy, or
# live-mode settings survive this env -i boundary.
controller() { # proposal-mode failure-stage controller arguments...
  local proposal_mode=$1 failure_stage=$2
  shift 2
  env -i \
    PATH="$tmp/guards:/usr/local/bin:/usr/bin:/bin" \
    HOME="$tmp/home" TMPDIR="$tmp/tmp" \
    ENV_FILE="$fixture_env" \
    SENTINEL_NUCLEI_IMAGE_DIGEST="$FIXTURE_DIGEST" \
    SENTINEL_RUNS_DIR="$tmp/runs" \
    SENTINEL_STAGE_ADAPTER="$adapter" \
    SENTINEL_E2E_STAGE_LOG="$tmp/stages-$proposal_mode-$failure_stage" \
    SENTINEL_E2E_GUARD_LOG="$guard_log" \
    SENTINEL_E2E_PROPOSAL_MODE="$proposal_mode" \
    SENTINEL_E2E_FAIL_STAGE="$failure_stage" \
    SENTINEL_MANIFEST_PY="$ROOT/scripts/sentinel-manifest.py" \
    SENTINEL_PYTHON="$PROJECT_PYTHON" \
    SENTINEL_LITELLM_ALIAS=sast-charter-vertex-gemini-flash-lite \
    SENTINEL_CHARTER_REQUEST_KIND=get \
    "$DEMO" "$@"
}

controller current none run --profile charter --run-id e2e
controller current none verify e2e
expect_stage_log "$tmp/stages-current-none" "$STAGE_ORDER"

python3 - "$tmp/runs/e2e/manifest.json" "$tmp/runs/e2e/receipt.json" "$tmp/runs/e2e/request-descriptor.json" <<'PY'
import json, sys
manifest, receipt, descriptor = (json.load(open(path, encoding="utf-8")) for path in sys.argv[1:])
assert manifest["result"] == {"status":"passed", "action_sent":True}
assert manifest["metrics"]["request_count"] == 1
assert receipt["schema_version"] == "sentinel-charter-receipt/v2"
assert receipt["preview"] == "synthetic fixture only"
assert descriptor == {"schema_version":"sentinel-request-descriptor/v1", "receipt":"receipt.json"}
PY
echo 'PASS synthetic terminal action: adapter simulation only; no real dispatch'

expect_mode "$tmp" 700
expect_mode "$tmp/runs" 700
expect_mode "$tmp/runs/e2e" 700
expect_mode "$fixture_env" 600
if find "$tmp/runs/e2e" -type f ! -perm 600 -print -quit | grep -q .; then
  fail 'a synthetic run artifact is not mode 0600'
fi
echo 'PASS synthetic fixture and run artifacts are private'

expect_status 77 controller expired none run --profile charter --run-id expired
expect_stage_log "$tmp/stages-expired-none" 'preflight labelled-chat topology-ready scan-redact-import analysis-report proposal'
for absent in approval.json receipt.json request-descriptor.json; do
  [ ! -e "$tmp/runs/expired/$absent" ] || fail "expired preflight published $absent"
done
echo 'PASS expired policy-valid spec stops before approval adapter'

expect_status 1 controller current analysis-report run --profile charter --run-id analysis-failed
expect_stage_log "$tmp/stages-current-analysis-report" 'preflight labelled-chat topology-ready scan-redact-import analysis-report'
[ ! -e "$tmp/runs/analysis-failed/request-spec.json" ] || fail 'analysis failure reached proposal'
echo 'PASS analysis failure stops before proposal'

[ ! -e "$guard_log" ] || fail "guarded command was invoked: $(tr '\n' ' ' <"$guard_log")"
echo 'PASS no guarded command was invoked'
