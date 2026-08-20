#!/usr/bin/env bash
# Charter-run controller: owns only private state and controller-started resources.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNS="${SENTINEL_RUNS_DIR:-$HERE/../.sentinel-runs}"
MANIFEST_TOOL=(python3 "$HERE/sentinel-manifest.py")
CHARTER_PYTHON="${SENTINEL_PYTHON:-$HERE/../rag/.venv/bin/python}"

usage() { echo 'usage: sentinel-demo.sh run --profile charter --run-id ID [--artifact-input PATH --artifact-sha256 SHA] | resume ID [--artifact-input PATH --artifact-sha256 SHA] | recover-audit ID | verify ID | --teardown ID' >&2; }
die() { echo "sentinel-demo: $*" >&2; exit 2; }
safe_id() { [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]]; }
hash_file() { sha256sum "$1" | awk '{print $1}'; }
hash_text() { printf '%s' "$1" | sha256sum | awk '{print $1}'; }

parse_artifact_options() {
  ARTIFACT= ARTIFACT_SHA=
  while (($#)); do
    case "$1" in
      --artifact-input) ARTIFACT=${2:-}; shift 2 ;;
      --artifact-sha256) ARTIFACT_SHA=${2:-}; shift 2 ;;
      *) die "unknown option $1" ;;
    esac
  done
  if [[ -n "$ARTIFACT" || -n "$ARTIFACT_SHA" ]]; then
    [[ -n "$ARTIFACT" && -n "$ARTIFACT_SHA" ]] || die 'CI artifact and SHA must be supplied together'
  fi
}

parse_run() {
  PROFILE= RUN_ID=
  local remaining=()
  while (($#)); do
    case "$1" in
      --profile) PROFILE=${2:-}; shift 2 ;;
      --run-id) RUN_ID=${2:-}; shift 2 ;;
      *) remaining+=("$1"); shift ;;
    esac
  done
  [[ "$PROFILE" == charter ]] && safe_id "$RUN_ID" || die 'requires --profile charter --run-id SAFE_ID'
  parse_artifact_options "${remaining[@]}"
}

ci_artifact_ok() {
  [[ -f "$ARTIFACT" && ! -L "$ARTIFACT" && "$(hash_file "$ARTIFACT")" == "$ARTIFACT_SHA" ]] || return 1
  local metadata="${ARTIFACT%.json}.metadata.json"
  [[ -f "$metadata" && ! -L "$metadata" ]] || return 1
  python3 - "$metadata" "$ARTIFACT_SHA" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
raise SystemExit(0 if value == {"type":"trivy-sanitized-json", "version":"1", "sha256":sys.argv[2]} else 1)
PY
}

require_private_regular() {
  local path=$1 nonempty=${2:-0}
  [[ -f "$path" && ! -L "$path" ]] || return 1
  [[ "$(stat -c '%a' "$path")" == 600 ]] || return 1
  [[ "$nonempty" != 1 || -s "$path" ]]
}

prepare_ci_snapshots() {
  local dir=$1 metadata="${ARTIFACT%.json}.metadata.json"
  python3 - "$ARTIFACT" "$metadata" "$dir/trivy.admitted.json" "$dir/trivy.admitted.metadata.json" "$ARTIFACT_SHA" <<'PY'
import hashlib, json, os, stat, sys
from pathlib import Path

source, metadata, out_artifact, out_metadata = map(Path, sys.argv[1:5]); expected = sys.argv[5]
def read_once(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode): raise ValueError("not a regular file")
        chunks=[]
        while True:
            part=os.read(fd, 65536)
            if not part: return b"".join(chunks)
            chunks.append(part)
    finally: os.close(fd)
def publish(path, value):
    fd=os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0), 0o600)
    try:
        os.write(fd, value); os.fsync(fd)
    finally: os.close(fd)
artifact = read_once(source)
sidecar = read_once(metadata)
if hashlib.sha256(artifact).hexdigest() != expected: raise SystemExit("artifact digest changed")
try: doc=json.loads(sidecar)
except Exception as exc: raise SystemExit("invalid metadata") from exc
if doc != {"type":"trivy-sanitized-json","version":"1","sha256":expected}: raise SystemExit("invalid metadata")
publish(out_artifact, artifact); publish(out_metadata, sidecar)
PY
}

ensure_run_root() {
  local source=${1:-local}
  if [[ -e "$RUNS" || -L "$RUNS" ]]; then
    [[ -d "$RUNS" && ! -L "$RUNS" ]] || die 'unsafe run root'
    if [[ "$source" == ci ]]; then
      [[ "$(stat -c '%a' "$RUNS")" == 700 ]] || die 'unsafe run root'
    else
      chmod 700 "$RUNS"
    fi
  else
    mkdir -m 700 "$RUNS"
  fi
}

guard_private_run_path() {
  # Validate every controller-owned path component without following a final
  # symlink before a read-side command touches the manifest.  This is a guard,
  # not a repair: widened modes and hostile paths stay untouched and fail closed.
  local id=$1
  python3 - "$RUNS" "$id" <<'PY'
import os, stat, sys
from pathlib import Path

root, run_id = Path(sys.argv[1]), sys.argv[2]
run, manifest = root / run_id, root / run_id / "manifest.json"
def private_directory(path):
    item = os.lstat(path)
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode) or stat.S_IMODE(item.st_mode) != 0o700:
        raise ValueError(f"unsafe private directory: {path.name}")
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not os.path.samestat(item, os.fstat(fd)): raise ValueError(f"raced private directory: {path.name}")
    finally: os.close(fd)
def private_file(path):
    item = os.lstat(path)
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode) or stat.S_IMODE(item.st_mode) != 0o600:
        raise ValueError("unsafe private manifest")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not os.path.samestat(item, os.fstat(fd)): raise ValueError("raced private manifest")
    finally: os.close(fd)
try:
    private_directory(root); private_directory(run); private_file(manifest)
except (OSError, ValueError) as exc:
    raise SystemExit(str(exc))
PY
}

stages_for() {
  if [[ "$1" == ci ]]; then
    printf '%s\n' preflight labelled-chat verify-ci-artifact ci-normalize-import
  else
    printf '%s\n' preflight labelled-chat topology-ready scan-redact-import analysis-report proposal approval executor response-guard final-report evaluation finalize
  fi
}

stage_order_json() {
  stages_for "$1" | python3 -c 'import json,sys; print(json.dumps([line.strip() for line in sys.stdin if line.strip()]))'
}

immutable_hashes() {
  TARGET_SHA="$(hash_text 'http://127.0.0.1:13000')"
  CONFIG_SHA="$(hash_file "$HERE/../infra/kong/kong.declarative.yml.tmpl")"
  POLICY_SHA="$(hash_file "$HERE/../scanners/target-allowlist.sh")"
}

build_resume_identity() { # source input digest; prints canonical descriptor, never config bytes
  local source=$1 input_digest=$2 runtime alias ci_value rendered request_kind
  request_kind=${SENTINEL_CHARTER_REQUEST_KIND:-get}
  [[ "$request_kind" == get || "$request_kind" == post ]] || die 'unsafe charter request kind'
  alias="${SENTINEL_LITELLM_ALIAS:-sast-charter-vertex-gemini-flash-lite}"
  [[ "$alias" =~ ^[a-z][a-z0-9-]{0,63}$ ]] || die 'unsafe LiteLLM model alias'
  python3 - "$HERE/../infra/litellm/config.yaml" "$alias" <<'PY' || die 'model alias is not config-bound'
import re, sys
path, alias = sys.argv[1:]
pattern = re.compile(r"^\s*(?:-\s*)?model_name:\s*([^\s#]+)\s*(?:#.*)?$")
for line in open(path, encoding="utf-8"):
    match = pattern.match(line)
    if match and match.group(1) == alias:
        raise SystemExit(0)
raise SystemExit(1)
PY
  local scanner_image="${SENTINEL_NUCLEI_IMAGE_DIGEST:-}" scanner_binary="${SENTINEL_NUCLEI_BIN:-}"
  [[ -z "${NUCLEI_BIN:-}" ]] || die 'legacy NUCLEI_BIN is not an admitted charter scanner selector'
  [[ -z "${NUCLEI_IMAGE:-}" ]] || die 'legacy NUCLEI_IMAGE is not an admitted charter scanner selector'
  if [[ -n "$scanner_image" && -n "$scanner_binary" ]]; then
    die 'exactly one admitted charter scanner selector is required'
  elif [[ -n "$scanner_image" ]]; then
    [[ "$scanner_image" =~ ^[0-9a-f]{64}$ ]] || die 'unsafe scanner image digest'
    runtime=$(python3 - "$scanner_image" <<'PY'
import json,sys; print(json.dumps({"kind":"image","digest":sys.argv[1]}, separators=(",",":")))
PY
)
  else
    [[ -n "$scanner_binary" && -f "$scanner_binary" && -x "$scanner_binary" && ! -L "$scanner_binary" ]] || die 'new v2 run requires an admitted scanner image digest or local binary'
    version=$("$scanner_binary" -version 2>/dev/null | tr -d '\r\n')
    [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9._-]+)?$ ]] || die 'local scanner version is not a safe Nuclei version literal'
    runtime=$(python3 - "$(hash_file "$scanner_binary")" "$version" <<'PY'
import json,sys; print(json.dumps({"kind":"local-binary","sha256":sys.argv[1],"version":sys.argv[2]}, separators=(",",":")))
PY
)
  fi
  # Render to a controller-private disposable file and retain only its digest.
  # No expanded byte is emitted, copied to the manifest, or accepted from an
  # operator-provided hash that could describe a different rendered policy.
  local rendered_file
  rendered_file=$(mktemp "${TMPDIR:-/tmp}/sentinel-kong-rendered.XXXXXX")
  chmod 600 "$rendered_file"
  if ! OUT="$rendered_file" "$HERE/../infra/kong/render-config.sh" >/dev/null; then
    rm -f "$rendered_file"; die 'could not render private Kong configuration for v2 identity'
  fi
  rendered=$(hash_file "$rendered_file")
  rm -f "$rendered_file"
  if [[ "$source" == ci ]]; then
    ci_value=$(python3 - "$input_digest" "${SENTINEL_CI_METADATA_SHA256:-}" <<'PY'
import json,sys
if not all(len(x)==64 and all(c in '0123456789abcdef' for c in x) for x in sys.argv[1:]): raise SystemExit(1)
print(json.dumps({"type":"trivy-sanitized-json","version":"1","artifact_sha256":sys.argv[1],"metadata_sha256":sys.argv[2]},separators=(",",":")))
PY
) || die 'CI metadata digest is required for v2 identity'
  else ci_value='"not-applicable"'; fi
  python3 - "$source" "$runtime" "$ci_value" "$alias" "$rendered" "$request_kind" "$HERE" <<'PY'
import hashlib, json, pathlib, sys
source, runtime, ci, alias, rendered, request_kind, here = sys.argv[1:]
root=pathlib.Path(here).parent
def h(path): return hashlib.sha256((root/path).read_bytes()).hexdigest()
inputs={
 "controller":{"sentinel_demo_sha256":h("scripts/sentinel-demo.sh"),"sentinel_manifest_sha256":h("scripts/sentinel-manifest.py"),"stage_order_sha256":hashlib.sha256((b"preflight\nlabelled-chat\n" + (b"verify-ci-artifact\nci-normalize-import\n" if source=="ci" else b"topology-ready\nscan-redact-import\nanalysis-report\nproposal\napproval\nexecutor\nresponse-guard\nfinal-report\nevaluation\nfinalize\n"))).hexdigest(),"profile":"charter","source":source,"request_kind":request_kind},
 "target_and_scan":{"target_origin":"http://127.0.0.1:13000","target_allowlist_sha256":h("scanners/target-allowlist.sh"),"run_nuclei_sha256":h("scanners/run-nuclei.sh"),"redact_report_sha256":h("scanners/redact-report.sh"),"scan_and_import_sha256":h("scripts/scan-and-import.sh"),"template_manifest_sha256":h("scanners/charter-template-manifest.json"),"scanner_runtime":json.loads(runtime)},
 "analysis":{"normalize_findings_sha256":h("agent/normalize_findings.py"),"recon_sha256":h("agent/recon.py"),"report_sha256":h("agent/report.py"),"charter_contracts_sha256":h("agent/charter_contracts.py"),"response_guard_sha256":h("agent/charter_response_guard.py"),"pii_sha256":h("agent/pii.py"),"prompt_sha256":h("agent/prompts/charter-system-prompt.md"),"llm_sha256":h("agent/llm.py"),"corpus_manifest_sha256":h("rag/charter-corpus-manifest.json"),"retrieval_contract_sha256":h("rag/retrieve.py"),"model_alias":alias,"model_config_sha256":h("infra/litellm/config.yaml")},
 "gateway_and_request":{"kong_render_script_sha256":h("infra/kong/render-config.sh"),"kong_rendered_config_sha256":rendered,"charter_requests_sha256":h("agent/charter_requests.py"),"charter_proposal_sha256":h("agent/charter_proposal.py"),"charter_approval_sha256":h("agent/charter_approval.py"),"charter_receipt_sha256":h("agent/charter_receipt.py"),"charter_audit_recovery_sha256":h("agent/charter_audit_recovery.py"),"executor_sha256":h("scripts/sentinel-charter-executor.py"),"adapter_capture_sha256":h("scripts/sentinel-adapter-capture.py")},
 "evaluation":{"result_report_sha256":h("evaluation/charter-eval/result-report.py"),"cases_sha256":h("evaluation/charter-eval/cases.json"),"gold_sha256":h("evaluation/charter-eval/gold.json")},
 "ci_handoff":{"value":json.loads(ci)}, }
print(json.dumps({"schema_version":"sentinel-charter-resume-identity/v1","inputs":inputs,"sha256":hashlib.sha256(json.dumps(inputs,sort_keys=True,separators=(",",":")).encode()).hexdigest()},sort_keys=True,separators=(",",":")))
PY
}

# The injectable adapter is a component boundary. It emits one status line and,
# optionally, a second JSON object with only its RunMetrics/v1 increments.
approval_spec_is_current() {
  local spec_path="$1/request-spec.json"
  [[ -f "$spec_path" && ! -L "$spec_path" ]] || return 1
  "$CHARTER_PYTHON" - "$spec_path" <<'PY'
import json, sys, time
from pathlib import Path
from agent.charter_requests import load_spec

try:
    spec = load_spec(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")))
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if spec.expires_at > time.time() else 1)
PY
}

operator_boundary_is_safe() {
  local public_key="${SENTINEL_CHARTER_PUBLIC_KEY:-}"
  local public_key_sha256="${SENTINEL_CHARTER_PUBLIC_KEY_SHA256:-}"
  local adapter="${SENTINEL_CHARTER_EXECUTOR_ADAPTER:-}"
  [[ "$public_key_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  "$CHARTER_PYTHON" - "$public_key" "$public_key_sha256" "$adapter" <<'PY'
import hashlib
import os
import stat
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

public_path, expected, adapter_path = sys.argv[1:]

def safe_parents(path):
    if not os.path.isabs(path) or "//" in path or "/./" in path or "/../" in path:
        raise SystemExit(1)
    parent = os.path.dirname(path) or os.sep
    while True:
        item = os.lstat(parent)
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
            raise SystemExit(1)
        mode = stat.S_IMODE(item.st_mode)
        if item.st_uid not in (os.geteuid(), 0):
            raise SystemExit(1)
        if mode & 0o022 and not (item.st_uid == 0 and mode & stat.S_ISVTX):
            raise SystemExit(1)
        if parent == os.sep:
            return
        parent = os.path.dirname(parent) or os.sep

def safe_regular(path, *, exact_mode=None, forbidden_mode=0o022, read_content=False):
    safe_parents(path)
    item = os.lstat(path)
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid():
        raise SystemExit(1)
    mode = stat.S_IMODE(item.st_mode)
    if (exact_mode is not None and mode != exact_mode) or (exact_mode is None and mode & forbidden_mode):
        raise SystemExit(1)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not os.path.samestat(item, os.fstat(fd)):
            raise SystemExit(1)
        if read_content:
            return b"".join(iter(lambda: os.read(fd, 65536), b""))
    finally:
        os.close(fd)

data = safe_regular(public_path, read_content=True)
safe_regular(adapter_path, exact_mode=0o700)
key = serialization.load_pem_public_key(data)
if not isinstance(key, Ed25519PublicKey):
    raise SystemExit(1)
der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
raise SystemExit(0 if hashlib.sha256(der).hexdigest() == expected else 1)
PY
}

write_import_intent() { # phase1 run-id; exclusive, safe public facts only
  local phase=$1 run_id=$2
  python3 - "$phase/import-intent.json" "$phase/nuclei.sanitized.jsonl" "$run_id" <<'PY'
import hashlib,json,os,sys
path,sanitized,run_id=sys.argv[1:]
value={"state":"intent","run_id":run_id,"scanner":"nuclei","scan_type":"Nuclei Scan","test_title":"Sentinel charter nuclei","sanitized_sha256":hashlib.sha256(open(sanitized,"rb").read()).hexdigest(),"request":{"close_old_findings":False,"deduplication_execution_mode":"async_wait"}}
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,"w",encoding="utf-8") as out: json.dump(value,out,sort_keys=True,separators=(",",":"));out.write("\n");out.flush();os.fsync(out.fileno())
PY
}

record_effect() { # dir stage effect state intent [observation]
  local dir=$1 stage=$2 effect_name=$3 state=$4 intent=$5 observation=${6:-} event
  event=$(python3 - "$stage" "$effect_name" "$state" "$intent" "$observation" <<'PY'
import hashlib,json,pathlib,sys
stage,effect,state,intent,observation=sys.argv[1:]
def row(path): return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
value={"stage":stage,"effect":effect,"state":state,"intent_path":str(pathlib.Path(intent).relative_to(pathlib.Path(intent).parents[1] if pathlib.Path(intent).parent.name=='phase1' else pathlib.Path(intent).parent)),"intent_sha256":row(intent)}
# The controller only calls this for controller-fixed paths.  Preserve phase1
# in the manifest rather than trusting an adapter-supplied path.
if pathlib.Path(intent).parent.name == 'phase1': value['intent_path']='phase1/'+pathlib.Path(intent).name
else: value['intent_path']=pathlib.Path(intent).name
if state in {'observed','audited'}:
    value['observation_path']='phase1/'+pathlib.Path(observation).name if pathlib.Path(observation).parent.name=='phase1' else pathlib.Path(observation).name
    value['observation_sha256']=row(observation)
print(json.dumps(value,sort_keys=True,separators=(",",":")))
PY
)
  "${MANIFEST_TOOL[@]}" effect "$dir/manifest.json" "$event"
}

invoke_stage() {
  local stage=$1 run_dir=$2 reply status source
  source=$("${MANIFEST_TOOL[@]}" read "$run_dir/manifest.json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["input"]["source"])')
  if [[ "$source" == ci && ( -n "${SENTINEL_STAGE_ADAPTER:-}" || -n "${SENTINEL_COMPONENT_RUNNER:-}" ) ]]; then
    return 78
  fi
  APPROVAL_PREFLIGHT_REFUSED=0
  # This must precede both the injectable adapter and production dispatch: an
  # expired or policy-invalid persisted request is not an operator-ready pause.
  if [[ "$stage" == approval ]] && ! approval_spec_is_current "$run_dir"; then
    APPROVAL_PREFLIGHT_REFUSED=1
    return 77
  fi
  if [[ -n "${SENTINEL_STAGE_ADAPTER:-}" ]]; then
    reply=$("$SENTINEL_STAGE_ADAPTER" "$stage" "$run_dir") || { status=$?; return "$status"; }
  else
    reply=$(production_stage "$stage" "$run_dir" "$source") || { status=$?; return "$status"; }
  fi
  mapfile -t STAGE_LINES <<<"$reply"
  [[ ${#STAGE_LINES[@]} -ge 1 && ${#STAGE_LINES[@]} -le 2 ]] || return 70
  STAGE_OUTCOME=${STAGE_LINES[0]}
  STAGE_METRICS=${STAGE_LINES[1]:-\{\}}
  case "$STAGE_OUTCOME" in passed|rejected|failed|skipped) ;; *) return 70;; esac
  python3 - "$STAGE_METRICS" <<'PY'
import json, sys
allowed = {"duration_ms", "request_count", "warning_count", "approve_count", "reject_count", "llm_error_count", "application_error_count", "finding_count"}
try: value = json.loads(sys.argv[1])
except json.JSONDecodeError: raise SystemExit(1)
raise SystemExit(0 if isinstance(value, dict) and all(k in allowed and type(v) is int and v >= 0 for k, v in value.items()) else 1)
PY
}

report_finding_increment() {
  python3 - "$1" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
count = 0
for line in path.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    json.loads(line)
    count += 1
print(json.dumps({"finding_count": count}, separators=(",", ":")))
PY
}

production_stage() {
  local stage=$1 dir=$2 source=${3:-local} runner="${SENTINEL_COMPONENT_RUNNER:-}"
  # The runner is an explicit component boundary; absent it production invokes
  # only published commands and fails rather than inventing a fallback target.
  # Remote scan/import and request dispatch stay controller-owned so it can
  # durably record the intent before the effect and its observation afterwards.
  # A component runner may provide only the non-remote stage boundary.
  if [[ "$source" != ci && -n "$runner" && "$stage" != scan-redact-import && "$stage" != executor ]]; then
    "$runner" "$stage" "$dir" "${ARTIFACT:-}"
    return
  fi
  case "$stage" in
    preflight)
      if [[ "$source" == ci ]]; then
        require_private_regular "$dir/trivy.admitted.json" 1 && require_private_regular "$dir/trivy.admitted.metadata.json" 1 || return 1
      else
        [[ "${TARGET_URL:-}" == http://127.0.0.1:13000 && -x "$HERE/scan-and-import.sh" && -x "$HERE/../scanners/target-allowlist.sh" && -x "$CHARTER_PYTHON" ]] || return 1
      fi
      printf 'passed\n';;
    labelled-chat)
      [[ "$source" == ci ]] && { printf 'passed\n'; return; }
      [[ -n "${SENTINEL_LITELLM_ALIAS:-}" && -n "${LITELLM_MASTER_KEY:-}" ]] || return 1
      "$CHARTER_PYTHON" - "$SENTINEL_LITELLM_ALIAS" <<'PY' >/dev/null || return 1
import sys
from agent.llm import Msg, checked_chat, operator, target_derived
reply = checked_chat([
    Msg("system", "You are a security analyst. Reply with acknowledged.", operator()),
    Msg("user", "Controller preflight only; do not perform any action.",
        target_derived(source="sentinel-controller-preflight", target="juice-shop-charter")),
], model=sys.argv[1], max_tokens=8)
raise SystemExit(0 if reply.strip() else 1)
PY
      printf 'passed\n'
      ;;
    scan-redact-import)
      [[ -z "${ARTIFACT:-}" ]] || return 1
      mkdir -m 700 "$dir/phase1"
      if ! SCANNERS_DIR="$HERE/../scanners" TARGET_URL=http://127.0.0.1:13000 "$HERE/scan-and-import.sh" charter-admit --run-root "$dir/phase1" --run-id "$(basename "$dir")" >/dev/null; then
        printf 'failed\n'
        return 0
      fi
      if ! write_import_intent "$dir/phase1" "$(basename "$dir")" || ! record_effect "$dir" scan-redact-import defectdojo-import prepared "$dir/phase1/import-intent.json"; then
        printf 'failed\n'; return 0
      fi
      if ! "$HERE/scan-and-import.sh" charter-import --run-root "$dir/phase1" >/dev/null; then
        # The durable prepared intent is deliberately not replaced by a retry.
        record_effect "$dir" scan-redact-import defectdojo-import unknown "$dir/phase1/import-intent.json" || true
        printf 'failed\n'; return 0
      fi
      if ! record_effect "$dir" scan-redact-import defectdojo-import observed "$dir/phase1/import-intent.json" "$dir/phase1/import-observation.json"; then
        printf 'failed\n'; return 0
      fi
      printf 'passed\n'
      ;;
    verify-ci-artifact)
      [[ "$source" == ci ]] && require_private_regular "$dir/trivy.admitted.json" 1 && require_private_regular "$dir/trivy.admitted.metadata.json" 1 || return 1
      printf 'passed\n';;
    ci-normalize-import)
      [[ "$source" == ci ]] || return 1
      "$CHARTER_PYTHON" -m agent.normalize_trivy --artifact "$dir/trivy.admitted.json" --metadata "$dir/trivy.admitted.metadata.json" --output "$dir/trivy.normalized.jsonl" --exclusive-output >/dev/null || return 1
      require_private_regular "$dir/trivy.normalized.jsonl" 1 || return 1
      printf 'passed\n';;
    analysis-report)
      local i; i=$(find "$dir/phase1" -name nuclei.sanitized.jsonl -type f)
      [[ -n "$i" && -n "${SENTINEL_LITELLM_ALIAS:-}" ]] || return 1
      local analysis_status=0
      "$CHARTER_PYTHON" -m agent.recon --charter-input "$i" --charter-normalized-out "$dir/normalized.jsonl" --charter-report-out "$dir/report.jsonl" --charter-model "$SENTINEL_LITELLM_ALIAS" >/dev/null || analysis_status=$?
      if [[ "$analysis_status" != 0 ]]; then
        printf 'failed\n{"llm_error_count":1}\n'
        return 0
      fi
      printf 'passed\n%s\n' "$(report_finding_increment "$dir/report.jsonl")"
      ;;
    topology-ready)
      [[ -n "$(docker ps -q --filter 'name=^/sentinel-litellm$' 2>/dev/null)" ]] \
        && [[ -n "$(docker ps -q --filter 'name=^/sentinel-kong$' 2>/dev/null)" ]] \
        && [[ -n "$(docker ps -q --filter 'name=^/juice-shop$' 2>/dev/null)" ]] \
        || return 1
      printf 'passed\n'
      ;;
    proposal)
      [[ -f "$dir/report.jsonl" && ! -L "$dir/report.jsonl" ]] || return 1
      "$CHARTER_PYTHON" - "$dir" "${SENTINEL_CHARTER_REQUEST_KIND:-get}" <<'PY' || return 1
import json, os, sys
from dataclasses import asdict
from pathlib import Path
from agent.charter_proposal import propose_report_jsonl
from agent.charter_requests import safe_request_case_ids

run_dir, request_kind = Path(sys.argv[1]), sys.argv[2]
if request_kind not in {"get", "post", *safe_request_case_ids()}:
    raise SystemExit("unsupported charter request kind")
try:
    proposal = propose_report_jsonl(run_dir / "report.jsonl", request_kind=request_kind)
except Exception as exc:
    raise SystemExit("invalid grounded report") from exc
if not proposal.available:
    raise SystemExit("no fixed request can be proposed from grounded findings")
spec = proposal.to_spec(run_dir.name)
payload = asdict(spec)
payload["headers"] = [list(pair) for pair in spec.headers]
destination = run_dir / "request-spec.json"
fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as output:
    json.dump(payload, output, sort_keys=True, separators=(",", ":"))
    output.write("\n"); output.flush(); os.fsync(output.fileno())
PY
      printf 'passed\n'
      ;;
    approval)
      # Approval is a real pause: do not turn an absent human decision into a failed
      # run, an automatic rejection, or an unreviewed request.  Exit 76 keeps this
      # first incomplete stage resumable after the operator signs the displayed spec.
      [[ -n "${SENTINEL_CHARTER_APPROVAL_FILE:-}" && -n "${SENTINEL_CHARTER_PUBLIC_KEY:-}" ]] || return 76
      [[ -f "$SENTINEL_CHARTER_APPROVAL_FILE" && ! -L "$SENTINEL_CHARTER_APPROVAL_FILE" && -f "$SENTINEL_CHARTER_PUBLIC_KEY" && ! -L "$SENTINEL_CHARTER_PUBLIC_KEY" ]] || return 1
      local decision
      decision=$("$CHARTER_PYTHON" - "$dir" "$SENTINEL_CHARTER_APPROVAL_FILE" "$SENTINEL_CHARTER_PUBLIC_KEY" <<'PY'
import json, os, sys
from dataclasses import asdict
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from agent.charter_approval import CharterApproval, verify
from agent.charter_requests import load_spec

run_dir, supplied, public_path = map(Path, sys.argv[1:])
try:
    spec_doc = json.loads((run_dir / "request-spec.json").read_text(encoding="utf-8"))
    spec = load_spec(spec_doc)
    approval = CharterApproval(**json.loads(supplied.read_text(encoding="utf-8")))
    public = serialization.load_pem_public_key(public_path.read_bytes())
except Exception as exc:
    raise SystemExit("invalid isolated approval input") from exc
if not verify(approval, spec, public):
    raise SystemExit("approval does not bind the fixed request")
destination = run_dir / "approval.json"
fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as output:
    json.dump(asdict(approval), output, sort_keys=True, separators=(",", ":"))
    output.write("\n"); output.flush(); os.fsync(output.fileno())
print(approval.decision)
PY
      ) || return 1
      case "$decision" in
        approve) printf 'passed\n{"approve_count":1}\n' ;;
        reject|revoke) printf 'rejected\n' ;;
        *) return 1 ;;
      esac
      ;;
    executor)
      # This shell is the agent/controller boundary.  It must not inherit, inspect,
      # or forward the OAuth secret; a separately provisioned executor adapter owns
      # that credential and invokes sentinel-charter-executor.py in its own context.
      operator_boundary_is_safe || return 1
      [[ -f "$dir/request-spec.json" && -f "$dir/approval.json" && -f "$SENTINEL_CHARTER_PUBLIC_KEY" ]] || return 1
      "$CHARTER_PYTHON" - "$dir" <<'PY' || return 1
import json, sys
from pathlib import Path
from agent.charter_requests import load_spec
try:
    load_spec(json.loads((Path(sys.argv[1]) / "request-spec.json").read_text(encoding="utf-8")))
except Exception as exc:
    raise SystemExit("invalid immutable request spec") from exc
PY
      if [[ "$("${MANIFEST_TOOL[@]}" read "$dir/manifest.json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["schema_version"])')" == sentinel-run/v2 ]]; then
        record_effect "$dir" executor charter-request prepared "$dir/request-spec.json" || return 1
      fi
      local result
      if ! result=$("$CHARTER_PYTHON" "$HERE/sentinel-adapter-capture.py" --stdout-limit 4096 --stderr-limit 4096 -- "$SENTINEL_CHARTER_EXECUTOR_ADAPTER" "$dir/request-spec.json" "$dir/approval.json" "$dir/executor-state.sqlite" "$SENTINEL_CHARTER_PUBLIC_KEY"); then
        if [[ "$("${MANIFEST_TOOL[@]}" read "$dir/manifest.json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["schema_version"])')" == sentinel-run/v2 ]]; then record_effect "$dir" executor charter-request unknown "$dir/request-spec.json" || true; fi
        return 1
      fi
      if ! CHARTER_EXECUTOR_RESULT="$result" "$CHARTER_PYTHON" - "$dir" <<'PY'
import json, os, sys
from pathlib import Path
from agent.charter_receipt import decode_object, validate_adapter_result, validate_receipt
from agent.charter_requests import load_spec
from agent.charter_response_guard import guard_http_response

run_dir = Path(sys.argv[1])
try:
    spec = load_spec(json.loads((run_dir / "request-spec.json").read_text(encoding="utf-8")))
    raw = os.environ["CHARTER_EXECUTOR_RESULT"].encode("utf-8")
    value = decode_object(raw)
    if value.get("schema_version") == "sentinel-charter-receipt/v2":
        if spec.method != "GET":
            raise ValueError("receipt v2 is GET-only")
        receipt = validate_receipt(value, spec)
        if "preview" in receipt:
            guarded = guard_http_response(receipt["preview"])
            if guarded.status != "accepted" or guarded.persisted_text != receipt["preview"]:
                raise ValueError("preview projection does not survive re-guarding")
    else:
        if spec.method != "POST":
            raise ValueError("legacy adapter result is POST-only")
        legacy = validate_adapter_result(value, spec)
        receipt = validate_receipt({"schema_version":"sentinel-charter-receipt/v1", "request_id":legacy["request_id"],
                                   "status":legacy["status"], "bytes":legacy["bytes"],
                                   "receipt_digest":legacy["receipt_digest"]}, spec)
    if (run_dir / "receipt.json").exists() or (run_dir / "request-descriptor.json").exists():
        raise ValueError("receipt artifacts already exist")
except Exception as exc:
    raise SystemExit("executor response did not meet the fixed receipt contract") from exc
for name, document in (("receipt.json", receipt), ("request-descriptor.json", {"schema_version":"sentinel-request-descriptor/v1", "receipt":"receipt.json"})):
    destination = run_dir / name
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(document, output, sort_keys=True, separators=(",", ":")); output.write("\n")
        output.flush(); os.fsync(output.fileno())
PY
      then
        if [[ "$("${MANIFEST_TOOL[@]}" read "$dir/manifest.json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["schema_version"])')" == sentinel-run/v2 ]]; then record_effect "$dir" executor charter-request unknown "$dir/request-spec.json" || true; fi
        return 1
      fi
      if [[ "$("${MANIFEST_TOOL[@]}" read "$dir/manifest.json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["schema_version"])')" == sentinel-run/v2 ]]; then
        record_effect "$dir" executor charter-request observed "$dir/request-spec.json" "$dir/receipt.json" || return 1
      fi
      printf 'passed\n{"request_count":1}\n'
      ;;
    response-guard)
      "$CHARTER_PYTHON" - "$dir" <<'PY' || return 1
import json, sys
from pathlib import Path
from agent.charter_receipt import decode_object, validate_receipt
from agent.charter_requests import load_spec
try:
    run_dir=Path(sys.argv[1])
    spec=load_spec(json.loads((run_dir / "request-spec.json").read_text(encoding="utf-8")))
    validate_receipt(decode_object((run_dir / "receipt.json").read_bytes()), spec)
except Exception as exc: raise SystemExit(1) from exc
PY
      printf 'passed\n'
      ;;
    final-report)
      [[ -f "$dir/normalized.jsonl" && -f "$dir/report.jsonl" && -f "$dir/receipt.json" ]] || return 1
      printf 'passed\n'
      ;;
    evaluation)
      [[ -f "$HERE/../evaluation/charter-eval/cases.json" && -f "$HERE/../evaluation/charter-eval/gold.json" ]] || return 1
      "$CHARTER_PYTHON" -m py_compile "$HERE/../evaluation/charter-eval/result-report.py" || return 1
      printf 'passed\n'
      ;;
    finalize) printf 'passed\n' ;;
    *) return 1;; esac
}

checkpoint_for_stage() { # run-root stage -> closed checkpoint JSON
  local dir=$1 stage=$2
  python3 - "$dir" "$stage" <<'PY'
import hashlib, json, os, pathlib, stat, sys
root, stage = pathlib.Path(sys.argv[1]), sys.argv[2]
contracts = {
 "scan-redact-import": {"phase1/scan-admission.json":"scan-admission/v1","phase1/nuclei.sanitized.jsonl":"nuclei-sanitized-jsonl/v1","phase1/import-intent.json":"import-intent/v1","phase1/import-observation.json":"import-observation/v1"},
 "analysis-report":{"normalized.jsonl":"normalized-jsonl/v1","report.jsonl":"report-jsonl/v1"},
 "proposal":{"request-spec.json":"request-spec/v1"}, "approval":{"approval.json":"approval/v1"},
 "executor":{"request-descriptor.json":"request-descriptor/v1"},
 "verify-ci-artifact":{"trivy.admitted.json":"trivy-sanitized-json/v1","trivy.admitted.metadata.json":"trivy-metadata/v1"},
 "ci-normalize-import":{"trivy.normalized.jsonl":"normalized-jsonl/v1"}, }
required=contracts.get(stage,{})
if stage == "executor":
    audit = root / "audit-recovery.json"
    if audit.exists():
        required = {
            "audit-recovery.json": "audit-recovery/v1",
            "audit-recovery-report.json": "audit-recovery-report/v1",
            "audit-evaluation.json": "audit-evaluation/v1",
        }
    else:
        required = {"request-descriptor.json":"request-descriptor/v1"}
        try:
            receipt = json.loads((root / "receipt.json").read_text(encoding="utf-8"))
            schema = receipt.get("schema_version")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise SystemExit("invalid receipt checkpoint artifact") from exc
        if schema == "sentinel-charter-receipt/v1":
            required = {"receipt.json": "receipt/v1", **required}
        elif schema == "sentinel-charter-receipt/v2":
            required = {"receipt.json": "receipt/v2", **required}
        else:
            raise SystemExit("invalid receipt checkpoint artifact")
entries=[]
for relative, kind in required.items():
    path=root/relative; item=path.lstat()
    if path.is_symlink() or not stat.S_ISREG(item.st_mode) or stat.S_IMODE(item.st_mode)!=0o600: raise SystemExit("unsafe or missing checkpoint artifact: "+relative)
    data=path.read_bytes()
    if not data: raise SystemExit("empty checkpoint artifact: "+relative)
    entries.append({"path":relative,"type":kind,"sha256":hashlib.sha256(data).hexdigest()})
print(json.dumps({"entries":entries},sort_keys=True,separators=(",",":")))
PY
}

record_stage() {
  local dir=$1 stage=$2 status=$3 increments=$4 version checkpoint
  version=$("${MANIFEST_TOOL[@]}" read "$dir/manifest.json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["schema_version"])')
  if [[ "$version" == sentinel-run/v2 ]]; then
    if [[ "$status" == passed ]]; then
      checkpoint=$(checkpoint_for_stage "$dir" "$stage") || return
      "${MANIFEST_TOOL[@]}" stage-v2 "$dir/manifest.json" "$stage" "$status" "$increments" "$checkpoint"
    else
      "${MANIFEST_TOOL[@]}" stage-v2 "$dir/manifest.json" "$stage" "$status" "$increments"
    fi
  else
    "${MANIFEST_TOOL[@]}" stage "$dir/manifest.json" "$stage" "$status" "$increments"
  fi
}

require_private_artifact() {
  local path=$1
  [[ -f "$path" && ! -L "$path" ]] || die "required concrete artifact is absent: $(basename "$path")"
  chmod 600 "$path"
}

write_private_json_once() {
  local destination=$1 payload=$2
  python3 - "$destination" "$payload" <<'PY'
import json, os, sys, tempfile
from pathlib import Path

destination = Path(sys.argv[1])
try:
    value = json.loads(sys.argv[2])
except json.JSONDecodeError as exc:
    raise SystemExit(f"invalid controller JSON payload: {exc}")
if destination.exists() or destination.is_symlink():
    raise SystemExit(f"refusing to overwrite artifact: {destination.name}")
fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.link(temporary, destination)
    os.chmod(destination, 0o600)
except Exception:
    # link(2) either creates the exact staged inode or creates nothing; never
    # remove a caller-owned destination after an exclusive-create race.
    raise
finally:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
PY
}

publish_terminal_artifacts() {
  local dir=$1 manifest="$dir/manifest.json" doc action request_count receipt_hash=null request_spec_hash=null descriptor
  doc=$("${MANIFEST_TOOL[@]}" read "$manifest")
  require_private_artifact "$dir/normalized.jsonl"
  require_private_artifact "$dir/report.jsonl"
  read -r action request_count < <(python3 - "$doc" <<'PY'
import json, sys
d=json.loads(sys.argv[1]); print(str(d['result']['action_sent']).lower(), d['metrics']['request_count'])
PY
)
  if [[ -e "$dir/request-spec.json" ]]; then
    require_private_artifact "$dir/request-spec.json"
    "$CHARTER_PYTHON" - "$dir/request-spec.json" <<'PY' || die 'immutable request spec is invalid'
import json, sys
from pathlib import Path
from agent.charter_requests import load_spec
load_spec(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")))
PY
    request_spec_hash=$(hash_file "$dir/request-spec.json")
  fi
  if [[ "$action" == true ]]; then
    [[ "$request_spec_hash" != null ]] || die 'action-sent run requires an immutable request spec'
    descriptor="$dir/request-descriptor.json"
    require_private_artifact "$descriptor"
    if ! python3 - "$descriptor" <<'PY'
import json, sys
try: value=json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, json.JSONDecodeError): raise SystemExit(1)
raise SystemExit(0 if value == {"schema_version":"sentinel-request-descriptor/v1", "receipt":"receipt.json"} else 1)
PY
    then
      die 'action-sent run requires the exact concrete receipt descriptor'
    fi
    require_private_artifact "$dir/receipt.json"
    receipt_hash=$(hash_file "$dir/receipt.json")
  else
    [[ ! -e "$dir/receipt.json" && ! -e "$dir/request-descriptor.json" && ! -e "$dir/executor-state.sqlite" ]] || die 'zero-action run must not publish action evidence'
  fi
  write_private_json_once "$dir/request.json" "$(python3 - "$action" "$request_count" "$receipt_hash" <<'PY'
import json, sys
print(json.dumps({"schema_version":"charter-request-outcome/v1", "action_sent":sys.argv[1] == "true", "request_count":int(sys.argv[2]), "receipt_sha256":None if sys.argv[3] == "null" else sys.argv[3]}, separators=(",", ":")))
PY
)" || die 'could not safely publish request outcome'
  local manifest_hash normalized_hash report_hash request_hash output_hash run_id
  manifest_hash=$(hash_file "$manifest")
  normalized_hash=$(hash_file "$dir/normalized.jsonl")
  report_hash=$(hash_file "$dir/report.jsonl")
  request_hash=$(hash_file "$dir/request.json")
  read -r output_hash run_id < <(python3 - "$doc" <<'PY'
import json, sys
d=json.loads(sys.argv[1]); print(d['identity']['output_sha256'], d['run_id'])
PY
)
  write_private_json_once "$dir/artifact-bindings.json" "$(python3 - "$run_id" "$output_hash" "$manifest_hash" "$normalized_hash" "$report_hash" "$request_hash" "$receipt_hash" "$request_spec_hash" <<'PY'
import json, sys
print(json.dumps({"schema_version":"charter-artifact-bindings/v2", "run_id":sys.argv[1], "manifest_output_sha256":sys.argv[2], "manifest_sha256":sys.argv[3], "normalized_sha256":sys.argv[4], "report_sha256":sys.argv[5], "request_sha256":sys.argv[6], "receipt_sha256":None if sys.argv[7] == "null" else sys.argv[7], "request_spec_sha256":None if sys.argv[8] == "null" else sys.argv[8]}, separators=(",", ":")))
PY
)" || die 'could not safely publish artifact bindings'
}

evaluate_terminal_artifacts() {
  local dir=$1 evaluator="$HERE/../evaluation/charter-eval/result-report.py"
  "$CHARTER_PYTHON" "$evaluator" evaluate --run-dir "$dir" >/dev/null || return 1
  "$CHARTER_PYTHON" "$evaluator" verify --run-dir "$dir" >/dev/null
}

publish_ci_terminal() {
  "${MANIFEST_TOOL[@]}" ci-publish "$1/manifest.json"
}

publish_for_source() {
  local dir=$1 source=$2
  if [[ "$source" == ci ]]; then
    publish_ci_terminal "$dir"
  else
    publish_terminal_artifacts "$dir"
    evaluate_terminal_artifacts "$dir"
  fi
}

advance_stage() {
  local dir=$1 stage=$2 status
  if invoke_stage "$stage" "$dir"; then
    :
  else
    status=$?
    [[ "$status" == 76 ]] && return 76
    [[ "$stage" == approval && "$status" == 77 && "${APPROVAL_PREFLIGHT_REFUSED:-0}" == 1 ]] && return 77
    record_stage "$dir" "$stage" failed '{}'
    return 1
  fi
  case "$STAGE_OUTCOME" in
    passed) record_stage "$dir" "$stage" passed "$STAGE_METRICS" ;;
    rejected) record_stage "$dir" "$stage" rejected "$STAGE_METRICS"; return 10 ;;
    skipped) record_stage "$dir" "$stage" skipped "$STAGE_METRICS"; return 11 ;;
    failed) record_stage "$dir" "$stage" failed "$STAGE_METRICS"; return 1 ;;
  esac
}

run_all_stages() {
  local dir=$1 source=$2 stage result
  local -a ordered_stages=()
  # Components may legitimately use stdin.  Snapshot the controller-owned order
  # before invoking any of them so a child process cannot consume later stages.
  mapfile -t ordered_stages < <(stages_for "$source")
  for stage in "${ordered_stages[@]}"; do
    advance_stage "$dir" "$stage" || {
      result=$?
      [[ "$result" == 10 ]] && return 3
      [[ "$result" == 76 ]] && return 76
      return "$result"
    }
  done
  [[ "$source" == ci ]] || "${MANIFEST_TOOL[@]}" finalize "$dir/manifest.json"
}

run_new() {
  parse_run "$@"
  umask 077
  local dir="$RUNS/$RUN_ID" source=local input_type=local-charter-input input_version=1 input_digest resume_identity
  [[ ! -e "$dir" ]] || die 'run id already exists; use resume'
  if [[ -n "$ARTIFACT" ]]; then
    [[ -z "${SENTINEL_STAGE_ADAPTER:-}" && -z "${SENTINEL_COMPONENT_RUNNER:-}" ]] || die 'CI source refuses adapters'
    ci_artifact_ok || die 'invalid CI artifact metadata/digest'
    source=ci; input_type=trivy-sanitized-json; input_version=1; input_digest=$ARTIFACT_SHA
    SENTINEL_CI_METADATA_SHA256=$(hash_file "${ARTIFACT%.json}.metadata.json")
  else
    input_digest=$(hash_text 'local-charter-input')
  fi
  ensure_run_root "$source"
  immutable_hashes
  resume_identity=$(build_resume_identity "$source" "$input_digest")
  mkdir -m 700 "$dir"
  "${MANIFEST_TOOL[@]}" init-v2 "$dir/manifest.json" "$RUN_ID" "$source" "$input_type" "$input_version" "$input_digest" "$TARGET_SHA" "$CONFIG_SHA" "$POLICY_SHA" "$(stage_order_json "$source")" "$resume_identity"
  [[ "$source" != ci ]] || prepare_ci_snapshots "$dir" || die 'could not safely admit CI artifact'
  if run_all_stages "$dir" "$source"; then
    publish_for_source "$dir" "$source" || die 'could not publish terminal artifacts'
    return
  else
    local result=$?
    if [[ "$result" == 3 ]]; then
      publish_for_source "$dir" "$source" || die 'could not publish terminal rejection artifacts'
    fi
    [[ "$result" == 76 ]] && return 75
    return "$result"
  fi
}

verify() {
  local id=${1:-}
  safe_id "$id" || die 'safe run id required'
  guard_private_run_path "$id" || die 'unsafe private run path'
  local path="$RUNS/$id/manifest.json" source status
  "${MANIFEST_TOOL[@]}" verify "$path"
  read -r source status < <("${MANIFEST_TOOL[@]}" read "$path" | python3 -c 'import json,sys; value=json.load(sys.stdin); print(value["input"]["source"], value["result"]["status"])')
  [[ "$status" == passed ]] || die 'only passed terminal runs are verifiable'
  case "$source" in
    local) "$CHARTER_PYTHON" "$HERE/../evaluation/charter-eval/result-report.py" verify --run-dir "$RUNS/$id" ;;
    ci) "${MANIFEST_TOOL[@]}" ci-verify "$path" ;;
    *) die 'invalid manifest source' ;;
  esac
}

resume() {
  local id=${1:-}; shift || true
  safe_id "$id" || die 'safe run id required'
  guard_private_run_path "$id" || die 'unsafe private run path'
  parse_artifact_options "$@"
  local path="$RUNS/$id/manifest.json" doc source input_digest next_stage resume_identity schema
  doc=$("${MANIFEST_TOOL[@]}" read "$path")
  read -r schema source < <(python3 - "$doc" <<'PY'
import json, sys
d=json.loads(sys.argv[1]); print(d['schema_version'], d['input']['source'])
PY
)
  [[ "$schema" != sentinel-run/v1 ]] || die 'legacy manifest lacks exhaustive resume identity'
  if [[ "$source" == ci ]]; then
    [[ -z "${SENTINEL_STAGE_ADAPTER:-}" && -z "${SENTINEL_COMPONENT_RUNNER:-}" ]] || die 'CI source refuses adapters'
    [[ -n "$ARTIFACT" ]] || die 'CI resume requires its artifact and digest'
    ci_artifact_ok || die 'invalid CI artifact metadata/digest'
    input_digest=$ARTIFACT_SHA
    SENTINEL_CI_METADATA_SHA256=$(hash_file "${ARTIFACT%.json}.metadata.json")
  else
    [[ -z "$ARTIFACT" ]] || die 'local resume does not accept a CI artifact'
    input_digest=$(hash_text 'local-charter-input')
  fi
  immutable_hashes
  resume_identity=$(build_resume_identity "$source" "$input_digest")
  next_stage=$("${MANIFEST_TOOL[@]}" authorize-resume "$path" "$resume_identity") || die 'resume identity, checkpoint, effect, or resumable-state mismatch'
  local dir="$RUNS/$id"
  if [[ -z "$next_stage" ]]; then
    if [[ "$source" == ci ]]; then
      publish_ci_terminal "$dir"
    else
      "${MANIFEST_TOOL[@]}" finalize "$path" || die 'could not finalize terminal manifest'
      publish_for_source "$dir" "$source" || die 'could not publish terminal artifacts'
    fi
    return
  fi
  # Deliberately advance exactly the first missing stage; a later stage needs another resume.
  advance_stage "$dir" "$next_stage" || {
    local result=$?
    if [[ "$result" == 10 ]]; then
      publish_for_source "$dir" "$source" || die 'could not publish terminal rejection artifacts'
      return 3
    fi
    [[ "$result" == 76 ]] && return 75
    return "$result"
  }
  doc=$("${MANIFEST_TOOL[@]}" read "$path")
  if python3 - "$doc" <<'PY'
import json, sys
d=json.loads(sys.argv[1]); raise SystemExit(0 if len(d['stages']) == len(d['stage_order']) else 1)
PY
  then
    if [[ "$source" == ci ]]; then
      publish_ci_terminal "$dir"
    else
      "${MANIFEST_TOOL[@]}" finalize "$path" || die 'could not finalize terminal manifest'
      publish_for_source "$dir" "$source" || die 'could not publish terminal artifacts'
    fi
  else
    # State is intentionally still incomplete; reserve zero-success for a terminal run.
    return 75
  fi
}

recover_audit() {
  [[ "$#" -eq 1 ]] || die 'recover-audit requires exactly one safe run id'
  local id=$1 dir path doc result recovery_started audit_payload state audit_digest report_payload evaluation_payload event checkpoint
  safe_id "$id" || die 'safe run id required'
  guard_private_run_path "$id" || die 'unsafe private run path'
  dir="$RUNS/$id"; path="$dir/manifest.json"
  doc=$("${MANIFEST_TOOL[@]}" read "$path")
  result=$(python3 - "$doc" <<'PY'
import json, sys
value=json.loads(sys.argv[1])
if value["input"]["source"] != "local":
    raise SystemExit(1)
print(value["result"]["status"])
PY
  ) || die 'audit recovery requires a local manifest'
  if [[ "$result" == recovered ]]; then
    "${MANIFEST_TOOL[@]}" verify-audit-recovery "$path" || die 'existing audit recovery is not verifiable'
    return 0
  fi
  [[ "$result" == failed ]] || die 'audit recovery requires a stranded failed executor'
  state=$("$CHARTER_PYTHON" -m agent.charter_audit_recovery state "$dir") \
    || die 'audit recovery durable state is incomplete or inconsistent'
  if [[ "$state" == none ]]; then
    recovery_started=$("$CHARTER_PYTHON" - <<'PY'
import time
print(int(time.time() * 1000))
PY
)
    audit_payload=$("$CHARTER_PYTHON" -m agent.charter_audit_recovery acquire "$dir" "$recovery_started") \
      || die 'fixed Kong audit source did not prove exactly one bounded request'
    write_private_json_once "$dir/audit-recovery.json" "$audit_payload" \
      || die 'could not safely publish audit recovery artifact'
    state=audit-artifact-durable
  fi
  if [[ "$state" == audit-artifact-durable ]]; then
    "$CHARTER_PYTHON" -m agent.charter_audit_recovery terminalize "$dir" \
      || die 'could not terminalize the durable audit recovery'
    state=sqlite-terminal
  fi
  if [[ "$state" == sqlite-terminal ]]; then
    state=$("$CHARTER_PYTHON" -m agent.charter_audit_recovery state "$dir") \
      || die 'audit recovery durable state is incomplete or inconsistent'
    [[ "$state" == sqlite-terminal ]] || die 'audit recovery durable state advanced unexpectedly'
  fi
  if [[ "$state" == sqlite-terminal || "$state" == limited-artifacts-complete ]]; then
    audit_payload=$("$CHARTER_PYTHON" - "$dir/audit-recovery.json" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).read_text(encoding="utf-8").strip())
PY
) || die 'durable audit artifact is unreadable'
  else
    die 'audit recovery durable state is not resumable'
  fi
  audit_digest=$(hash_file "$dir/audit-recovery.json")
  report_payload=$(python3 - "$audit_payload" "$audit_digest" <<'PY'
import json, sys
audit=json.loads(sys.argv[1])
print(json.dumps({
 "schema_version":"sentinel-audit-recovery-report/v1",
 "request_id":audit["request_id"], "audit_sha256":sys.argv[2],
 "limitation":"gateway-transit-status-only",
}, sort_keys=True, separators=(",",":")))
PY
)
  evaluation_payload=$(python3 - "$audit_payload" "$audit_digest" <<'PY'
import json, sys
audit=json.loads(sys.argv[1])
print(json.dumps({
 "schema_version":"sentinel-audit-evaluation/v1",
 "request_id":audit["request_id"], "audit_sha256":sys.argv[2], "result":"limited",
 "limitation":"not-a-receipt-or-response-guard-evaluation",
}, sort_keys=True, separators=(",",":")))
PY
)
  if [[ "$state" == sqlite-terminal ]]; then
    write_private_json_once "$dir/audit-recovery-report.json" "$report_payload" \
      || die 'could not safely publish audit recovery report'
    write_private_json_once "$dir/audit-evaluation.json" "$evaluation_payload" \
      || die 'could not safely publish audit evaluation'
  fi
  state=$("$CHARTER_PYTHON" -m agent.charter_audit_recovery state "$dir") \
    || die 'audit recovery durable state changed before manifest publication'
  [[ "$state" == limited-artifacts-complete ]] \
    || die 'audit recovery limited artifacts are incomplete before manifest publication'
  event=$(python3 - "$dir/request-spec.json" "$dir/audit-recovery.json" <<'PY'
import hashlib, json, sys
from pathlib import Path
intent, observation = map(Path, sys.argv[1:])
print(json.dumps({
 "stage":"executor","effect":"charter-request","state":"recovered",
 "intent_path":"request-spec.json","intent_sha256":hashlib.sha256(intent.read_bytes()).hexdigest(),
 "observation_path":"audit-recovery.json","observation_sha256":hashlib.sha256(observation.read_bytes()).hexdigest(),
}, sort_keys=True, separators=(",",":")))
PY
)
  checkpoint=$(checkpoint_for_stage "$dir" executor) || die 'audit recovery artifact is not checkpointable'
  "${MANIFEST_TOOL[@]}" recover-audit "$path" "$event" "$checkpoint" || die 'could not bind audit recovery to the stranded manifest'
}

teardown() {
  local id=${1:-}
  safe_id "$id" || die 'safe run id required'
  guard_private_run_path "$id" || die 'unsafe private run path'
  local path="$RUNS/$id/manifest.json" doc resource_lines
  doc=$("${MANIFEST_TOOL[@]}" read "$path")
  resource_lines=$(python3 - "$doc" <<'PY'
import json, re, sys
d=json.loads(sys.argv[1]); pattern = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')
for r in d['resources']:
    if r['status'] == 'active':
        if r != {'owner':'controller', 'kind':'container', 'id':r['id'], 'status':'active'} or not pattern.fullmatch(r['id']):
            raise SystemExit(1)
        print(r['id'])
PY
  ) || die 'unsafe resource record'
  local -a ACTIVE_RESOURCES=()
  [[ -z "$resource_lines" ]] || mapfile -t ACTIVE_RESOURCES <<<"$resource_lines"
  [[ ${#ACTIVE_RESOURCES[@]} -eq 0 ]] && return 0
  [[ -n "${SENTINEL_RESOURCE_ADAPTER:-}" && -x "$SENTINEL_RESOURCE_ADAPTER" ]] || die 'active controller resources require a safe resource adapter'
  local resource
  for resource in "${ACTIVE_RESOURCES[@]}"; do
    "$SENTINEL_RESOURCE_ADAPTER" stop "$resource" || die "safe resource adapter refused $resource"
    "${MANIFEST_TOOL[@]}" release "$path" "$resource"
  done
}

case "${1:-}" in
  run) shift; run_new "$@" ;;
  verify) shift; verify "$@" ;;
  resume) shift; resume "$@" ;;
  recover-audit) shift; recover_audit "$@" ;;
  --teardown) shift; teardown "$@" ;;
  *) usage; exit 2 ;;
esac
