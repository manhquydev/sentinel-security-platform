#!/usr/bin/env bash
# Run the native scanners and land their findings in DefectDojo.
#
#   scan-and-import.sh                  scan every configured source and import
#   scan-and-import.sh gate <resp> <n>  gate one reimport response against a count
#   scan-and-import.sh decide <status>  print the close_old_findings decision
#
# The two subcommands are the seams the guards are tested through. They are not
# decoration: a gate that is only reachable by running four real scanners against
# a live instance is a gate nobody can prove works, and an unprovable guard on the
# path that mutates finding state is worse than none.
#
# Environment:
#   SCANNERS        space-separated subset of "semgrep trivy nuclei zap"
#                   (default: semgrep trivy nuclei — zap has never run live)
#   TARGET_SRC      source tree for the SAST/SCA scanners
#   TARGET_URL      URL for the DAST scanners
#   ALLOWLIST       fail-closed target guard, required by the DAST wrappers
#   SEMGREP_RULESET mirrored, checksummed ruleset
#   OUT_DIR         where raw and sanitized reports land (default scanners/out)
#   LOCK_FILE       serialisation lock (default OUT_DIR/.scan-and-import.lock)
#   DD_API_TOKEN    preferred; otherwise import-report.sh falls back to infra/.env
#
# Exit: 0 all configured sources landed; 1 at least one source failed;
#       75 another run holds the lock.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
SCANNERS_DIR="${SCANNERS_DIR:-$REPO_ROOT/scanners}"
OUT_DIR="${OUT_DIR:-$SCANNERS_DIR/out}"

# ---------------------------------------------------------------- gate --------
# Compare what DefectDojo accounted for against what the scanner reported.
#
# The count to compare against is NOT `created`. On every run after the first,
# deduplication files each finding as `untouched`, so created==0 while the import
# was completely successful. What must equal the reported count is the number of
# findings the import matched to the report: created + reactivated + untouched.
#
# `closed` is deliberately excluded. It counts findings in the PRIOR test that are
# ABSENT from this report and were mitigated as remediated — by construction they
# are not in `reported`. Adding them would false-fail every genuine remediation
# (report shrinks by one, closed grows by one, the sum stays flat while reported
# drops) and false-pass a run that matched nothing but closed everything. Both
# break the exact remediation path this gate exists to protect. `closed` is
# reported for visibility, never summed into the comparison.
#
# On the FIRST import into a newly created test DefectDojo omits `delta` entirely
# and returns only `after` — there is no previous state to diff against. A gate
# written solely against delta fails every time a test is created.
#
# `deduplication_complete` must be true. Deduplication runs asynchronously by
# default, and statistics read while it is still running describe a state that is
# about to change; import-report.sh requests async_wait so this should hold, and
# if it does not the numbers cannot be trusted.
gate_response() { # <response.json> <reported>
  local resp="$1" reported="$2"
  python3 - "$resp" "$reported" <<'PY'
import json, sys

resp_path, reported = sys.argv[1], int(sys.argv[2])
try:
    with open(resp_path) as fh:
        doc = json.load(fh)
except Exception as exc:
    print(f"gate: unreadable reimport response: {exc}", file=sys.stderr)
    raise SystemExit(1)

if doc.get("deduplication_complete") is not True:
    print("gate: deduplication did not complete — statistics describe a state still in flight",
          file=sys.stderr)
    raise SystemExit(1)

stats = doc.get("statistics") or {}
delta = stats.get("delta")


def total(block):
    return int(((block or {}).get("total") or {}).get("total") or 0)


if delta is None:
    parsed = total(stats.get("after"))
    basis = "statistics.after (first import into this test)"
    closed = 0
else:
    parsed = sum(total(delta.get(action))
                 for action in ("created", "reactivated", "untouched"))
    closed = total(delta.get("closed"))
    basis = "statistics.delta"

if parsed != reported:
    print(f"gate: {basis} matched {parsed} of the {reported} findings the scanner reported "
          f"(closed {closed})", file=sys.stderr)
    raise SystemExit(1)

print(f"gate: {parsed} == {reported} via {basis} (closed {closed})", file=sys.stderr)
PY
}

# ------------------------------------------------------------- decision -------
# Whether this import may close findings absent from the report.
#
# DefectDojo mitigates everything missing from an import, which is the correct
# reading of "the scanner looked and it is gone" and a catastrophic reading of
# "the scanner never looked". Three separate conditions must all hold, and any
# doubt resolves to false:
#   - the wrapper considered its own run trustworthy;
#   - it positively proved it reached the source or target;
#   - it actually reported findings. A zero-finding report is imported so the
#     lake reflects it, but it is never allowed to mitigate anything: an empty
#     report is exactly what a scanner pointed at nothing produces.
close_decision() { # <status.json>  -> prints true|false
  python3 - "$1" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as fh:
        st = json.load(fh)
except Exception:
    print("false"); raise SystemExit(0)
ok = (st.get("status") == "ok"
      and st.get("contact_proven") is True
      and isinstance(st.get("reported"), int)
      and st["reported"] > 0)
print("true" if ok else "false")
PY
}

# Whether an import would re-key the findings it touches.
#
# DefectDojo identifies a Semgrep finding by file_path + line + vuln_id_from_tool. A
# scanner that starts spelling paths differently re-keys everything it reports, and a
# close-enabled import then records a remediation for each old one. The active count does
# not move, so the exact-match drift check is structurally blind to it. Exposed as a
# subcommand for the same reason `gate` and `decide` are: the guards that can corrupt the
# lake have to be testable without a live instance.
rekey_suppresses_close() { # <incoming scheme> <lake scheme> -> prints true|false
  if [ "$1" = "relative" ] && [ "$2" = "absolute" ]; then echo true; else echo false; fi
}

# ---------------------------------------------------------- charter profile --
# The charter path is deliberately separate from the legacy shared OUT_DIR
# workflow below.  A raw scanner report can contain request/response material;
# it belongs in one private, controller-created run root and has no status
# sidecar or caller-selected output directory.
charter_state() { # <run-root>; never performs an import
  local root="${1:?charter run root required}"
  python3 - "$root" <<'PY'
import hashlib, json, pathlib, sys

root = pathlib.Path(sys.argv[1])
intent_path = root / "import-intent.json"
observation_path = root / "import-observation.json"
try:
    intent = json.loads(intent_path.read_text(encoding="utf-8"))
    request = intent.get("request")
    if (not isinstance(intent.get("run_id"), str) or not intent["run_id"]
            or not isinstance(intent.get("sanitized_sha256"), str)
            or not isinstance(request, dict)
            or request.get("close_old_findings") is not False):
        raise ValueError("invalid intent")
    sanitized = root / "nuclei.sanitized.jsonl"
    if (not sanitized.is_file()
            or hashlib.sha256(sanitized.read_bytes()).hexdigest() != intent["sanitized_sha256"]):
        raise ValueError("sanitized artifact does not match intent")
except Exception:
    print("import-outcome-unknown", file=sys.stderr)
    raise SystemExit(1)

try:
    observed = json.loads(observation_path.read_text(encoding="utf-8"))
    if (observed.get("state") != "completed"
            or observed.get("sanitized_sha256") != intent["sanitized_sha256"]
            or not isinstance(observed.get("remote_test_id"), (str, int))
            or not str(observed["remote_test_id"])
            or not isinstance(observed.get("response_sha256"), str)
            or not observed["response_sha256"]
            or not isinstance(observed.get("gate"), dict)
            or observed["gate"].get("state") != "passed"
            or not isinstance(observed["gate"].get("reported"), int)):
        raise ValueError("incomplete observation")
except Exception:
    # A POST may have completed just before a process crash.  Repeating it is a
    # mutation with an unknown prior outcome, so resume stops for later remote
    # reconciliation instead of performing a blind second reimport.
    print("import-outcome-unknown", file=sys.stderr)
    raise SystemExit(1)

print("completed")
PY
}

charter_write_intent() { # <root> <run-id> <sanitized-file>
  local root="$1" run_id="$2" sanitized="$3" tmp
  tmp="$(mktemp "$root/.import-intent.XXXXXX")"
  chmod 600 "$tmp"
  python3 - "$tmp" "$run_id" "$sanitized" <<'PY'
import hashlib, json, pathlib, sys

out = pathlib.Path(sys.argv[1])
run_id = sys.argv[2]
sanitized = pathlib.Path(sys.argv[3])
payload = {
    "state": "intent",
    "run_id": run_id,
    "scanner": "nuclei",
    "scan_type": "Nuclei Scan",
    "test_title": "Sentinel charter nuclei",
    "sanitized_sha256": hashlib.sha256(sanitized.read_bytes()).hexdigest(),
    "request": {
        "close_old_findings": False,
        "deduplication_execution_mode": "async_wait",
    },
}
pathlib.Path(out).write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
PY
  mv -f "$tmp" "$root/import-intent.json"
}

charter_write_observation() { # <root> <sanitized-file> <response-file> <reported>
  local root="$1" sanitized="$2" response="$3" reported="$4" tmp
  tmp="$(mktemp "$root/.import-observation.XXXXXX")"
  chmod 600 "$tmp"
  python3 - "$tmp" "$sanitized" "$response" "$reported" <<'PY'
import hashlib, json, pathlib, sys

out = pathlib.Path(sys.argv[1])
sanitized = pathlib.Path(sys.argv[2])
response = pathlib.Path(sys.argv[3])
reported = int(sys.argv[4])
try:
    body = response.read_bytes()
    doc = json.loads(body)
except Exception as exc:
    raise SystemExit(f"charter import response is not valid JSON: {exc}")
remote = doc.get("test") or doc.get("test_id") or doc.get("id")
if not isinstance(remote, (str, int)) or not str(remote):
    raise SystemExit("charter import response has no remote Test identity")
payload = {
    "state": "completed",
    "sanitized_sha256": hashlib.sha256(sanitized.read_bytes()).hexdigest(),
    "remote_test_id": remote,
    "response_sha256": hashlib.sha256(body).hexdigest(),
    "gate": {"state": "passed", "reported": reported},
}
out.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
PY
  mv -f "$tmp" "$root/import-observation.json"
}

charter_validate_prepared_import() { # <root>; closes the intent-to-POST mutation window
  python3 - "$1" <<'PY'
import hashlib, json, os, pathlib, stat, sys

root = pathlib.Path(sys.argv[1])
def load(name):
    path = root / name
    item = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(item.st_mode) or stat.S_IMODE(item.st_mode) != 0o600:
        raise ValueError(f"unsafe {name}")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise ValueError(f"duplicate key in {name}")
            value[key] = item
        return value
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)

try:
    admission, intent = load("scan-admission.json"), load("import-intent.json")
    sanitized = root / "nuclei.sanitized.jsonl"
    item = sanitized.lstat()
    if sanitized.is_symlink() or not stat.S_ISREG(item.st_mode) or stat.S_IMODE(item.st_mode) != 0o600:
        raise ValueError("unsafe sanitized artifact")
    digest = hashlib.sha256(sanitized.read_bytes()).hexdigest()
    if (set(admission) != {"schema_version", "run_id", "sanitized_path", "sanitized_sha256", "template_manifest_sha256", "runtime"}
            or admission["schema_version"] != "sentinel-scan-admission/v1"
            or not isinstance(admission["run_id"], str) or not admission["run_id"]
            or admission["sanitized_path"] != "nuclei.sanitized.jsonl"
            or admission["runtime"] != "nuclei"):
        raise ValueError("invalid scan admission")
    if (set(intent) != {"state", "run_id", "scanner", "scan_type", "test_title", "sanitized_sha256", "request"}
            or intent["state"] != "intent" or intent["run_id"] != admission["run_id"]
            or intent["scanner"] != "nuclei" or intent["scan_type"] != "Nuclei Scan"
            or intent["test_title"] != "Sentinel charter nuclei"
            or intent["request"] != {"close_old_findings": False, "deduplication_execution_mode": "async_wait"}
            or admission["sanitized_sha256"] != digest or intent["sanitized_sha256"] != digest):
        raise ValueError("prepared import no longer matches admitted input")
    if any(not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value)
           for value in (admission["sanitized_sha256"], admission["template_manifest_sha256"], intent["sanitized_sha256"])):
        raise ValueError("invalid prepared import digest")
except Exception as exc:
    raise SystemExit(f"invalid prepared charter import: {exc}")
PY
}

# These two commands are the controller-owned v2 seam.  The first is purely
# admission: it may scan and redact but has no import capability.  The second
# accepts only the fixed, already-admitted pair; it never creates an intent.
charter_admit() { # --run-root <private phase1> --run-id <id>
  [ "$#" -eq 4 ] && [ "$1" = --run-root ] && [ "$3" = --run-id ] || { echo 'scan-and-import: charter-admit --run-root ROOT --run-id ID' >&2; return 2; }
  local root=$2 run_id=$4 raw san tmp manifest_digest sanitized_digest
  case "$run_id" in *[!A-Za-z0-9._-]*|"") return 2;; esac
  [ -d "$root" ] && [ ! -L "$root" ] && [ "$(stat -c '%a' "$root")" = 700 ] || { echo 'scan-and-import: unsafe admission root' >&2; return 2; }
  umask 077
  raw=$(mktemp "$root/.raw.XXXXXX"); chmod 600 "$raw"
  if ! SENTINEL_PROFILE=charter CHARTER_RUN_ROOT="$root" TARGET_URL="${TARGET_URL:-}" "$SCANNERS_DIR/run-nuclei.sh" "$raw"; then
    echo 'scan-and-import: charter scan failed; private quarantine retained' >&2; return 1
  fi
  san="$root/nuclei.sanitized.jsonl"; [ ! -e "$san" ] || { echo 'scan-and-import: admission artifact already exists' >&2; return 1; }
  tmp=$(mktemp "$root/.sanitized.XXXXXX"); chmod 600 "$tmp"
  if ! CHARTER_ORIGIN=http://127.0.0.1:13000 "$SCANNERS_DIR/redact-report.sh" nuclei "$raw" "$tmp"; then
    rm -f "$tmp"; echo 'scan-and-import: charter redaction failed; private quarantine retained' >&2; return 1
  fi
  mv -f "$tmp" "$san"; chmod 600 "$san"
  sanitized_digest=$(sha256sum "$san" | awk '{print $1}')
  manifest_digest=$(sha256sum "$SCANNERS_DIR/charter-template-manifest.json" | awk '{print $1}')
  python3 - "$root/scan-admission.json" "$run_id" "$sanitized_digest" "$manifest_digest" <<'PY'
import json, os, sys
path, run_id, artifact, templates = sys.argv[1:]
value = {"schema_version":"sentinel-scan-admission/v1", "run_id":run_id,
         "sanitized_path":"nuclei.sanitized.jsonl", "sanitized_sha256":artifact,
         "template_manifest_sha256":templates,
         "runtime":"nuclei"}
fd=os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as out:
    json.dump(value,out,sort_keys=True,separators=(",",":")); out.write("\n"); out.flush(); os.fsync(out.fileno())
PY
  rm -f "$raw" "$root"/.nuclei-stderr.*
}

charter_import() { # --run-root <private phase1>
  [ "$#" -eq 2 ] && [ "$1" = --run-root ] || { echo 'scan-and-import: charter-import --run-root ROOT' >&2; return 2; }
  local root=$2 san="$2/nuclei.sanitized.jsonl" response reported lock fd importer
  [ -d "$root" ] && [ ! -L "$root" ] && [ "$(stat -c '%a' "$root")" = 700 ] || return 2
  [ -f "$root/scan-admission.json" ] && [ ! -L "$root/scan-admission.json" ] && [ -f "$root/import-intent.json" ] && [ ! -L "$root/import-intent.json" ] && [ -f "$san" ] && [ ! -L "$san" ] || return 1
  charter_state "$root" >/dev/null 2>&1 && { echo 'scan-and-import: already observed import is not replayable' >&2; return 1; }
  lock="${CHARTER_LOCK_FILE:-$(dirname "$root")/.charter-import.lock}"; exec {fd}>"$lock"
  flock -n "$fd" || return 75
  charter_validate_prepared_import "$root" || return 1
  response=$(mktemp "$root/.import-response.XXXXXX"); chmod 600 "$response"; importer="${CHARTER_IMPORT_REPORT:-$SCANNERS_DIR/import-report.sh}"
  if ! CLOSE_OLD_FINDINGS=false "$importer" 'Nuclei Scan' "$san" 'Sentinel charter nuclei' >"$response"; then
    echo 'scan-and-import: charter import outcome unknown; private quarantine retained' >&2; return 1
  fi
  reported=$(python3 - "$san" <<'PY'
import sys
print(sum(1 for line in open(sys.argv[1], encoding='utf-8') if line.strip()))
PY
)
  gate_response "$response" "$reported" || return 1
  charter_write_observation "$root" "$san" "$response" "$reported"
}

charter_run() {
  local run_id="" run_root="" raw san_tmp san response reported charter_lock_file charter_lock_fd charter_import_report
  case "${1:-}" in
    --resume)
      [ "$#" -eq 2 ] || { echo "scan-and-import: charter --resume <run-root>" >&2; return 2; }
      charter_state "$2"
      return $?
      ;;
    "") ;;
    --run-id)
      [ "$#" -eq 2 ] || { echo "scan-and-import: charter --run-id <id>" >&2; return 2; }
      run_id="$2"
      ;;
    *) echo "scan-and-import: charter [--run-id <id>] | charter --resume <run-root>" >&2; return 2 ;;
  esac
  run_id="${run_id:-$(date -u +%Y%m%dT%H%M%SZ)}"
  case "$run_id" in *[!A-Za-z0-9._-]*|"") echo "scan-and-import: unsafe charter run id" >&2; return 2;; esac

  # The run directory is intentionally selected and created here, not inherited
  # from OUT_DIR.  On scanner/redaction/import failure it remains a 0700
  # quarantine.  An operator may inspect it under the same-UID limitation and
  # erase it only after handling the failure: `rm -rf <charter-run-root>`.
  local runs_base="${CHARTER_RUNS_DIR:-$REPO_ROOT/scanners/charter-runs}"
  umask 077
  mkdir -p "$runs_base"
  chmod 700 "$runs_base"
  run_root="$(mktemp -d "$runs_base/${run_id}.XXXXXX")"
  chmod 700 "$run_root"

  raw="$(mktemp "$run_root/.raw.XXXXXX")"
  chmod 600 "$raw"
  if ! SENTINEL_PROFILE=charter CHARTER_RUN_ROOT="$run_root" TARGET_URL="${TARGET_URL:-}" \
      "$SCANNERS_DIR/run-nuclei.sh" "$raw"; then
    echo "scan-and-import: charter scan failed; private quarantine retained" >&2
    return 1
  fi

  san="$run_root/nuclei.sanitized.jsonl"
  san_tmp="$(mktemp "$run_root/.sanitized.XXXXXX")"
  chmod 600 "$san_tmp"
  if ! CHARTER_ORIGIN=http://127.0.0.1:13000 "$SCANNERS_DIR/redact-report.sh" nuclei "$raw" "$san_tmp"; then
    rm -f "$san_tmp"
    echo "scan-and-import: charter redaction failed; private quarantine retained" >&2
    return 1
  fi
  mv -f "$san_tmp" "$san"
  chmod 600 "$san"

  # All charter reimports address one fixed Test title.  Serialize from the
  # durable intent through response gate and terminal observation; a contending
  # controller must stop before it can POST or write a second intent.
  charter_lock_file="${CHARTER_LOCK_FILE:-$runs_base/.charter-import.lock}"
  exec {charter_lock_fd}>"$charter_lock_file"
  if ! flock -n "$charter_lock_fd"; then
    echo "scan-and-import: another charter run holds the import lock — refusing before import" >&2
    return 75
  fi

  charter_write_intent "$run_root" "$run_id" "$san"
  response="$(mktemp "$run_root/.import-response.XXXXXX")"
  chmod 600 "$response"
  charter_import_report="${CHARTER_IMPORT_REPORT:-$SCANNERS_DIR/import-report.sh}"
  # Charter imports never close old findings.  This explicit assignment prevents
  # a caller environment from changing the approved profile policy.
  if ! CLOSE_OLD_FINDINGS=false "$charter_import_report" "Nuclei Scan" "$san" "Sentinel charter nuclei" >"$response"; then
    echo "scan-and-import: charter import outcome unknown; private quarantine retained" >&2
    return 1
  fi
  reported="$(python3 - "$san" <<'PY'
import sys
print(sum(1 for line in open(sys.argv[1], encoding="utf-8") if line.strip()))
PY
)"
  if ! gate_response "$response" "$reported"; then
    echo "scan-and-import: charter completeness gate failed" >&2
    return 1
  fi
  # Completion is written only after the mandatory response gate has passed.
  # Until this point raw output and scanner stderr remain in the private run
  # root for recovery of any failed/unknown import outcome.
  charter_write_observation "$run_root" "$san" "$response" "$reported"
  if ! charter_state "$run_root" >/dev/null; then
    echo "scan-and-import: charter import outcome unknown; refusing a retry" >&2
    return 1
  fi
  # Sanitized artifact and import records are durable; erase raw scanner output
  # and stderr only after the complete charter success path.
  rm -f "$raw" "$run_root"/.nuclei-stderr.*
  local sanitized_digest manifest_digest
  sanitized_digest="$(sha256sum "$san" | awk '{print $1}')"
  manifest_digest="$(sha256sum "$SCANNERS_DIR/charter-template-manifest.json" | awk '{print $1}')"
  echo "scan-and-import: charter completed literal-origin template-manifest=$manifest_digest sanitized-sha256=$sanitized_digest" >&2
}

case "${1:-run}" in
  gate)
    gate_response "${2:?response json required}" "${3:?reported count required}"
    exit $?
    ;;
  decide)
    close_decision "${2:?status json required}"
    exit 0
    ;;
  rekey)
    rekey_suppresses_close "${2:?incoming scheme required}" "${3:?lake scheme required}"
    exit 0
    ;;
  charter-state)
    charter_state "${2:?charter run root required}"
    exit $?
    ;;
  charter-admit)
    shift; charter_admit "$@"; exit $?
    ;;
  charter-import)
    shift; charter_import "$@"; exit $?
    ;;
  charter)
    shift
    charter_run "$@"
    exit $?
    ;;
  run) ;;
  *) echo "scan-and-import: unknown subcommand '$1'" >&2; exit 2 ;;
esac

# ------------------------------------------------------------------ run -------
mkdir -p "$OUT_DIR"
LOCK_FILE="${LOCK_FILE:-$OUT_DIR/.scan-and-import.lock}"

# Serialise. A single writer is not the same as a serialised one: two overlapping
# runs reimporting the same test each compute "findings absent from my report"
# against a snapshot that already contains the other's work, and each closes what
# the other just created. Non-deterministic, silent, and indistinguishable from
# remediation afterwards.
exec {lock_fd}>"$LOCK_FILE"
if ! flock -n "$lock_fd"; then
  echo "scan-and-import: another run holds $LOCK_FILE — refusing to overlap" >&2
  exit 75
fi

SCANNERS="${SCANNERS:-semgrep trivy nuclei}"

scan_type_of() {
  case "$1" in
    semgrep) echo "Semgrep JSON Report" ;;
    trivy)   echo "Trivy Scan" ;;
    nuclei)  echo "Nuclei Scan" ;;
    zap)     echo "ZAP Scan" ;;
    *)       return 1 ;;
  esac
}

extension_of() {
  case "$1" in
    nuclei) echo jsonl ;;
    zap)    echo xml ;;
    *)      echo json ;;
  esac
}

failures=0
landed=0

for tool in $SCANNERS; do
  scan_type="$(scan_type_of "$tool")" || { echo "scan-and-import: unknown scanner '$tool'" >&2; failures=$((failures+1)); continue; }
  ext="$(extension_of "$tool")"
  raw="$OUT_DIR/$tool.$ext"
  san="$OUT_DIR/$tool.san.$ext"
  status_file="$raw.status.json"

  printf '\n--- %s ---\n' "$tool" >&2
  rm -f "$status_file"

  # The wrapper's exit code is deliberately NOT interpreted here. The four
  # wrappers overload their numeric space — the same code means "target rejected"
  # in one and "scanner error" in another — so a per-scanner whitelist over those
  # integers cannot be made sound. The sidecar is the contract.
  set +e
  "$SCANNERS_DIR/run-$tool.sh" "$raw"
  wrapper_rc=$?
  set -e

  if [ ! -s "$status_file" ]; then
    echo "scan-and-import: $tool produced no status sidecar (exit $wrapper_rc) — treating as failed, not as clean" >&2
    failures=$((failures+1))
    continue
  fi

  status="$(python3 -c 'import json,sys; print((json.load(open(sys.argv[1])).get("status") or "error"))' "$status_file" 2>/dev/null || echo error)"
  reported="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("reported", -1))' "$status_file" 2>/dev/null || echo -1)"

  if [ "$status" != "ok" ] || [ "$reported" -lt 0 ]; then
    echo "scan-and-import: $tool reported status=$status reported=$reported — skipping import and alerting" >&2
    failures=$((failures+1))
    continue
  fi

  # Guarded like the import and gate calls below: a redaction failure (missing
  # dependency, unreadable report) must fail this one source and move on, not
  # abort the whole loop under `set -e` and silently drop every later scanner.
  if ! "$SCANNERS_DIR/redact-report.sh" "$tool" "$raw" "$san"; then
    echo "scan-and-import: $tool redaction failed — skipping import" >&2
    failures=$((failures+1))
    continue
  fi

  close="$(close_decision "$status_file")"

  # Refuse to close when this report locates findings differently from the ones
  # already in the lake.
  #
  # DefectDojo identifies a Semgrep finding by file_path + line + vuln_id_from_tool.
  # Change how the scanner spells a path — an absolute host path versus a
  # repository-relative one — and every hash changes. The import then closes the
  # whole previous set as "remediated" and creates the same number of new findings.
  # Nothing was fixed, the active count is unchanged, and an exact-match drift check
  # sees a healthy lake. A count-based check cannot catch it by construction, so the
  # guard sits on the one decision that turns re-keyed findings into false history.
  #
  # Not hypothetical: this scanner's two run modes produced exactly that divergence
  # until the wrapper was made mode-independent, and findings imported before that
  # are still in the lake.
  if [ "$close" = "true" ]; then
    incoming_scheme="$(python3 - "$san" <<'SCHEME'
import json, sys
try:
    doc = json.load(open(sys.argv[1]))
except Exception:
    print("unknown"); raise SystemExit(0)
paths = [r.get("path") or r.get("file_path") or "" for r in (doc.get("results") or [])]
print("absolute" if any(p.startswith("/") for p in paths)
      else "relative" if paths else "empty")
SCHEME
)"
    lake_scheme="$(REPORT_SCAN_TYPE="$scan_type" "$HERE/verify-lake.sh" --locator-scheme 2>/dev/null || echo unknown)"
    if [ "$(rekey_suppresses_close "$incoming_scheme" "$lake_scheme")" = "true" ]; then
      echo "scan-and-import: $tool locates findings differently from those already in the lake" >&2
      echo "  (incoming=$incoming_scheme lake=$lake_scheme). Importing WITHOUT closing, so no" >&2
      echo "  remediation that did not happen is recorded. The existing findings need a" >&2
      echo "  one-time reconciliation — see scanners/README.md." >&2
      close=false
    fi
  fi
  resp="$OUT_DIR/$tool.import.json"
  if ! CLOSE_OLD_FINDINGS="$close" "$SCANNERS_DIR/import-report.sh" "$scan_type" "$san" "$scan_type" >"$resp"; then
    echo "scan-and-import: $tool import failed" >&2
    failures=$((failures+1))
    continue
  fi

  if ! gate_response "$resp" "$reported"; then
    echo "scan-and-import: $tool failed the completeness gate — the lake is missing findings this run produced" >&2
    failures=$((failures+1))
    continue
  fi

  landed=$((landed+1))
done

printf '\nscan-and-import: %d source(s) landed, %d failed\n' "$landed" "$failures" >&2
[ "$failures" -eq 0 ]
