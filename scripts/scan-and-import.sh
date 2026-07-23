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
SCANNERS_DIR="$REPO_ROOT/scanners"
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

case "${1:-run}" in
  gate)
    gate_response "${2:?response json required}" "${3:?reported count required}"
    exit $?
    ;;
  decide)
    close_decision "${2:?status json required}"
    exit 0
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
