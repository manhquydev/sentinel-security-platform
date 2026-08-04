#!/usr/bin/env bash
# Semgrep SAST wrapper (phase-03).
#   run-semgrep.sh <output.json>
# Scans TARGET_SRC with a MIRRORED, checksummed ruleset (no unpinned registry
# pull — a weakened rule silently drops findings). Emits Semgrep JSON (RAW —
# caller MUST pass through redact-report.sh; extra.lines carries matched source,
# including any literal secret). Image pinned by @sha256.
#
# Finding identity is mode-independent by construction (see README "Finding
# identity"). Semgrep derives `check_id` from the config file's directory
# relative to the process cwd, and emits `path` relative to whatever form the
# scan target argument took — both vary with the docker mount layout vs the
# local-binary host paths, and DefectDojo hashes Semgrep findings on exactly
# these two fields (+ line). Left alone, the same source tree scanned in the
# two modes produces two different finding identities: a later switch between
# modes would auto-mitigate every existing finding as "remediated" and
# recreate it, a fabricated event verify-lake.sh's active-count check cannot
# see (the total stays the same). This wrapper normalises both fields to be
# TARGET_SRC-relative and mount/host-path free before the report leaves this
# script, and fails closed (exit 9) if that normalisation does not hold.
#
# Exit: 0 = clean, 1 = findings (SUCCESS for us), ≥2 = error.
set -euo pipefail

out="${1:?output json path required}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$HERE/image-pins.env" ] && . "$HERE/image-pins.env"

# Emit the status sidecar on EVERY exit once a scan is plausible, so an
# orchestrator can tell "ran and failed" from "never ran". STATUS/CONTACT/DETAIL
# are updated as the run progresses; the trap publishes whatever they hold when
# the wrapper leaves, including on an early error exit. The out directory is
# created first so the trap can always write beside the report.
mkdir -p "$(dirname "$out")"
STATUS="error"; CONTACT="false"; DETAIL="run did not complete"
emit_status() { local rc=$?; "$HERE/write-status.sh" semgrep "$out" "$STATUS" "$CONTACT" "$rc" "$DETAIL" 2>/dev/null || true; }
trap emit_status EXIT

# Two run modes. Production = digest-pinned docker image. SEMGREP_BIN = a local
# semgrep binary (fallback when the container registry is unreachable — the pin
# guarantee then rests on the pip lock/venv, documented in README, not @sha256).
SEMGREP_BIN="${SEMGREP_BIN:-}"
if [ -z "$SEMGREP_BIN" ]; then
  SEMGREP_IMAGE="${SEMGREP_IMAGE:?SEMGREP_IMAGE unset — populate scanners/image-pins.env with a @sha256 digest (or set SEMGREP_BIN for a local binary)}"
  case "$SEMGREP_IMAGE" in *@sha256:*) : ;; *) echo "run-semgrep: SEMGREP_IMAGE must be @sha256-pinned" >&2; exit 4;; esac
fi
WORKBENCH_SOURCE_MOUNT="${WORKBENCH_SOURCE_MOUNT:-0}"
case "$WORKBENCH_SOURCE_MOUNT" in
  0|1) ;;
  *) echo "run-semgrep: WORKBENCH_SOURCE_MOUNT must be 0 or 1" >&2; exit 2 ;;
esac
if [ "$WORKBENCH_SOURCE_MOUNT" = 1 ] && [ -n "$SEMGREP_BIN" ]; then
  echo "run-semgrep: Workbench source scans require the pinned Docker path, not SEMGREP_BIN" >&2
  exit 4
fi
workbench_network=()
[ "$WORKBENCH_SOURCE_MOUNT" = 1 ] && workbench_network=(--network none)

TARGET_SRC="${TARGET_SRC:?TARGET_SRC required (source tree to scan)}"
TARGET_SRC_ABS="$(cd "$TARGET_SRC" 2>/dev/null && pwd)" \
  || { echo "run-semgrep: TARGET_SRC not found or not a directory: $TARGET_SRC" >&2; exit 2; }
# Mirrored ruleset path (a directory or .yml). Pinned + checksummed offline,
# NOT p/owasp-top-ten pulled live from the registry at scan time.
RULESET="${SEMGREP_RULESET:?SEMGREP_RULESET required (path to a mirrored/pinned ruleset)}"
[ -e "$RULESET" ] || { echo "run-semgrep: ruleset not found: $RULESET" >&2; exit 2; }

# Fail closed if the mirrored ruleset does not match its recorded checksum
# (a silently-weakened rule drops findings → false clean). CHECKSUMS.txt lives
# beside the ruleset and is verified from that directory.
#
# A MISSING CHECKSUMS.txt is fatal, not a warning. It is a small non-executable
# file — the easiest thing in this tree to lose to a sparse checkout, a partial
# artifact copy, or a narrow Docker build context. Warning-and-continuing turned
# the supply-chain control off exactly when it was needed, printed one line into a
# log nobody reads, and exited 0. Every other guard in this wrapper fails closed;
# this one now does too.
CKSUM="$(dirname "$RULESET")/CHECKSUMS.txt"
[ -f "$CKSUM" ] || { echo "run-semgrep: no CHECKSUMS.txt beside ruleset — refusing to scan with an unverifiable pin" >&2; exit 6; }
( cd "$(dirname "$RULESET")" && sha256sum -c --quiet "$(basename "$CKSUM")" ) \
  || { echo "run-semgrep: ruleset checksum MISMATCH — refusing to scan with unverified rules" >&2; exit 6; }

# Same-directory config reference, used in BOTH modes below. Semgrep prefixes
# check_id with the config file's directory path relative to the process cwd
# ("scanners.rulesets.<id>" locally, "rules.<id>" under the /rules docker
# mount) — an artifact of where the ruleset happens to live on disk, not of
# the rule itself. Running with cwd == the ruleset's own directory and
# referencing the config by basename collapses that prefix to nothing in
# both modes, verified empirically for the local path (see README).
RULESET_DIR="$(cd "$(dirname "$RULESET")" && pwd)"
RULESET_REF="$(basename "$RULESET")"

mkdir -p "$(dirname "$out")"
set +e
if [ -n "$SEMGREP_BIN" ]; then
  # Local-binary mode: cwd = ruleset dir (bare check_id); target passed
  # absolute so `path` normalisation below has a fixed prefix to strip.
  ( cd "$RULESET_DIR" && "$SEMGREP_BIN" scan --json --error --disable-version-check --metrics=off \
      --config "$RULESET_REF" "$TARGET_SRC_ABS" ) >"$out"
else
  # Docker mode: -w /rules makes the container's cwd equal the mounted
  # ruleset directory, the same geometry as the local branch above (Docker's
  # -w is a guaranteed override of the image's own WORKDIR).
  docker run --rm "${workbench_network[@]}" \
    -v "$TARGET_SRC_ABS":/src:ro \
    -v "$RULESET_DIR":/rules:ro \
    -w /rules \
    "$SEMGREP_IMAGE" \
    semgrep scan --json --error --disable-version-check --metrics=off \
      --config "$RULESET_REF" /src >"$out"
fi
rc=$?
set -e

# 0=clean, 1=findings both fine; ≥2 is a real error.
if [ "$rc" -ge 2 ]; then echo "run-semgrep: error exit $rc" >&2; exit "$rc"; fi

# Normalise `path` and `check_id` — the two fields (with `line`) DefectDojo
# hashes Semgrep findings on — to be identical regardless of run mode:
#   path:      strip the mode-specific target prefix ("/src" under docker,
#              TARGET_SRC_ABS locally) so what remains is TARGET_SRC-relative
#              in both modes, and never carries a host absolute path (which
#              would leak the OS username into the lake).
#   check_id:  assert it is a bare id declared in $RULESET. The cwd/basename
#              construction above is expected to already make this true; this
#              is a fail-closed check, not a silent rewrite, so a future
#              Semgrep version changing its prefixing heuristic is caught
#              here instead of silently reintroducing mode-dependent identity.
STRIP_PREFIX="/src"; [ -n "$SEMGREP_BIN" ] && STRIP_PREFIX="$TARGET_SRC_ABS"
python3 - "$out" "$RULESET" "$STRIP_PREFIX" <<'PY' || exit 9
import json, os, sys
import yaml

out_path, ruleset_path, strip_prefix = sys.argv[1], sys.argv[2], sys.argv[3]

with open(ruleset_path) as f:
    spec = yaml.safe_load(f) or {}
declared_ids = {r.get("id") for r in (spec.get("rules") or []) if r.get("id")}

with open(out_path) as f:
    report = json.load(f)

prefix = strip_prefix.rstrip("/") + "/"
for r in report.get("results", []):
    p = r.get("path", "")
    if not p.startswith(prefix):
        print(f"run-semgrep: path {p!r} does not start with expected {prefix!r} "
              "-- mode-independent path normalisation assumption broken", file=sys.stderr)
        sys.exit(1)
    r["path"] = p[len(prefix):]
    cid = r.get("check_id", "")
    if cid not in declared_ids:
        print(f"run-semgrep: check_id {cid!r} is not a bare id from {ruleset_path} "
              "-- a directory-derived prefix leaked through; finding identity "
              "would differ between docker and local-binary mode", file=sys.stderr)
        sys.exit(1)

tmp = out_path + ".norm.tmp"
with open(tmp, "w") as f:
    json.dump(report, f)
os.replace(tmp, out_path)
PY

# Proof of contact, read from the RAW report — the redactor blanks `errors` and a
# count taken from the sanitized file would describe a scan that never happened.
#
# Two ways a semgrep run exits 0 having found nothing while being badly broken:
# TARGET_SRC resolved to an empty or wrong directory (paths.scanned empty), or a
# large share of the tree failed to parse (errors populated, results silently
# short). Either one, imported with close_old_findings, mitigates real findings as
# remediated. Both fail the run here instead.
read -r scanned errcount <<EOF
$(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("-1 -1"); raise SystemExit(0)
print("%d %d" % (len((d.get("paths") or {}).get("scanned") or []), len(d.get("errors") or [])))
' "$out")
EOF

if [ "$scanned" -lt 0 ] 2>/dev/null; then
  echo "run-semgrep: report is missing or unparseable — not a clean scan" >&2; exit 7
fi
if [ "$scanned" -eq 0 ]; then
  echo "run-semgrep: scanned 0 files — TARGET_SRC ($TARGET_SRC) is empty or wrong; refusing to call this a clean scan" >&2
  exit 7
fi
if [ "$errcount" -gt 0 ]; then
  echo "run-semgrep: $errcount parse/rule errors — results are incomplete and must not close findings" >&2
  exit 8
fi

# paths.scanned>0 with an empty errors array is positive proof semgrep read the
# tree, so contact is established and the run is trustworthy.
STATUS="ok"; CONTACT="true"; DETAIL="scanned $scanned files, 0 errors"
echo "run-semgrep: wrote $out (exit $rc, scanned $scanned files, 0 errors)" >&2
