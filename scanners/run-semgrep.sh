#!/usr/bin/env bash
# Semgrep SAST wrapper (phase-03).
#   run-semgrep.sh <output.json>
# Scans TARGET_SRC with a MIRRORED, checksummed ruleset (no unpinned registry
# pull — a weakened rule silently drops findings). Emits Semgrep JSON (RAW —
# caller MUST pass through redact-report.sh; extra.lines carries matched source,
# including any literal secret). Image pinned by @sha256.
#
# Exit: 0 = clean, 1 = findings (SUCCESS for us), ≥2 = error.
set -euo pipefail

out="${1:?output json path required}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$HERE/image-pins.env" ] && . "$HERE/image-pins.env"

# Two run modes. Production = digest-pinned docker image. SEMGREP_BIN = a local
# semgrep binary (fallback when the container registry is unreachable — the pin
# guarantee then rests on the pip lock/venv, documented in README, not @sha256).
SEMGREP_BIN="${SEMGREP_BIN:-}"
if [ -z "$SEMGREP_BIN" ]; then
  SEMGREP_IMAGE="${SEMGREP_IMAGE:?SEMGREP_IMAGE unset — populate scanners/image-pins.env with a @sha256 digest (or set SEMGREP_BIN for a local binary)}"
  case "$SEMGREP_IMAGE" in *@sha256:*) : ;; *) echo "run-semgrep: SEMGREP_IMAGE must be @sha256-pinned" >&2; exit 4;; esac
fi

TARGET_SRC="${TARGET_SRC:?TARGET_SRC required (source tree to scan)}"
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

mkdir -p "$(dirname "$out")"
set +e
if [ -n "$SEMGREP_BIN" ]; then
  # Local-binary mode: run semgrep directly against the host paths.
  "$SEMGREP_BIN" scan --json --error --disable-version-check --metrics=off \
    --config "$RULESET" "$TARGET_SRC" >"$out"
else
  docker run --rm \
    -v "$TARGET_SRC":/src:ro \
    -v "$(cd "$(dirname "$RULESET")" && pwd)":/rules:ro \
    "$SEMGREP_IMAGE" \
    semgrep scan --json --error --disable-version-check --metrics=off \
      --config "/rules/$(basename "$RULESET")" /src >"$out"
fi
rc=$?
set -e

# 0=clean, 1=findings both fine; ≥2 is a real error.
if [ "$rc" -ge 2 ]; then echo "run-semgrep: error exit $rc" >&2; exit "$rc"; fi

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

echo "run-semgrep: wrote $out (exit $rc, scanned $scanned files, 0 errors)" >&2
