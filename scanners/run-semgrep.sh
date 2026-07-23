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
CKSUM="$(dirname "$RULESET")/CHECKSUMS.txt"
if [ -f "$CKSUM" ]; then
  ( cd "$(dirname "$RULESET")" && sha256sum -c --quiet "$(basename "$CKSUM")" ) \
    || { echo "run-semgrep: ruleset checksum MISMATCH — refusing to scan with unverified rules" >&2; exit 6; }
else
  echo "run-semgrep: WARNING no CHECKSUMS.txt beside ruleset — cannot verify pin" >&2
fi

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
echo "run-semgrep: wrote $out (exit $rc)" >&2
