#!/usr/bin/env bash
# OWASP ZAP baseline DAST wrapper (phase-03).
#   run-zap.sh <output.xml>
# Passive baseline spider+scan of TARGET_URL. Emits ZAP XML (RAW — caller MUST
# pass through redact-report.sh before import; request/response blocks carry
# auth headers, cookies, CSRF). Target is allowlist-validated + IP-pinned.
#
# ZAP baseline exit codes: 0 = no findings above threshold, 1/2 = WARN/FAIL
# thresholds (findings present = SUCCESS for us), other = real error. The report
# is authoritative; we key success on "report produced", not the exit code.
set -euo pipefail

out="${1:?output xml path required}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$HERE/image-pins.env" ] && . "$HERE/image-pins.env"
ZAP_IMAGE="${ZAP_IMAGE:?ZAP_IMAGE unset — populate scanners/image-pins.env with a @sha256 digest}"
case "$ZAP_IMAGE" in *@sha256:*) : ;; *) echo "run-zap: ZAP_IMAGE must be @sha256-pinned" >&2; exit 4;; esac

TARGET_URL="${TARGET_URL:?TARGET_URL required}"
ALLOWLIST="${ALLOWLIST:?ALLOWLIST required (fail-closed target guard)}"
ZAP_MINUTES="${ZAP_MINUTES:-1}"   # spider budget; keep small for a local harness

pin="$(ALLOWLIST="$ALLOWLIST" "$HERE/target-allowlist.sh" validate "$TARGET_URL")" \
  || { echo "run-zap: target rejected by allowlist" >&2; exit 1; }

mkdir -p "$(dirname "$out")"
workdir="$(mktemp -d)"; trap 'rm -rf "$workdir"' EXIT
# zap runs as uid 1000 inside the container; grant that group write, not world
# write (a 777 mktemp is a local TOCTOU / symlink-plant window before the cp).
chmod 770 "$workdir"; chgrp 1000 "$workdir" 2>/dev/null || chmod 777 "$workdir"

# --network host so 127.0.0.1:13000 is the host harness. -I = do not fail on
# WARN. Report written into the mounted workdir, then copied to $out.
# (The validated pin is logged; forcing the scan onto that exact IP matters only
# for hostname targets and is a documented follow-up — the harness target is a
# literal loopback IP.)
set +e
docker run --rm --network host \
  -v "$workdir":/zap/wrk:rw \
  "$ZAP_IMAGE" \
  zap-baseline.py -t "$TARGET_URL" -m "$ZAP_MINUTES" -I -x report.xml
rc=$?
set -e

if [ -s "$workdir/report.xml" ]; then
  cp "$workdir/report.xml" "$out"
  echo "run-zap: wrote $out (zap exit $rc, pinned $pin)" >&2
else
  echo "run-zap: NO report produced (zap exit $rc) — treat as scanner error" >&2
  exit 5
fi
