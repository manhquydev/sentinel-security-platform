#!/usr/bin/env bash
# Trivy SCA/secret scanner wrapper (phase-03).
#   run-trivy.sh <output.json>
# Scans TARGET_SRC (filesystem) when set, otherwise IMAGE. Emits Trivy JSON to
# <output.json> (RAW — the caller MUST pass it through redact-report.sh before
# import: Trivy secret findings embed the literal secret in Match/Code).
#
# Image pinned by @sha256 (mutable tag = supply-chain drift). Exit codes: Trivy
# returns 0 on success regardless of findings unless --exit-code is set; we do
# NOT set it, so 0=ok and any non-zero is a real error (P4 whitelists none here).
set -euo pipefail

out="${1:?output json path required}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Centralised @sha256 pins; fail closed if the image is not digest-pinned.
[ -f "$HERE/image-pins.env" ] && . "$HERE/image-pins.env"
TRIVY_IMAGE="${TRIVY_IMAGE:?TRIVY_IMAGE unset — populate scanners/image-pins.env with a @sha256 digest}"
case "$TRIVY_IMAGE" in *@sha256:*) : ;; *) echo "run-trivy: TRIVY_IMAGE must be @sha256-pinned, got $TRIVY_IMAGE" >&2; exit 4;; esac
TARGET_SRC="${TARGET_SRC:-}"
IMAGE="${IMAGE:-}"
CACHE="${TRIVY_CACHE_DIR:-$HOME/.cache/trivy}"
WORKBENCH_SOURCE_MOUNT="${WORKBENCH_SOURCE_MOUNT:-0}"
case "$WORKBENCH_SOURCE_MOUNT" in
  0|1) ;;
  *) echo "run-trivy: WORKBENCH_SOURCE_MOUNT must be 0 or 1" >&2; exit 2 ;;
esac

mkdir -p "$CACHE" "$(dirname "$out")"

# Status sidecar on every exit — see the note in run-semgrep.sh. Trivy proves
# contact BEFORE scanning (it reports no scanned-file count afterwards), so CONTACT
# is set true only once that check has passed.
STATUS="error"; CONTACT="false"; DETAIL="run did not complete"
emit_status() { local rc=$?; "$HERE/write-status.sh" trivy "$out" "$STATUS" "$CONTACT" "$rc" "$DETAIL" 2>/dev/null || true; }
trap emit_status EXIT

# vuln scanning needs Trivy's downloadable DB; secret+misconfig work offline.
# Override with TRIVY_SCANNERS=secret,misconfig where the DB cannot be fetched.
TRIVY_SCANNERS="${TRIVY_SCANNERS:-vuln,secret,misconfig}"
common=(--format json --scanners "$TRIVY_SCANNERS" --quiet)

if [ -n "$TARGET_SRC" ]; then
  # Proof of contact, checked BEFORE the scan because Trivy reports no scanned-file
  # count to check afterwards. An empty or wrong TARGET_SRC yields a valid,
  # findings-free report and exit 0 — indistinguishable from a genuinely clean tree,
  # and enough to mitigate a whole baseline as "remediated" if it is ever imported
  # with close_old_findings. This is weaker than Semgrep's post-scan paths.scanned:
  # it proves the directory had content, not that Trivy read it.
  if [ -z "$(find "$TARGET_SRC" -type f -print -quit 2>/dev/null)" ]; then
    echo "run-trivy: TARGET_SRC ($TARGET_SRC) contains no files — refusing to produce a would-be clean report" >&2
    exit 7
  fi
  CONTACT="true"   # the source tree had content to scan
  # Scan a source tree. Mount read-only; Trivy needs no write access to it.
  workbench_network=()
  [ "$WORKBENCH_SOURCE_MOUNT" = 1 ] && workbench_network=(--network none)
  docker run --rm "${workbench_network[@]}" \
    -v "$TARGET_SRC":/src:ro \
    -v "$CACHE":/root/.cache/ \
    "$TRIVY_IMAGE" filesystem "${common[@]}" /src >"$out"
elif [ -n "$IMAGE" ]; then
  if [ "$WORKBENCH_SOURCE_MOUNT" = 1 ]; then
    echo "run-trivy: Workbench source scans do not permit image/Docker-socket mode" >&2
    exit 2
  fi
  CONTACT="true"   # a named image to read is itself the contact
  # Scan a container image via the host docker socket.
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$CACHE":/root/.cache/ \
    "$TRIVY_IMAGE" image "${common[@]}" "$IMAGE" >"$out"
else
  echo "run-trivy: set TARGET_SRC (fs) or IMAGE (image)" >&2; exit 2
fi

# A non-empty, parseable report is required for a clean status; write-status.sh
# recounts from it and downgrades to error if it cannot be read.
[ -s "$out" ] || { echo "run-trivy: empty report" >&2; exit 5; }
STATUS="ok"; DETAIL="scanned $([ -n "$TARGET_SRC" ] && echo "$TARGET_SRC" || echo "$IMAGE")"
echo "run-trivy: wrote $out ($(wc -c <"$out") bytes)" >&2
