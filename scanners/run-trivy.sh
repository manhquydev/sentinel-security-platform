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

mkdir -p "$CACHE" "$(dirname "$out")"

# vuln scanning needs Trivy's downloadable DB; secret+misconfig work offline.
# Override with TRIVY_SCANNERS=secret,misconfig where the DB cannot be fetched.
TRIVY_SCANNERS="${TRIVY_SCANNERS:-vuln,secret,misconfig}"
common=(--format json --scanners "$TRIVY_SCANNERS" --quiet)

if [ -n "$TARGET_SRC" ]; then
  # Scan a source tree. Mount read-only; Trivy needs no write access to it.
  docker run --rm \
    -v "$TARGET_SRC":/src:ro \
    -v "$CACHE":/root/.cache/ \
    "$TRIVY_IMAGE" filesystem "${common[@]}" /src >"$out"
elif [ -n "$IMAGE" ]; then
  # Scan a container image via the host docker socket.
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$CACHE":/root/.cache/ \
    "$TRIVY_IMAGE" image "${common[@]}" "$IMAGE" >"$out"
else
  echo "run-trivy: set TARGET_SRC (fs) or IMAGE (image)" >&2; exit 2
fi

echo "run-trivy: wrote $out ($(wc -c <"$out") bytes)" >&2
