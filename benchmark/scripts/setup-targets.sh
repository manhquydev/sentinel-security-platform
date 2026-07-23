#!/usr/bin/env bash
# Clone SAST targets as source only (no containers run). Pins each clone to a tag,
# then resolves and records the real commit SHA into a manifest for provenance.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARK_DIR="$(dirname "$SCRIPT_DIR")"
TARGETS_DIR="$BENCHMARK_DIR/targets"
MANIFEST="$BENCHMARK_DIR/targets/manifest.json"

OWASP_BENCHMARK_REPO="https://github.com/OWASP-Benchmark/BenchmarkJava.git"
# Verified via `git ls-remote --tags` 2026-07-21 (no plain "1.2" tag exists, only "1.2beta").
OWASP_BENCHMARK_TAG="${OWASP_BENCHMARK_TAG:-1.2beta}"

WEBGOAT_REPO="https://github.com/WebGoat/WebGoat.git"
# Confirmed via GitHub releases API 2026-07-21; override if a newer tag exists by then.
WEBGOAT_TAG="${WEBGOAT_TAG:-v2025.3}"

mkdir -p "$TARGETS_DIR"

clone_at_tag() {
  local repo="$1" tag="$2" dest="$3"
  if [ -d "$dest/.git" ]; then
    echo "[skip] $dest already cloned" >&2
  else
    git clone --branch "$tag" --depth 1 "$repo" "$dest" >&2
  fi
  git -C "$dest" rev-parse HEAD
}

echo "== OWASP Benchmark @ $OWASP_BENCHMARK_TAG =="
owasp_sha="$(clone_at_tag "$OWASP_BENCHMARK_REPO" "$OWASP_BENCHMARK_TAG" "$TARGETS_DIR/owasp-benchmark")"

echo "== WebGoat source @ $WEBGOAT_TAG (source only, container NOT started) =="
webgoat_sha="$(clone_at_tag "$WEBGOAT_REPO" "$WEBGOAT_TAG" "$TARGETS_DIR/webgoat-src")"

python3 - "$MANIFEST" "$OWASP_BENCHMARK_TAG" "$owasp_sha" "$WEBGOAT_TAG" "$webgoat_sha" <<'PY'
import json, sys, datetime
manifest_path, owasp_tag, owasp_sha, webgoat_tag, webgoat_sha = sys.argv[1:6]
data = {
    "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "owasp_benchmark": {"tag": owasp_tag, "sha": owasp_sha},
    "webgoat_src": {"tag": webgoat_tag, "sha": webgoat_sha},
}
with open(manifest_path, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
print(f"Manifest written to {manifest_path}")
PY

echo "Done. WebGoat container was NOT started (SAST only needs source)."
