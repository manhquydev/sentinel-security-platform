#!/usr/bin/env bash
# Clone + install SAIST (primary engine) and Metis (cross-check engine) at pinned
# commit SHAs. The pins are literal commits, not "main": a floating ref silently
# changes the engine under a benchmark whose whole point is comparability across
# runs. Override via SAIST_REF / METIS_REF only to move a pin deliberately.
#
# Metis is patched in this tree (usage-file uniqueness; see
# src/metis/usage/runtime.py). This script therefore refuses to check out over a
# dirty working tree instead of reverting the patch behind the operator's back,
# and benchmark/scripts/preflight.sh asserts both the pin and the patch before
# any run.
#
# This script only installs the tools. It does NOT run a scan and does NOT need any
# API key. Do not run the Step-0 spike until the provider key (ROUTER_API_KEY, and,
# if SAIST is kept as primary engine, DD_API_KEY/DD_APP_KEY per
# runs/spike-engine-endpoint.md) are set.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARK_DIR="$(dirname "$SCRIPT_DIR")"
TOOLS_DIR="$BENCHMARK_DIR/tools"
MANIFEST="$BENCHMARK_DIR/tools/manifest.json"

SAIST_REPO="https://github.com/DataDog/datadog-saist.git"
SAIST_REF="${SAIST_REF:-7dbdb5a71d562bbc974c93699b903cfba77d6d8a}"

METIS_REPO="https://github.com/arm/metis.git"
METIS_REF="${METIS_REF:-e5320d77ea02db3e9a078c24f4e67b25f0948640}"

mkdir -p "$TOOLS_DIR"

clone_at_ref() {
  local repo="$1" ref="$2" dest="$3"
  if [ ! -d "$dest/.git" ]; then
    git clone "$repo" "$dest" >&2
    git -C "$dest" checkout "$ref" >&2
  elif [ "$(git -C "$dest" rev-parse HEAD)" = "$(git -C "$dest" rev-parse "$ref^{commit}" 2>/dev/null || echo none)" ]; then
    echo "[ok] $dest already at $ref" >&2
  elif [ -n "$(git -C "$dest" status --porcelain)" ]; then
    echo "[FAIL] $dest is at a different commit AND has local modifications." >&2
    echo "       Checking out $ref would discard them (the vendored Metis patch lives here)." >&2
    echo "       Resolve by hand: re-apply the patch on top of $ref, or move the pin." >&2
    exit 1
  else
    git -C "$dest" fetch --quiet origin "$ref" 2>/dev/null || git -C "$dest" fetch --quiet origin
    git -C "$dest" checkout "$ref" >&2
  fi
  git -C "$dest" rev-parse HEAD
}

echo "== SAIST @ $SAIST_REF =="
saist_sha="$(clone_at_ref "$SAIST_REPO" "$SAIST_REF" "$TOOLS_DIR/datadog-saist")"
echo "[note] SAIST requires DD_API_KEY + DD_APP_KEY (Datadog account) even for local scans;"
echo "       this is separate from the DeepSeek/LiteLLM LLM key. Confirm with user first."

echo "== Metis @ $METIS_REF =="
metis_sha="$(clone_at_ref "$METIS_REPO" "$METIS_REF" "$TOOLS_DIR/arm-metis")"
if command -v uv >/dev/null 2>&1; then
  (cd "$TOOLS_DIR/arm-metis" && [ -d .venv ] || uv venv >&2 && uv pip install --python .venv '.[all-providers]' >&2)
else
  echo "[warn] 'uv' not found; skipping Metis dependency install. Run manually:"
  echo "       cd $TOOLS_DIR/arm-metis && uv venv && uv pip install --python .venv '.[all-providers]'"
fi

python3 - "$MANIFEST" "$SAIST_REF" "$saist_sha" "$METIS_REF" "$metis_sha" <<'PY'
import json, sys, datetime
manifest_path, saist_ref, saist_sha, metis_ref, metis_sha = sys.argv[1:6]
data = {
    "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "saist": {"ref": saist_ref, "sha": saist_sha},
    "metis": {"ref": metis_ref, "sha": metis_sha},
}
with open(manifest_path, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
print(f"Manifest written to {manifest_path}")
PY
