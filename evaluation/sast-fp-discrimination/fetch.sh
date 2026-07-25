#!/usr/bin/env bash
# Fetch the RealVuln FP-trap corpus (Apache-2.0) at eval time — NEVER committed (the benchmark/targets/
# pattern). Shallow-clones the RealVuln repo, then the pinned per-repo commit SHAs from ITS manifest.
# Fail-closed: a clone that drifts from the pinned SHA aborts. Bounded by $SUBSET (a committed list of
# repo names for the viability spike; empty = all 66). See docs/ai-sast-verifier-design.md §5.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORPUS="$HERE/corpus"
REALVULN="https://github.com/kolega-ai/Real-Vuln-Benchmark"
mkdir -p "$CORPUS"

# 1. The benchmark repo (ground truth + its manifest of pinned repo SHAs).
if [ ! -d "$CORPUS/Real-Vuln-Benchmark/.git" ]; then
  git clone --depth 1 "$REALVULN" "$CORPUS/Real-Vuln-Benchmark"
fi
MANIFEST="$CORPUS/Real-Vuln-Benchmark/benchmark-manifest.json"
[ -f "$MANIFEST" ] || { echo "FAIL: RealVuln manifest not found at $MANIFEST"; exit 2; }

# 2. Shallow-clone each target repo at its PINNED sha (subset for the spike, or all).
SUBSET_FILE="$HERE/spike-subset.txt"   # committed: repo slugs for the bounded viability spike
"$HERE/../../rag/.venv/bin/python" - "$MANIFEST" "${SUBSET_FILE}" "$CORPUS" <<'PY'
import json, os, shutil, subprocess, sys
manifest, subset_file, corpus = sys.argv[1], sys.argv[2], sys.argv[3]
repos = json.load(open(manifest))["repos"]   # dict: slug -> {repo_url, commit_sha, ...}
subset = {l.strip() for l in open(subset_file)} if os.path.exists(subset_file) else set()
subset = {s for s in subset if s and not s.startswith("#")}
picked = {k: v for k, v in repos.items() if not subset or k in subset}
print(f"fetching {len(picked)}/{len(repos)} repos (subset={'all' if not subset else len(subset)})")
for name, r in picked.items():
    url, sha = r.get("repo_url"), r.get("commit_sha")
    if not (url and sha):
        print(f"  SKIP malformed entry {name}: {r}"); continue
    dst = os.path.join(corpus, "repos", name)
    if os.path.isdir(os.path.join(dst, ".git")):
        continue
    os.makedirs(dst, exist_ok=True)
    try:
        subprocess.run(["git", "init", "-q", dst], check=True)
        subprocess.run(["git", "-C", dst, "fetch", "-q", "--depth", "1", url, sha],
                       check=True, capture_output=True)
        subprocess.run(["git", "-C", dst, "checkout", "-q", "FETCH_HEAD"], check=True)
    except subprocess.CalledProcessError:
        # A single unavailable/placeholder upstream repo must not abort the whole fetch — skip it.
        shutil.rmtree(dst, ignore_errors=True)
        print(f"  SKIP {name}: upstream unreachable ({url})")
        continue
    got = subprocess.check_output(["git", "-C", dst, "rev-parse", "HEAD"]).decode().strip()
    if got[:12] != sha[:12]:
        print(f"  FAIL: {name} drifted from pinned sha {sha[:12]} (got {got[:12]})"); sys.exit(2)
    print(f"  {name} @ {sha[:12]}")
PY
echo "corpus ready at $CORPUS (gitignored)"
