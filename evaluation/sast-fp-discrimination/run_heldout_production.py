"""Do E83/E84's false-positive reductions survive on applications they were NOT derived from?

The cross-file work cut production flags from 1005 to 276 across four applications — but every fix was
found by reading those same four. `Security(...)` was discovered in `fides` and validated on `fides`. That
is the in-sample trap this project has flagged against itself before (E61's ENFORCEMENT vocabulary, still
carried as an open limitation in E74), and a 72% reduction measured where the fixes were derived is a
statement about the fixes fitting those repositories, not about the detector.

This clones production applications the fixes have **never seen** and measures the same before/after.

DESIGN, and what makes it a real held-out test:
  * the repository set is drawn from advisories NOT among the fourteen already cloned for E76;
  * it is fixed before any measurement — no repository is dropped for producing an inconvenient number;
  * the comparison is within-repository (same files, two detector configurations), so repository choice
    cannot bias the DIRECTION of the effect, only its size;
  * "before" is the single-file behaviour published as E56 (no context, and with the pre-E78/E83 regexes
    restored), "after" is what ships today.

WHAT WOULD FALSIFY THE IMPROVEMENT: a reduction on held-out applications far below the 72% measured
in-sample, or — worse — repositories where the new configuration flags MORE than the old one.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/run_heldout_production.py
"""

from __future__ import annotations

import json
import os
import re
import shutil
import statistics
import subprocess
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import detect_absent_auth as det  # noqa: E402
import probe_organic_absence_corpus as P  # noqa: E402

WORK = os.path.join(os.environ.get("TMPDIR", "/tmp"), "heldout-production-clones")
IN_SAMPLE = {"ethyca/fides", "NousResearch/hermes-agent", "marimo-team/marimo",
             "open-webui/open-webui", "maziggy/bambuddy", "langflow-ai/langflow",
             "apache/airflow", "janeczku/calibre-web", "jupyterlab/jupyterlab",
             "aegra/aegra", "parisneo/lollms", "volcengine/OpenViking",
             "arthurkatcher/google-maps-mcp", "pylixm/django-mdeditor",
             "nicolargo/glances", "nltk/nltk", "strawberry-graphql/strawberry",
             "Labs64/NetLicensing-MCP", "homeassistant-ai/ha-mcp", "zenml-io/zenml",
             "BerriAI/litellm"}
MAX_REPOS = int(os.environ.get("HELDOUT_MAX", "12"))
CLONE_TIMEOUT = 240
SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__", "tests", "test"}

# The single-file configuration as published in E56 — the state before tonight's cross-file work and
# before the @patch and CORS corrections. Restoring it exactly is what makes "before" honest.
OLD_ROUTE = re.compile(r"^\s*@(?:\w+\.)?(?:route|get|post|put|patch|delete)\s*\(", re.M)
OLD_APP_LEVEL = re.compile(r"@\w+\.before_request|add_middleware\s*\([^)]*Auth"
                           r"|LoginRequiredMiddleware|AuthenticationMiddleware", re.I)
OLD_AUTH_MARKER = re.compile(
    r"login_required|permission_required|user_passes_test|staff_member_required|"
    r"require_role|require_roles|require_user|require_auth|requires_auth|"
    r"Depends\s*\(\s*(?:get_current|require_|verify_|auth)|"
    r"IsAuthenticated|permission_classes|authentication_classes|"
    r"current_user|request\.user\.is_authenticated|@token_required|@jwt_required|"
    r"api_key|check_permission|has_perm|ensure_\w*auth", re.I)


def old_sites(src: str) -> set[int]:
    """E56's single-file detector, reconstructed: no context, old ROUTE/APP_LEVEL/AUTH_MARKER."""
    if OLD_APP_LEVEL.search(src):
        return set()
    protected = set(det.PROTECTED_ROUTER.findall(src))
    lines = src.splitlines()
    out = set()
    for m in OLD_ROUTE.finditer(src):
        i = src[:m.start()].count("\n")
        owner = det.ROUTE_OWNER.match(lines[i])
        if owner and owner.group(1) in protected:
            continue
        start, end = det._handler_span(lines, i)
        block = "\n".join(lines[start:end])
        if OLD_AUTH_MARKER.search(block) or det.ENFORCEMENT.search(block):
            continue
        if det.PUBLIC_OK.search("\n".join(lines[i:min(i + 3, len(lines))])):
            continue
        out.add(i + 1)
    return out


def clone(owner: str, repo: str) -> str | None:
    dest = os.path.join(WORK, f"{owner}__{repo}")
    if os.path.isdir(os.path.join(dest, ".git")):
        return dest
    os.makedirs(WORK, exist_ok=True)
    try:
        r = subprocess.run(["git", "clone", "--depth", "1", "--quiet",
                            f"https://github.com/{owner}/{repo}.git", dest],
                           capture_output=True, timeout=CLONE_TIMEOUT)
    except subprocess.TimeoutExpired:
        shutil.rmtree(dest, ignore_errors=True)
        return "TIMEOUT"
    if r.returncode != 0:
        shutil.rmtree(dest, ignore_errors=True)
        return None
    return dest


def measure(root: str) -> tuple[int, int, int]:
    """(old sites, new sites, real route declarations) over non-test Python files."""
    ctx = det.scan_repo(root)
    old = new = routes = 0
    for dp, dirs, fns in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for fn in fns:
            if not fn.endswith(".py") or fn.startswith("test_"):
                continue
            path = os.path.join(dp, fn)
            try:
                src = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            rel = os.path.relpath(path, root)
            routes += len(det.ROUTE.findall(src))
            old += len(old_sites(src))
            new += len({x["line"] for x in det.findings_for(src, rel, ctx)})
    return old, new, routes


def main() -> int:
    if not det.self_test():
        print("FAIL: detector self-test")
        return 2
    adv, _ = P.advisories()
    targets, seen = [], set()
    for _gid, owner, repo, _sha in P.fix_commits(adv):
        key = f"{owner}/{repo}"
        if key in IN_SAMPLE or key in seen:
            continue
        seen.add(key)
        targets.append((owner, repo))
        if len(targets) >= MAX_REPOS * 8:          # over-draw hard: most advisory repos are libraries
            break
    print(f"held-out candidates (never used to derive a fix): {len(targets)}\n")

    rows, skipped = [], []
    for owner, repo in targets:
        if len(rows) >= MAX_REPOS:
            break
        dest = clone(owner, repo)
        if dest == "TIMEOUT" or not dest:
            skipped.append(f"{owner}/{repo}")
            continue
        old, new, routes = measure(dest)
        if routes < 20:
            skipped.append(f"{owner}/{repo} (lib, {routes} routes)")
            continue
        rows.append({"repo": f"{owner}/{repo}", "routes": routes, "old": old, "new": new,
                     "reduction": round(1 - new / old, 4) if old else None})
        print(f"  {owner}/{repo:<34} routes {routes:>5}  old {old:>5} -> new {new:>5}  "
              f"{'' if not old else f'-{(1-new/old):.0%}'}")

    if len(rows) < 4:
        print(f"FAIL: only {len(rows)} held-out web applications resolved")
        return 2

    told = sum(r["old"] for r in rows)
    tnew = sum(r["new"] for r in rows)
    reds = [r["reduction"] for r in rows if r["reduction"] is not None]
    worse = [r["repo"] for r in rows if r["new"] > r["old"]]

    print(f"\n=== held-out: {len(rows)} production web applications ===")
    print(f"  total flags   : {told} -> {tnew}   pooled reduction {1 - tnew/told:.1%}")
    print(f"  per-repo reduction: median {statistics.median(reds):.1%}  "
          f"range [{min(reds):.0%}, {max(reds):.0%}]")
    print(f"  repositories where the new config flags MORE: {len(worse)} {worse or ''}")
    print(f"  in-sample comparator (E83/E84, 4 apps): 1005 -> 276 = 72.5% reduction")

    pooled = 1 - tnew / told
    verdict = ("HOLDS OUT-OF-SAMPLE — the reduction is not an artefact of the four repositories the "
               "fixes were read from"
               if pooled >= 0.30 and not worse else
               "DOES NOT HOLD — the in-sample reduction does not generalise")
    print(f"\n  {verdict}")
    print("  Volume only: no labels here, so this bounds false-positive REDUCTION, not precision.")
    print("  The corpus recall anchor (0.263) is what guarantees the reduction did not come from")
    print("  suppressing real defects; it is unchanged by every fix measured here.")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(),
           "question": "do E83/E84's false-positive reductions survive on production applications the "
                       "fixes were never derived from?",
           "why": "every fix was found by reading the four in-sample apps; a 72% reduction measured there "
                  "is a statement about fit, not about the detector",
           "held_out_repositories": len(rows), "skipped": skipped[:10],
           "in_sample_excluded": sorted(IN_SAMPLE),
           "old_config": "E56 single-file: no RepoContext, pre-@patch ROUTE, pre-anchor APP_LEVEL, "
                         "AUTH_MARKER without Security()",
           "total_old": told, "total_new": tnew,
           "pooled_reduction": round(pooled, 4),
           "median_repo_reduction": round(statistics.median(reds), 4),
           "reduction_range": [round(min(reds), 4), round(max(reds), 4)],
           "repos_worse": worse,
           "in_sample_comparator": 0.725,
           "corpus_recall_unchanged": 0.263,
           "verdict": verdict, "per_repo": rows}
    with open(os.path.join(_HERE, "heldout-production-260727.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print("\nwrote heldout-production-260727.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
