"""How big is the inventory on production code that is mostly correct? The number that decides the product.

Every figure that makes the inventory framing look viable — 12.4% precision, 565 items, 92 file-level
decisions, 3x effort compression (E64, E71) — was measured on a benchmark where **38% of files carry a
defect** (E65). E65 and §22 already convicted this project once of comparing an effort figure across
corpora with different concentration. Precision and decision-volume are the same kind of quantity, and the
only organic datum so far points the wrong way: one real production file produced **98 findings** (E66).

If a mid-size production application yields hundreds of route handlers with no visible control, the
inventory dies regardless of precision — nobody attests to a thousand items. That outcome is available
here and would close a product direction this project has spent the day building.

WHAT THIS MEASURES, AND WHAT IT DELIBERATELY DOES NOT. Volume only: findings per repository, and the
**file-level decisions** a reviewer would face (E64 established the file is the unit of work). It needs
**no labels**, which is why it can run on real applications at all — the labelled organic set is stuck at
9 repositories (E70) while every repository that ever shipped an absence-class fix can be censused.
Precision on this population is a separate, harder measurement and is not attempted here.

The repositories are the production projects already identified by the advisory pipeline (E66/E70) — real
applications that shipped a real missing-authorization fix, so they are exactly the population a buyer
would point this tool at. They are cloned shallow into a scratch directory OUTSIDE the repository and
never committed, following the corpus policy in force.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/run_volume_census.py
"""

from __future__ import annotations

import json
import os
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

WORK = os.path.join(os.environ.get("TMPDIR", "/tmp"), "volume-census-clones")
MAX_REPOS = int(os.environ.get("CENSUS_MAX_REPOS", "14"))
CLONE_TIMEOUT = 240


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
        # A repository too large to clone in four minutes is skipped and COUNTED, not silently dropped:
        # excluding big projects would bias a volume census toward small ones, which is the direction
        # that flatters the product.
        shutil.rmtree(dest, ignore_errors=True)
        return "TIMEOUT"
    if r.returncode != 0:
        shutil.rmtree(dest, ignore_errors=True)
        return None
    return dest


def census(root: str) -> tuple[int, int, int, int, int]:
    """(python files, files with >=1 finding, findings, distinct sites, ROUTE DECLARATIONS anywhere).

    The last number decides whether the repository belongs in the population at all. A library with no
    HTTP routes cannot produce an access-control inventory, and averaging it in drags the median toward
    zero — which is exactly how the first run of this census printed "VIABLE" while the two actual web
    applications in the sample were carrying over a thousand sites each.
    """
    pyfiles = findings = routes = 0
    hit_files = 0
    sites = set()
    for dp, dirs, fns in os.walk(root):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "venv", "__pycache__")]
        for fn in fns:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(dp, fn)
            try:
                src = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            pyfiles += 1
            rel = os.path.relpath(path, root)
            routes += len(det.ROUTE.findall(src))
            fs = det.findings_for(src, rel)
            if fs:
                hit_files += 1
                findings += len(fs)
                sites |= {(rel, f["line"]) for f in fs}
    return pyfiles, hit_files, findings, len(sites), routes


def main() -> int:
    if not det.self_test():
        print("FAIL: detector self-test")
        return 2
    adv, _ = P.advisories()
    seen, targets = set(), []
    for _gid, owner, repo, _sha in P.fix_commits(adv):
        if (owner, repo) in seen:
            continue
        seen.add((owner, repo))
        targets.append((owner, repo))
        if len(targets) >= MAX_REPOS:
            break
    print(f"censusing {len(targets)} production repositories that shipped an absence-class fix\n")

    rows, skipped_big, skipped_other = [], [], []
    for owner, repo in targets:
        dest = clone(owner, repo)
        if dest == "TIMEOUT":
            skipped_big.append(f"{owner}/{repo}")
            print(f"  {owner}/{repo:<34} too large to clone in {CLONE_TIMEOUT}s — SKIPPED (counted)")
            continue
        if not dest:
            skipped_other.append(f"{owner}/{repo}")
            print(f"  {owner}/{repo:<34} clone failed — skipped")
            continue
        pyf, hitf, find, sites, routes = census(dest)
        if pyf < 5:
            skipped_other.append(f"{owner}/{repo}")
            print(f"  {owner}/{repo:<34} only {pyf} python files — skipped")
            continue
        rows.append({"repo": f"{owner}/{repo}", "python_files": pyf, "routes": routes,
                     "decision_files": hitf, "findings": find, "sites": sites,
                     "is_web_app": routes >= 20})
        kind = "web" if routes >= 20 else "lib"
        print(f"  {owner}/{repo:<34} {pyf:>5} py {routes:>5} routes  {hitf:>4} decisions "
              f"{sites:>5} sites  [{kind}]")

    if len(rows) < 5:
        print("FAIL: too few repositories censused")
        return 2

    # STRATIFY. The tool produces an access-control inventory; a repository with essentially no HTTP
    # routes is not in its market and must not be averaged in. 20 route declarations is the threshold and
    # it is arbitrary — the per-repo table is printed so any reader can move it.
    web = [r for r in rows if r["is_web_app"]]
    lib = [r for r in rows if not r["is_web_app"]]
    print(f"\n=== {len(rows)} repositories censused: {len(web)} web applications, {len(lib)} "
          f"libraries/tools with <20 routes ===")
    print("  Libraries are reported separately, not averaged in: they cannot produce an access-control")
    print("  inventory at all, and including them is what made the first run of this census print")
    print("  'VIABLE' while both real web applications carried over a thousand sites each.")
    if len(web) < 3:
        print(f"\n  FAIL: only {len(web)} web applications in the sample — cannot state a volume")
        return 2
    dec = sorted(r["decision_files"] for r in web)
    sit = sorted(r["sites"] for r in web)
    print(f"\n  WEB APPLICATIONS ({len(web)}):")
    for r in sorted(web, key=lambda r: -r["sites"]):
        print(f"    {r['repo']:<36} {r['routes']:>5} routes  {r['decision_files']:>4} decisions  "
              f"{r['sites']:>5} sites")
    print(f"\n  file-level DECISIONS per web app : median {statistics.median(dec):.0f}  "
          f"range [{dec[0]}, {dec[-1]}]")
    print(f"  route SITES per web app          : median {statistics.median(sit):.0f}  "
          f"range [{sit[0]}, {sit[-1]}]")
    print(f"  benchmark comparator (E64)       : {92/32:.1f} decisions, {565/32:.1f} sites per repo")

    # The kill condition, stated before the numbers were seen: an attestation inventory a human is
    # expected to work through cannot plausibly run to many hundreds of decisions per application.
    over_100 = sum(1 for d in dec if d > 100)
    over_300 = sum(1 for d in dec if d > 300)
    print(f"\n  repositories over 100 decisions: {over_100}/{len(dec)}   over 300: {over_300}/{len(dec)}")
    if skipped_big:
        print(f"  NOT censused because they were too large to clone: {len(skipped_big)} "
              f"({', '.join(skipped_big[:4])}) — these are the BIG applications, so the medians below "
              f"are biased DOWNWARD, i.e. toward the product looking viable")
    verdict = ("VIABLE AT THIS SCALE — the median application is a tractable attestation job"
               if statistics.median(dec) <= 100 else
               "INVENTORY TOO LARGE — the median production application exceeds a plausible "
               "attestation budget; the product framing needs scoping (per-service, per-diff) or dies")
    print(f"\n  {verdict}")
    print("  Volume only. Precision on this population is NOT measured here and is the separate,")
    print("  harder question; a small inventory that is mostly wrong is no better than a large one.")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(),
           "question": "how large is the inventory on real production applications, where most code is "
                       "correct — as opposed to a benchmark where 38% of files carry a defect?",
           "why": "every viability figure for the inventory framing (E64, E71) is a benchmark artefact "
                  "of defect concentration; E65/§22 convicted this project of exactly that error class",
           "population": "production repositories that shipped an absence-class security fix (E66/E70)",
           "labels_needed": False,
           "repositories": len(rows), "web_applications": len(web), "libraries": len(lib),
           "stratification": "repositories with >=20 route declarations are web applications; the rest "
                             "cannot produce an access-control inventory and are excluded from the "
                             "volume figures rather than averaged in",
           "median_decisions_per_repo": statistics.median(dec),
           "decisions_range": [dec[0], dec[-1]],
           "median_sites_per_repo": statistics.median(sit),
           "sites_range": [sit[0], sit[-1]],
           "repos_over_100_decisions": over_100, "repos_over_300_decisions": over_300,
           "benchmark_comparator_decisions_per_repo": round(92 / 32, 2),
           "verdict": verdict,
           "not_measured": "precision on this population",
           "skipped_too_large": skipped_big, "skipped_other": skipped_other,
           "bias_note": "repositories too large to clone were skipped; they are the big applications, so "
                        "reported medians are biased DOWNWARD — toward the product looking viable",
           "per_repo": rows}
    with open(os.path.join(_HERE, "volume-census-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
