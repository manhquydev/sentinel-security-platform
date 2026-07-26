"""Can an organic absence-class corpus be built for free, or does it really need $30-50k of labelling?

This is owed item 1, the one validity threat no experiment in this project closes: every positive result
rests on a corpus of deliberately-vulnerable teaching applications, and nothing here represents real
production code. Sourcing research priced the options at $30-50k (NVD + expert labelling), $5-10k
(bug-bounty disclosures) or $15-25k (hand-built, which repeats the self-authorship bias this lab already
measured). All three were recorded as project-level budget decisions sitting above a research session.

That framing was too quick. The part that costs money is EXPERT LABELLING. This probe tests whether the
labelling is needed at all, because for this specific class of defect there is a free oracle:

    **the fix commit is the label.**

If a maintainer's security fix ADDS an authentication or authorization check to a route handler, then the
parent commit's version of that file is a confirmed CWE-306/862 site — file and line derivable from the
diff, and the judgement already made by the person who owned the code. No annotator, no inter-rater
agreement to negotiate, no $30-50k. The prior datasets' 20-71% label inaccuracy comes from inferring labels;
this infers nothing.

WHAT THIS SCRIPT MEASURES — feasibility, not a corpus. The yield at each stage of that pipeline:
advisories -> carrying a fix commit -> the commit touches Python -> the diff ADDS an auth/enforcement
marker -> the marker lands on a route handler. The last stage is the one that matters, because it is the
only one that produces a usable labelled site.

The auth vocabulary is deliberately the SAME one `detect_absent_auth` uses. That is a real limitation and
it is stated rather than hidden: a fix expressed in a form the detector cannot see will not be counted, so
this measures what is reachable BY THIS DETECTOR, and the true organic yield is at least this large.

WHAT WOULD FALSIFY THE FREE PATH: a yield low enough that the surviving sample cannot support a study —
in which case the paid options stand and this probe has priced the alternative honestly.

Fetched data is CACHED OUTSIDE THE REPOSITORY and never committed, following the corpus policy already in
force. Only the measurement is committed.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/probe_organic_absence_corpus.py
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE,):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import detect_absent_auth as det  # noqa: E402

CWES = (306, 862, 863, 639)
ECOSYSTEM = "pip"
PAGES = 3                 # bounded: 100 advisories per page per class
COMMIT_SAMPLE = 200       # bounded diff fetches — this is the expensive stage
CACHE = os.path.join(os.environ.get("TMPDIR", "/tmp"), "organic-absence-cache")

COMMIT_URL = re.compile(r"https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})")


def gh(path: str):
    """One authenticated GitHub API call, cached on disk outside the repository."""
    os.makedirs(CACHE, exist_ok=True)
    key = os.path.join(CACHE, re.sub(r"[^A-Za-z0-9]+", "_", path)[:180] + ".json")
    if os.path.exists(key):
        try:
            return json.load(open(key, encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    try:
        out = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    try:
        data = json.loads(out.stdout)
    except json.JSONDecodeError:
        return None
    with open(key, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return data


def advisories() -> dict:
    """Every pip advisory in the absence classes, deduplicated across classes by GHSA id."""
    seen = {}
    per_class = {}
    for cwe in CWES:
        n = 0
        for page in range(1, PAGES + 1):
            batch = gh(f"/advisories?ecosystem={ECOSYSTEM}&cwes={cwe}&per_page=100&page={page}")
            if not batch:
                break
            for a in batch:
                seen.setdefault(a["ghsa_id"], a)
                n += 1
            if len(batch) < 100:
                break
        per_class[cwe] = n
        print(f"  CWE-{cwe}: {n} advisories")
    return seen, per_class


def fix_commits(adv: dict) -> list[tuple[str, str, str, str]]:
    out = []
    for gid, a in adv.items():
        for ref in a.get("references") or []:
            m = COMMIT_URL.match(ref)
            if m:
                out.append((gid, m.group(1), m.group(2), m.group(3)))
                break
    return out


def main() -> int:
    if subprocess.run(["gh", "auth", "status"], capture_output=True).returncode != 0:
        print("FAIL: gh is not authenticated; this probe needs the GitHub API.")
        return 2
    if not det.self_test():
        print("FAIL: detector self-test")
        return 2

    print(f"advisories in the absence classes, ecosystem={ECOSYSTEM}:")
    adv, per_class = advisories()
    print(f"\ndistinct advisories across the four classes: {len(adv)}")

    commits = fix_commits(adv)
    print(f"carrying a resolvable GitHub fix commit: {len(commits)} = {len(commits)/max(len(adv),1):.1%}")

    sample = commits[:COMMIT_SAMPLE]
    print(f"\nfetching {len(sample)} diffs (bounded) …")
    touches_py = adds_marker = on_route = 0
    sites = 0
    found: list[dict] = []
    for gid, owner, repo, sha in sample:
        c = gh(f"/repos/{owner}/{repo}/commits/{sha}")
        if not c:
            continue
        pyfiles = [f for f in c.get("files") or [] if f.get("filename", "").endswith(".py")]
        if not pyfiles:
            continue
        touches_py += 1
        hit_marker = hit_route = False
        for f in pyfiles:
            patch = f.get("patch") or ""
            added = "\n".join(l[1:] for l in patch.splitlines() if l.startswith("+"))
            if not added:
                continue
            if det.AUTH_MARKER.search(added) or det.ENFORCEMENT.search(added):
                hit_marker = True
                # The removed/context side is the pre-fix file: a route there with the marker newly added
                # is exactly one labelled absence site.
                ctx = "\n".join(l[1:] if l.startswith((" ", "-")) else ""
                                for l in patch.splitlines())
                if det.ROUTE.search(ctx) or det.ROUTE.search(added):
                    hit_route = True
                    sites += 1
                    found.append({"advisory": gid, "owner": owner, "repo": repo,
                                  "file": f["filename"], "commit": sha,
                                  "parents": [pp["sha"] for pp in c.get("parents") or []]})
        adds_marker += 1 if hit_marker else 0
        on_route += 1 if hit_route else 0

    n = len(sample)
    print(f"\nyield through the pipeline (of {n} sampled fix commits):")
    print(f"  touch a Python file                     : {touches_py:>4} = {touches_py/max(n,1):.1%}")
    print(f"  ADD an auth/enforcement marker          : {adds_marker:>4} = {adds_marker/max(n,1):.1%}")
    print(f"  ...and that marker lands on a route     : {on_route:>4} = {on_route/max(n,1):.1%}")
    print(f"  labelled absence SITES extracted        : {sites}")

    # ------------------------------------------------------------------
    # THE TRANSFER TEST. Everything this project has measured about the detector comes from
    # deliberately-vulnerable teaching applications. These sites are the opposite: real defects in
    # production code, labelled by the maintainer who fixed them. Fetch each file AS IT WAS BEFORE THE
    # FIX and ask the detector the same question it is asked on the corpus.
    # ------------------------------------------------------------------
    repos_hit = len({(e["owner"], e["repo"]) for e in found})
    print("\ntransfer test — does the detector fire on the PRE-FIX version of these organic files?")
    fired = checked = 0
    detail = []
    for e in found:
        if not e["parents"]:
            continue
        blob = gh(f"/repos/{e['owner']}/{e['repo']}/contents/"
                  f"{e['file']}?ref={e['parents'][0]}")
        if not blob or "content" not in blob:
            continue
        import base64
        try:
            src = base64.b64decode(blob["content"]).decode("utf-8", "replace")
        except (ValueError, TypeError):
            continue
        checked += 1
        hits = det.findings_for(src, e["file"])
        fired += 1 if hits else 0
        detail.append({"repo": f"{e['owner']}/{e['repo']}", "file": e["file"],
                       "commit": e["commit"][:10], "detector_findings": len(hits)})
    for d in detail[:12]:
        mark = "FIRES" if d["detector_findings"] else "MISSES"
        print(f"  {mark:<7} {d['repo']:<32} {d['file'][:40]:<41} "
              f"{d['detector_findings']:>3} findings")
    # THE COMPARISON HAS TO BE AT THE SAME STANDARD. Quoting this against the corpus's 0.226 would be
    # wrong twice over: that figure is site-level (file AND CWE AND line, claim-once) while this is "the
    # detector fired somewhere in the file", and one organic file here produced 98 findings — firing is a
    # weak bar on a high-recall instrument. So the teaching corpus is re-measured at the SAME file level:
    # of its files that carry a ground-truth CWE-306/862 entry, on how many does the detector fire at all?
    import run_spike as rs
    cfired = cfiles = 0
    for slug in sorted(os.listdir(rs.REPOS)) if os.path.isdir(rs.REPOS) else []:
        root = os.path.join(rs.REPOS, slug)
        gt = rs.load_gt(slug) if os.path.isdir(root) else None
        if not gt:
            continue
        want = {g["file"].replace("\\", "/") for g in gt
                if g["is_vulnerable"] and (306 in g["cwes"] or 862 in g["cwes"])}
        for rel in want:
            path = os.path.join(root, rel)
            try:
                src = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            cfiles += 1
            cfired += 1 if det.findings_for(src, rel) else 0
    if checked:
        print(f"\n  ORGANIC   file-level firing: {fired}/{checked} = {fired/checked:.3f}"
              f"   ({repos_hit} distinct repositories)")
        if cfiles:
            print(f"  TEACHING  file-level firing: {cfired}/{cfiles} = {cfired/cfiles:.3f}"
                  f"   (same standard, same detector)")
            print("  Both are FILE level: 'the detector fired somewhere in this file'. That is a weak bar")
            print("  — one organic file produced 98 findings — and it is NOT the 0.226 site-level recall")
            print("  published for the corpus. What it supports is a transfer statement at file level")
            print("  only; whether the detector lands on the SPECIFIC route the maintainer fixed is not")
            print("  established here and needs the line mapping this probe does not do.")

    # Sites per commit, NOT commits-containing-a-site. The first version multiplied by the latter and
    # called the result sites, understating it — a commit that adds auth to five routes yields five.
    sites_per_commit = sites / max(n, 1)
    projected = int(round(len(commits) * sites_per_commit))
    print(f"\nsites per sampled commit: {sites}/{n} = {sites_per_commit:.3f}")
    print(f"projected over all {len(commits)} commit-linked advisories: ~{projected} labelled sites")
    print("Sample is the FIRST n commit-linked advisories, not a random draw, so the projection is")
    print("indicative only. Sites also CLUSTER by repository — one fix can add auth to many routes —")
    print("so the effective independent sample is nearer the repository count than the site count.")
    print("Compare with the corpus in use: 337 ground-truth CWE-306/862 entries, all from")
    print("deliberately-vulnerable teaching applications.")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(),
           "question": "can an organic absence-class corpus be built without paid expert labelling?",
           "method": "GitHub Security Advisories -> fix commit -> diff ADDS an auth/enforcement marker "
                     "on a route; the maintainer's fix IS the label, so nothing is inferred",
           "ecosystem": ECOSYSTEM, "cwes": list(CWES),
           "advisories_per_class": {str(k): v for k, v in per_class.items()},
           "distinct_advisories": len(adv), "with_fix_commit": len(commits),
           "sampled_commits": n, "touch_python": touches_py, "add_auth_marker": adds_marker,
           "marker_on_route": on_route, "labelled_sites_in_sample": sites,
           "sites_per_commit": round(sites_per_commit, 4),
           "projected_sites_all_commits": projected,
           "projection_caveat": "sample is the first n commit-linked advisories, not random; sites "
                                "cluster by repository so the independent unit is the repo, not the site",
           "limitation": "counts only fixes expressed in the vocabulary detect_absent_auth already knows, "
                         "so this is a LOWER BOUND on organic yield",
           "transfer_test": {"checked": checked, "fired": fired,
                             "organic_file_level_recall": round(fired / checked, 4) if checked else None,
                             "note": "pre-fix file versions of organic maintainer-labelled defects; "
                                     "FILE level, not the strict file+CWE+line standard used on the "
                                     "teaching corpus, and a much smaller sample",
                             "detail": detail,
                             "distinct_repositories": repos_hit,
                             "teaching_corpus_same_standard": {
                                 "files": cfiles, "fired": cfired,
                                 "file_level_firing": round(cfired / cfiles, 4) if cfiles else None},
                             "not_established": "whether the detector lands on the SPECIFIC route the "
                                                "maintainer fixed — file-level firing only"}}
    with open(os.path.join(_HERE, "organic-absence-probe-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
