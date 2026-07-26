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

# 306/862/863/639 are the canonical absence classes. 285 and 284 ("Improper Access Control") were added
# after a sources review found them indexed by the same API and far denser in DISTINCT repositories — the
# binding constraint here is repository count, not advisory count (E69).
CWES = (306, 862, 863, 639, 285, 284)
ECOSYSTEM = "pip"
COMMIT_SAMPLE = 600       # bounded diff fetches — this is the expensive stage
CACHE = os.path.join(os.environ.get("TMPDIR", "/tmp"), "organic-absence-cache")

COMMIT_URL = re.compile(r"https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})")
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@")
LINE_TOL = 10          # the project matcher's tolerance, reused so the number is comparable


def protected_route_lines(patch: str) -> list[int]:
    """OLD-file line numbers of route handlers that this diff ADDS a control to.

    This is what turns a fix commit into a labelled SITE rather than a labelled file. Walking each hunk
    and tracking the old-file line counter gives, for every added auth/enforcement marker, the nearest
    route declaration at or above it that already EXISTED before the fix.

    A route that is itself added by the diff is skipped: a brand-new protected endpoint is not evidence
    that an old one was unprotected, and counting it would manufacture sites the corpus never had.
    """
    out, old, route_at = [], 0, None
    # Also record where markers were inserted, so the enclosing handler can be found in the pre-fix
    # SOURCE when the route decorator sits outside the hunk's context window. Real fixes routinely put
    # the control in the handler's SIGNATURE — `current_user: User = Depends(require_admin)` — several
    # lines below its decorator, and a context-only scan misses every one of them.
    inserts: list[int] = []
    for line in patch.splitlines():
        m = HUNK.match(line)
        if m:
            old = int(m.group(1))
            route_at = None
            continue
        if line.startswith("+"):
            body = line[1:]
            if det.AUTH_MARKER.search(body) or det.ENFORCEMENT.search(body):
                if route_at:
                    out.append(route_at)
                else:
                    inserts.append(old)          # resolved later against the pre-fix source
            continue
        body = line[1:] if line[:1] in (" ", "-") else line
        if det.ROUTE.search(body):
            route_at = old              # a route that existed BEFORE the fix
        old += 1
    return sorted(set(out)), sorted(set(inserts))


def enclosing_route_lines(src: str, inserts: list[int]) -> list[int]:
    """For each insertion point, the route decorator of the handler that ENCLOSES it, if any.

    Walks up from the insertion point to the `def` that owns it, then to the decorator block above that
    `def`. Returns the route decorator's line. This is what recovers signature-level fixes, which the
    hunk-context scan structurally cannot see.
    """
    lines = src.splitlines()
    out = []
    for pos in inserts:
        i = min(max(pos - 1, 0), len(lines) - 1)
        # up to the def that owns this line
        while i >= 0 and not re.match(r"\s*(?:async\s+)?def\s", lines[i]):
            i -= 1
        if i < 0:
            continue
        j = i - 1
        while j >= 0 and (lines[j].lstrip().startswith("@") or not lines[j].strip()):
            if det.ROUTE.match(lines[j]):
                out.append(j + 1)
                break
            j -= 1
    return sorted(set(out))


def gh(path: str, paginate: bool = False):
    """One authenticated GitHub API call, cached on disk outside the repository.

    `/advisories` paginates by CURSOR, not by page number. Passing `page=N` silently returns the same
    first 100 rows every time — the first version of this probe did exactly that and printed "CWE-863:
    1200 advisories" while the distinct count sat unchanged at 319, because deduplication hid it. Only
    the *distinct* figure was ever right. `--paginate` follows the Link header properly; it emits one
    JSON array per page, concatenated, so the response is decoded as a stream of values.
    """
    os.makedirs(CACHE, exist_ok=True)
    key = os.path.join(CACHE, re.sub(r"[^A-Za-z0-9]+", "_", path)[:180]
                       + ("_p" if paginate else "") + ".json")
    if os.path.exists(key):
        try:
            return json.load(open(key, encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    cmd = ["gh", "api"] + (["--paginate"] if paginate else []) + [path]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    if not paginate:
        try:
            data = json.loads(out.stdout)
        except json.JSONDecodeError:
            return None
    else:
        data, dec, text, i = [], json.JSONDecoder(), out.stdout, 0
        while i < len(text):
            while i < len(text) and text[i].isspace():
                i += 1
            if i >= len(text):
                break
            try:
                val, i = dec.raw_decode(text, i)
            except ValueError:
                break
            data.extend(val if isinstance(val, list) else [val])
    with open(key, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return data


def advisories() -> dict:
    """Every pip advisory in the absence classes, deduplicated across classes by GHSA id."""
    seen = {}
    per_class = {}
    for cwe in CWES:
        batch = gh(f"/advisories?ecosystem={ECOSYSTEM}&cwes={cwe}&per_page=100", paginate=True) or []
        uniq = {a["ghsa_id"] for a in batch}
        for a in batch:
            seen.setdefault(a["ghsa_id"], a)
        per_class[cwe] = len(uniq)
        print(f"  CWE-{cwe}: {len(uniq)} advisories")
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
    print(f"\ndistinct advisories across the {len(CWES)} classes: {len(adv)}")

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
                # A candidate site is any file where a control was newly added. Whether it attaches to a
                # route is decided LATER, against the pre-fix source, because the decorator often sits
                # outside the hunk's context window — the fix lands in the handler's signature. Gating
                # here on seeing a route inside the patch discarded exactly those cases, which inspection
                # showed to be the largest recoverable group of real fixes.
                routes, inserts = protected_route_lines(patch)
                if routes or inserts:
                    hit_route = hit_route or bool(routes)
                    found.append({"advisory": gid, "owner": owner, "repo": repo,
                                  "file": f["filename"], "commit": sha,
                                  "route_lines": routes, "insert_lines": inserts,
                                  "parents": [pp["sha"] for pp in c.get("parents") or []]})
        adds_marker += 1 if hit_marker else 0
        on_route += 1 if hit_route else 0

    n = len(sample)
    print(f"\nyield through the pipeline (of {n} sampled fix commits):")
    print(f"  touch a Python file                     : {touches_py:>4} = {touches_py/max(n,1):.1%}")
    print(f"  ADD an auth/enforcement marker          : {adds_marker:>4} = {adds_marker/max(n,1):.1%}")
    print(f"  ...and that marker lands on a route     : {on_route:>4} = {on_route/max(n,1):.1%}")
    print("  (sites are resolved against the pre-fix source below, not from the patch alone)")

    # ------------------------------------------------------------------
    # THE TRANSFER TEST. Everything this project has measured about the detector comes from
    # deliberately-vulnerable teaching applications. These sites are the opposite: real defects in
    # production code, labelled by the maintainer who fixed them. Fetch each file AS IT WAS BEFORE THE
    # FIX and ask the detector the same question it is asked on the corpus.
    # ------------------------------------------------------------------
    print("\ntransfer test — does the detector fire on the PRE-FIX version of these organic files?")
    fired = checked = site_want = site_hit = 0
    detail = []
    scored_repos: set = set()      # repositories that actually contribute a scored site, not candidates
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
        # Resolve the labelled routes FIRST. A file where no route encloses the change is not an absence
        # site at all and must not enter either denominator — counting its firing before deciding that
        # inflated file-level firing to a meaningless 1.000.
        want = sorted(set((e.get("route_lines") or [])
                          + enclosing_route_lines(src, e.get("insert_lines") or [])))
        if not want:
            continue
        sites += len(want)
        scored_repos.add((e["owner"], e["repo"]))
        checked += 1
        hits = det.findings_for(src, e["file"])
        fired += 1 if hits else 0
        got = {h["line"] for h in hits}
        matched = [w for w in want if any(abs(w - g) <= LINE_TOL for g in got)]
        site_want += len(want)
        site_hit += len(matched)
        detail.append({"repo": f"{e['owner']}/{e['repo']}", "file": e["file"],
                       "commit": e["commit"][:10], "detector_findings": len(hits),
                       "labelled_routes": len(want), "routes_matched": len(matched)})
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
    # THE DENOMINATOR THAT DECIDES WHETHER THE TRANSFER NUMBER MEANS ANYTHING.
    # Every organic site here is a route handler by construction — a maintainer added a control to it.
    # The corpus's published recall is measured against ALL ground-truth CWE-306/862 entries, and the
    # detector only recognises route decorators, so entries that are not on a route are structurally
    # unreachable and sit in that denominator as guaranteed misses. Comparing the two directly inflates
    # the organic figure. This re-measures the corpus on the same population the organic sample is drawn
    # from: labelled entries that sit on a route handler.
    gt_all = gt_route = gt_hit = 0
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
        for g in gt:
            if not (g["is_vulnerable"] and (306 in g["cwes"] or 862 in g["cwes"])):
                continue
            gt_all += 1
            try:
                src = open(os.path.join(root, g["file"]), encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            lines = src.splitlines()
            if not any(det.ROUTE.match(l) and abs(i + 1 - g["line"]) <= LINE_TOL
                       for i, l in enumerate(lines)):
                continue                      # not on a route: the detector cannot reach it at all
            gt_route += 1
            got = {f["line"] for f in det.findings_for(src, g["file"])}
            if any(abs(g["line"] - x) <= LINE_TOL for x in got):
                gt_hit += 1
    if checked:
        print(f"\n  ORGANIC   file-level firing: {fired}/{checked} = {fired/checked:.3f}"
              f"   ({len(scored_repos)} repositories contributing a scored site)")
        if cfiles:
            print(f"  TEACHING  file-level firing: {cfired}/{cfiles} = {cfired/cfiles:.3f}"
                  f"   (same standard, same detector)")
            print("  Both are FILE level: 'the detector fired somewhere in this file'. That is a weak bar")
            print("  — one organic file produced 98 findings — and it is NOT the 0.226 site-level recall")
            print("  published for the corpus. What it supports is a transfer statement at file level")
            print("  only. The site-level figure below is the one comparable to the published 0.226.")
        if site_want:
            print(f"\n  SITE level — the detector lands on the very route the maintainer protected")
            print(f"  (old-file line from the diff, +/-{LINE_TOL} as the project matcher allows):")
            print(f"    ORGANIC : {site_hit}/{site_want} = {site_hit/site_want:.3f}")
            if gt_route:
                print(f"    CORPUS  : {gt_hit}/{gt_route} = {gt_hit/gt_route:.3f}  "
                      f"(same population: labelled entries that sit ON a route)")
                # 35 sites is a small sample and the two point estimates have swung in BOTH directions
                # across revisions of this probe. Whether they differ at all is a question the intervals
                # answer, and it must be asked before either is described as better or worse.
                from stats import fisher_one_sided
                from pool_propensity import wilson
                olo, ohi = wilson(site_hit, site_want)
                clo, chi = wilson(gt_hit, gt_route)
                pv = fisher_one_sided(gt_hit, gt_route - gt_hit, site_hit, site_want - site_hit)
                print(f"    organic 95% CI [{olo:.3f}, {ohi:.3f}]   "
                      f"corpus 95% CI [{clo:.3f}, {chi:.3f}]")
                print(f"    Fisher one-sided (corpus > organic): p = {pv:.4f} — "
                      f"{'DIFFERENT' if pv < 0.05 else 'INDISTINGUISHABLE'}")
                print(f"\n  The published corpus recall uses ALL {gt_all} labelled entries as its")
                print(f"  denominator, of which only {gt_route} = {gt_route/gt_all:.1%} sit on a route at")
                print("  all. The rest are structurally unreachable by a route-decorator detector and sit")
                print("  in that denominator as guaranteed misses, so the headline recall carries a")
                print(f"  structural ceiling near {gt_route/gt_all:.3f}. Against what it actually targets")
                print(f"  the detector reaches {gt_hit/gt_route:.3f}, and the organic gap is")
                print(f"  {site_hit/site_want:.3f} vs {gt_hit/gt_route:.3f}, not vs the published figure.")
        else:
            print("\n  SITE level: no pre-existing route could be located in any diff — not measurable.")

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
                             "distinct_repositories": len(scored_repos),
                             "teaching_corpus_same_standard": {
                                 "files": cfiles, "fired": cfired,
                                 "file_level_firing": round(cfired / cfiles, 4) if cfiles else None},
                             "site_level": {"labelled_routes": site_want, "matched": site_hit,
                                            "organic_site_recall": round(site_hit / site_want, 4)
                                            if site_want else None,
                                            "line_tolerance": LINE_TOL,
                                            "corpus_published_strict_recall": 0.226,
                                            "organic_ci": list(wilson(site_hit, site_want)) if site_want else None,
                                            "fisher_corpus_gt_organic_p": round(pv, 4) if site_want and gt_route else None,
                                            "corpus_same_population": {
                                                "labelled_entries": gt_all,
                                                "on_a_route": gt_route,
                                                "route_fraction": round(gt_route / gt_all, 4) if gt_all else None,
                                                "recall_on_routes": round(gt_hit / gt_route, 4) if gt_route else None},
                                            "denominator_warning": "the published recall counts labelled "
                                                "entries a route-decorator detector cannot reach; comparing "
                                                "the organic figure against it inflates the gap"}}}
    with open(os.path.join(_HERE, "organic-absence-probe-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
