"""The one measurement that memorisation cannot explain: the model on post-cutoff production code.

E72 reopened the contamination threat. The benchmark's `human_authored` half is famous teaching
applications (PyGoat, VAmPI, vulpy) and the model detects MORE there, which is the direction training-data
memorisation predicts; the within-arm fame split leans the same way. Every generative-role number on that
corpus now carries a live memorisation caveat, and no amount of re-analysis of the same corpus can lift it.

Only new evidence can. This is it:

    ORGANIC, POST-CUTOFF, PAIRED. Take a real security fix a maintainer landed in a production project.
    The file BEFORE the fix is a confirmed missing-control defect — labelled by the person who owned the
    code. The file AFTER the fix is the same file with the control added: a clean control that differs
    from the positive in exactly the thing under test. Ask the model both.

WHY PAIRED IS THE POINT. Every earlier specificity measurement used *different* files for the clean arm,
so "flagged the vulnerable one, not the clean one" could always be a property of which files were chosen.
Here the two arms are the same file, same project, same style, same author, minutes apart in history. The
only systematic difference is the control. That is the strongest form this comparison can take, and it
costs nothing extra because the fix commit supplies both sides.

WHY POST-CUTOFF. The advisories driving these sites were published in 2026 — one of them two days before
this run. A model cannot have memorised a fix that did not exist when it was trained. Publication dates
are recorded per site and reported, and the headline is computed on the post-cutoff subset alone; the
model's exact cutoff is not public, so the date is reported rather than assumed and the threshold is a
parameter.

WHAT WOULD FALSIFY THE CAPABILITY CLAIM: the model flags the post-fix file as often as the pre-fix file.
That is a live outcome — the two differ by a few lines, often only a decorator or a signature argument,
which is a far harder discrimination than the corpus arms ever demanded.

KNOWN RESIDUAL LEAK, stated rather than hidden: several of these projects are themselves famous
(langflow, airflow). The model may know the PROJECT without knowing the FIX. That is why the design is
paired — project familiarity is held constant across both arms and cancels; only fix-specific knowledge
could survive it, and the fix postdates training.

    LITELLM_MASTER_KEY=... rag/.venv/bin/python -W ignore \\
        evaluation/sast-fp-discrimination/run_organic_paired.py
"""

from __future__ import annotations

import base64
import json
import os
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import detect_absent_auth as det  # noqa: E402
import probe_organic_absence_corpus as P  # noqa: E402
from run_generative import classify_prose, canary_passes, _RUBRIC  # noqa: E402
from stats import fisher_one_sided  # noqa: E402
from pool_propensity import wilson  # noqa: E402

MODEL = os.environ.get("ORGANIC_MODEL", "sast-grok45")
K = int(os.environ.get("ORGANIC_K", "3"))
CUTOFF = os.environ.get("ORGANIC_CUTOFF", "2025-06-01")   # conservative; reported, not assumed
MAX_CHARS = 4000
MAX_SITES = int(os.environ.get("ORGANIC_MAX_SITES", "24"))

# THE PROMPT IS IMPORTED, NOT REWRITTEN. The first run of this experiment defined its own rubric, which
# silently made the headline incomparable: the corpus rate it is measured against (~0.458 union at k=3) was
# produced by run_generative's `_RUBRIC` and its persisted-text classifier. A transfer claim is a claim
# about the SAME instrument on different code, so every part of the path — prompt, provenance labelling,
# truncation, parser — has to be the one the corpus number came from.


def blob(owner: str, repo: str, path: str, ref: str) -> str | None:
    b = P.gh(f"/repos/{owner}/{repo}/contents/{path}?ref={ref}")
    if not b or "content" not in b:
        return None
    try:
        return base64.b64decode(b["content"]).decode("utf-8", "replace")
    except (ValueError, TypeError):
        return None


def window(src: str, routes: list[int], budget: int = MAX_CHARS) -> str:
    """The slice of the file containing the labelled routes, within the same character budget.

    THE DEFECT THIS FIXES, measured before any result was published: production files here run 400-2700
    lines, and truncating at the first 4000 characters showed the model only ~90-170 of them. **56.5% of
    the labelled routes were never in the prompt at all.** Any "the model missed them" reading of that is
    a statement about the harness, not the model.

    Corpus files are a different shape — median 88-184 lines (E59) — so almost all of them fitted whole
    inside the same budget. Matching the INSTRUMENT therefore means matching what the model gets to see:
    the code the question is about. The window is centred on the labelled routes and applied identically
    to the pre-fix and post-fix arms, so the pairing is untouched.
    """
    lines = src.splitlines()
    if not routes or len(src) <= budget:
        return src[:budget]
    lo, hi = min(routes), max(routes)
    per = max(budget // 40, 40)
    start = max(0, lo - 1 - per // 3)
    end = min(len(lines), hi + per)
    return "\n".join(lines[start:end])[:budget]


def ask_file(src: str, label: str, routes: list[int] | None = None) -> tuple[str, str]:
    """One reading of one file version. Returns (verdict, persisted prose).

    Scores the text that is PERSISTED, never the raw response — protocol §14, the rule this project
    violated for six hours and pinned with SM19.
    """
    from agent import llm
    shown = window(src, routes or [])
    numbered = "\n".join(f"{i+1}: {ln}" for i, ln in enumerate(shown.splitlines()))
    try:
        out = llm.chat(
            [llm.Msg("system", _RUBRIC, llm.operator()),
             llm.Msg("user", f"file: {label}\n\n{numbered}",
                     llm.target_derived(source="organic-github", target=label))],
            model=MODEL, max_tokens=400, temperature=0.0)
    except Exception as exc:
        return "error", f"error: {str(exc)[:120]}"
    kept = out[:4000]
    return classify_prose(kept), kept


def main() -> int:
    if not os.environ.get("LITELLM_MASTER_KEY"):
        print("FAIL: LITELLM_MASTER_KEY not set — this run needs the gateway")
        return 2
    if not det.self_test():
        print("FAIL: detector self-test")
        return 2

    # Positive control, read n times passing on >=1 (E44): a dead harness must not score as a model
    # that found nothing.
    ok, seen = canary_passes(lambda: ask_file(
        "1: @app.route('/admin/delete/<int:uid>', methods=['POST'])\n"
        "2: def delete_user(uid):\n"
        "3:     User.query.filter_by(id=uid).delete()\n"
        "4:     db.session.commit()\n"
        "5:     return 'ok'\n", "canary.py")[1], n=3, need=1)
    print(f"canary: {'PASS' if ok else 'FAIL'} {seen}")
    if not ok:
        print("ABORT: the harness cannot detect a planted missing-auth defect; no result would mean anything.")
        return 2

    adv, _ = P.advisories()
    dates = {g: a.get("published_at", "") for g, a in adv.items()}
    commits = P.fix_commits(adv)

    # Rebuild the labelled sites, keeping BOTH refs this time.
    sites = []
    for gid, owner, repo, sha in commits:
        if len(sites) >= MAX_SITES:
            break
        c = P.gh(f"/repos/{owner}/{repo}/commits/{sha}")
        if not c or not (c.get("parents") or []):
            continue
        for f in c.get("files") or []:
            if not f.get("filename", "").endswith(".py"):
                continue
            patch = f.get("patch") or ""
            added = "\n".join(l[1:] for l in patch.splitlines() if l.startswith("+"))
            if not (det.AUTH_MARKER.search(added) or det.ENFORCEMENT.search(added)):
                continue
            routes, inserts = P.protected_route_lines(patch)
            pre = blob(owner, repo, f["filename"], c["parents"][0]["sha"])
            if pre is None:
                continue
            want = sorted(set(routes + P.enclosing_route_lines(pre, inserts)))
            if not want:
                continue
            post = blob(owner, repo, f["filename"], sha)
            if post is None:
                continue
            sites.append({"advisory": gid, "published_at": dates.get(gid, ""),
                          "repo": f"{owner}/{repo}", "file": f["filename"],
                          "commit": sha[:10], "routes": len(want), "route_lines": want,
                          "pre": pre, "post": post, "pre_lines": len(pre.splitlines())})
            break                                  # one file per advisory keeps repos from dominating

    if len(sites) < 8:
        print(f"FAIL: only {len(sites)} paired sites resolved")
        return 2
    post_cut = [s for s in sites if s["published_at"] >= CUTOFF]
    print(f"\npaired sites: {len(sites)}   published on/after {CUTOFF}: {len(post_cut)}")
    print(f"repositories: {len({s['repo'] for s in sites})}   readings per version: k={K}\n")

    rows = []
    for s in sites:
        pre_v, post_v = [], []
        for _ in range(K):
            v, _ = ask_file(s["pre"], s["file"], s["route_lines"])
            pre_v.append(v)
            v2, _ = ask_file(s["post"], s["file"], s["route_lines"])
            post_v.append(v2)
        r = {k: s[k] for k in ("advisory", "published_at", "repo", "file", "commit", "routes",
                               "pre_lines")}
        r["pre_flagged"] = sum(1 for v in pre_v if v == "flagged")
        r["post_flagged"] = sum(1 for v in post_v if v == "flagged")
        r["pre_verdicts"], r["post_verdicts"] = pre_v, post_v
        r["pre_nonanswer"] = sum(1 for v in pre_v if v not in ("flagged", "clean"))
        rows.append(r)
        print(f"  {r['repo']:<28} {r['file'][:34]:<35} pre {r['pre_flagged']}/{K}  post {r['post_flagged']}/{K}")

    def tally(rs):
        a = sum(1 for r in rs if r["pre_flagged"] > 0)
        b = sum(1 for r in rs if r["post_flagged"] > 0)
        return a, b, len(rs)

    import collections as _c
    allv = _c.Counter(v for r in rows for v in r["pre_verdicts"] + r["post_verdicts"])
    print(f"\nverdict distribution across every reading: {dict(allv)}")
    print("A run that is mostly non-answers is a broken harness, not a model finding nothing (rule 15).")

    for label, rs in (("ALL paired sites", rows),
                      (f"POST-CUTOFF only (>= {CUTOFF})",
                       [r for r in rows if r["published_at"] >= CUTOFF])):
        if len(rs) < 5:
            print(f"\n{label}: only {len(rs)} sites — not reported")
            continue
        a, b, n = tally(rs)
        alo, ahi = wilson(a, n)
        blo, bhi = wilson(b, n)
        # Exact paired test: sites where the two arms disagree (McNemar-style, one-sided).
        disc_pre = sum(1 for r in rs if r["pre_flagged"] > 0 and r["post_flagged"] == 0)
        disc_post = sum(1 for r in rs if r["post_flagged"] > 0 and r["pre_flagged"] == 0)
        p = fisher_one_sided(a, n - a, b, n - b)
        print(f"\n=== {label} — {n} paired sites, k={K} ===")
        print(f"  PRE-fix  (confirmed defect) flagged at least once : {a}/{n} = {a/n:.3f} "
              f"[{alo:.3f}, {ahi:.3f}]")
        print(f"  POST-fix (control added)    flagged at least once : {b}/{n} = {b/n:.3f} "
              f"[{blo:.3f}, {bhi:.3f}]")
        print(f"  discordant pairs: pre-only {disc_pre}, post-only {disc_post}")
        print(f"  Fisher one-sided (pre > post): p = {p:.4f}")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(),
           "question": "does the model detect maintainer-confirmed missing-control defects in ORGANIC, "
                       "POST-CUTOFF production code, and does it distinguish the fixed version?",
           "why": "E72 left every generative-role number on the benchmark carrying a live memorisation "
                  "caveat; paired post-cutoff organic files are the only evidence that can lift it",
           "model": MODEL, "k": K, "cutoff": CUTOFF,
           "design": "paired — pre-fix and post-fix versions of the SAME file, so project familiarity, "
                     "style and authorship are held constant and only the control differs",
           "residual_leak": "some projects are famous (langflow, airflow); the model may know the project "
                            "without knowing the fix. Pairing cancels project familiarity; the fix itself "
                            "postdates training.",
           "sites": len(sites), "post_cutoff_sites": len(post_cut),
           "repositories": len({s["repo"] for s in sites}),
           "canary": {"passed": ok, "verdicts": seen},
           "verdict_distribution": dict(allv),
           "prompt_source": "run_generative._RUBRIC — imported, so the instrument matches the corpus "
                            "number this is compared against",
           "windowing": "the prompt carries the slice of the file containing the labelled routes, within "
                        "the same 4000-char budget. Whole-file truncation hid 56.5% of the labelled "
                        "routes from the model, because production files run 400-2700 lines while corpus "
                        "files are 88-184; the same window is applied to both arms",
           "rows": rows}
    with open(os.path.join(_HERE, "organic-paired-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nwrote organic-paired-260726.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
