"""E59 mapped its arms to the wrong variable. Does the memorisation reading survive a discriminating test?

E59 tested the contamination threat by splitting the corpus on `authorship` and found detection HIGHER on
the `human_authored` half (0.519 vs 0.316, p = 0.0617), concluding "there is no evidence for the feared
direction". That conclusion rests on a directional prediction — *if positives come from an LLM recognising
another LLM's injected defect, the seeded half should lead* — which tests only the KINSHIP mechanism.

The feared mechanism was never kinship. It is TRAINING-DATA MEMORISATION, and on that mechanism the arms
point the other way:

    the `human_authored` half is PyGoat (OWASP), VAmPI, vulpy, DjanGoat, DSVW, the Damn-Vulnerable-*
    family — famous, public, deliberately-vulnerable teaching applications, documented in years of
    writeups and tutorials. MEMORISATION-MAXIMAL.

    the `llm_generated` half was generated in 2026 for this benchmark (Claude Opus 4.7, GPT-5.5,
    Kimi K2.6) — likely after any plausible training cutoff. MEMORISATION-MINIMAL.

Under memorisation, higher detection on the human half is exactly the predicted direction. E59's own
observation is therefore CONSISTENT WITH the threat it was written to dismiss.

THE DISCRIMINATING TEST THIS SCRIPT ADDS. The two readings disagree about a within-arm split that E59
never made: among human-authored repos, memorisation predicts higher detection on FAMOUS apps (heavily
starred, widely documented) than on obscure ones, while "human code is simply easier" predicts no fame
effect. Fame is proxied by the original repository's GitHub stars; kolega-ai mirror copies hide the
original, so they are excluded and counted.

Model detection comes from every committed generative reading (`generative*-260726.json`), the same rows
E59 pooled. Star counts are fetched once and cached OUTSIDE the repository.

WHAT WOULD FALSIFY THE MEMORISATION READING HERE: obscure repos detected at or above famous ones.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/probe_fame_memorisation.py
"""

from __future__ import annotations

import collections
import glob
import json
import os
import re
import statistics
import subprocess
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from stats import fisher_one_sided  # noqa: E402
from pool_propensity import wilson  # noqa: E402

MANIFEST = os.path.join(_HERE, "corpus", "Real-Vuln-Benchmark", "benchmark-manifest.json")
CACHE = os.path.join(os.environ.get("TMPDIR", "/tmp"), "fame-stars-cache.json")
GH_URL = re.compile(r"https://github\.com/([^/]+)/([^/]+)")


def stars_for(human: dict) -> dict[str, int]:
    """Original-repo star counts, cached outside the repository. kolega-ai mirrors excluded."""
    cache = {}
    if os.path.exists(CACHE):
        try:
            cache = json.load(open(CACHE, encoding="utf-8"))
        except json.JSONDecodeError:
            cache = {}
    out = {}
    for slug, v in human.items():
        m = GH_URL.match(v.get("repo_url", ""))
        if not m or m.group(1) == "kolega-ai":
            continue
        if slug in cache:
            out[slug] = cache[slug]
            continue
        r = subprocess.run(["gh", "api", f"/repos/{m.group(1)}/{m.group(2)}",
                            "--jq", ".stargazers_count"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            out[slug] = int(r.stdout.strip())
            cache[slug] = out[slug]
    with open(CACHE, "w", encoding="utf-8") as fh:
        json.dump(cache, fh)
    return out


def detection_by_repo(human: dict) -> dict[str, tuple[set, set]]:
    """Per human repo: (files read, files ever flagged) across every committed generative reading."""
    det: dict[str, tuple[set, set]] = collections.defaultdict(lambda: (set(), set()))
    for f in glob.glob(os.path.join(_HERE, "generative*-260726.json")):
        try:
            rows = json.load(open(f, encoding="utf-8")).get("rows") or []
        except (OSError, json.JSONDecodeError):
            continue
        for r in rows:
            if r.get("arm") != "positive" or r["repo"] not in human:
                continue
            det[r["repo"]][0].add(r["file"])
            if r.get("verdict") == "flagged":
                det[r["repo"]][1].add(r["file"])
    return det


def main() -> int:
    if not os.path.exists(MANIFEST):
        print("FAIL: corpus not fetched")
        return 2
    m = json.load(open(MANIFEST, encoding="utf-8"))
    human = {k: v for k, v in m["repos"].items() if v.get("authorship") == "human_authored"}
    llm_models = sorted({v.get("authorship_model") for v in m["repos"].values()
                         if v.get("authorship") == "llm_generated" and v.get("authorship_model")})

    print("ARM IDENTITY — what the two halves actually are:")
    print(f"  human_authored ({len(human)}): famous public teaching apps — "
          + ", ".join(sorted(human)[:6]) + ", ...")
    print(f"  llm_generated  (40): generated for this benchmark by {', '.join(llm_models)}")
    print("  Memorisation-maximal vs memorisation-minimal. E59 labelled these arms the other way round.\n")

    stars = stars_for(human)
    det = detection_by_repo(human)
    rows = [(slug, stars[slug], det[slug]) for slug in det if slug in stars]
    excluded = [slug for slug in det if slug not in stars]
    if len(rows) < 8:
        print("FAIL: too few human repos with both star data and readings")
        return 2

    med = statistics.median(s for _, s, _ in rows)
    famous = [(sl, s, d) for sl, s, d in rows if s >= med]
    obscure = [(sl, s, d) for sl, s, d in rows if s < med]

    def tally(group):
        seen = sum(len(d[0]) for _, _, d in group)
        fl = sum(len(d[1]) for _, _, d in group)
        return fl, seen

    fa, fs = tally(famous)
    oa, os_ = tally(obscure)
    p = fisher_one_sided(fa, fs - fa, oa, os_ - oa)
    flo, fhi = wilson(fa, fs)
    olo, ohi = wilson(oa, os_)

    print(f"WITHIN the human arm, split at the median of {med:.0f} original-repo stars:")
    print(f"{'':>10} {'repos':>6} {'files flagged':>14} {'union':>7} {'95% CI':>18}")
    print(f"{'famous':>10} {len(famous):>6} {fa:>7}/{fs:<6} {fa/fs:>7.3f} [{flo:.3f}, {fhi:.3f}]")
    print(f"{'obscure':>10} {len(obscure):>6} {oa:>7}/{os_:<6} {oa/os_:>7.3f} [{olo:.3f}, {ohi:.3f}]")
    print(f"\nFisher one-sided (famous > obscure): p = {p:.4f}")
    print(f"excluded for unresolvable fame (kolega-ai mirrors): {len(excluded)}")

    direction = fa / fs > oa / os_
    print(f"\ndirection: {'famous LEADS — consistent with memorisation' if direction else 'obscure leads or ties — memorisation NOT supported here'}")
    print("Small sample; this cannot be conclusive alone. What it decides is the honest phrasing: the")
    print("within-arm fame split was the one available test that could have SUPPORTED E59's reading, and")
    print(f"it {'does not' if direction else 'does'}.")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(),
           "question": "does the within-human-arm fame split support E59's 'no contamination evidence' "
                       "reading, or the memorisation reading?",
           "arm_identity": {
               "human_authored": "famous public teaching apps (PyGoat, VAmPI, vulpy, DjanGoat, DSVW, "
                                 "DVWA-family) — memorisation-MAXIMAL",
               "llm_generated": f"generated 2026 for this benchmark by {', '.join(llm_models)} — "
                                "memorisation-MINIMAL"},
           "median_stars": med,
           "famous": {"repos": len(famous), "flagged": fa, "files": fs,
                      "union": round(fa / fs, 4), "ci": [round(flo, 4), round(fhi, 4)]},
           "obscure": {"repos": len(obscure), "flagged": oa, "files": os_,
                       "union": round(oa / os_, 4), "ci": [round(olo, 4), round(ohi, 4)]},
           "fisher_one_sided_famous_gt_obscure": round(p, 4),
           "famous_leads": direction,
           "excluded_mirrors": sorted(excluded),
           "per_repo": {sl: {"stars": s, "flagged": len(d[1]), "files": len(d[0])}
                        for sl, s, d in sorted(rows, key=lambda t: -t[1])}}
    with open(os.path.join(_HERE, "fame-memorisation-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
