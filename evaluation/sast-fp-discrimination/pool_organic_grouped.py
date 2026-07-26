"""How many repositories does the organic transfer claim actually need?

E68 measured organic site-level recall at 17/35 = 0.486 against the teaching corpus's 0.576 and reported
them as indistinguishable (Fisher p = 0.22). That test treats the SITE as the unit of analysis, and the
sites are not independent: one maintainer's fix adds a control to many routes in one repository, so a
single repo can contribute a third of the sample. E14 established for this project that grouped analysis
changes conclusions; the same rule applies here.

This asks two questions the pooled figure cannot answer:

  1. Does the "indistinguishable" conclusion survive when the REPOSITORY is the unit?
  2. "Eight repositories is too few" has been asserted repeatedly in the log without a number attached.
     **How many would be enough?**

The second is the useful one. A validity threat with no target is a complaint; a validity threat with
"127 repositories" is a work item. The projection uses the standard interval-width scaling — width falls
as 1/sqrt(n) — applied to the measured grouped interval, and it is an estimate whose assumptions are
stated rather than a promise.

Reads the committed artefact; no API calls, no model calls.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/pool_organic_grouped.py
"""

from __future__ import annotations

import collections
import json
import math
import os
import random
import statistics
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from pool_propensity import wilson  # noqa: E402

SEED = 20260726
CORPUS_RECALL = 0.576          # 76/132, teaching corpus restricted to labelled entries on a route (E67)
TARGET_WIDTH = 0.15            # +/-0.075, the precision at which a transfer claim would be worth making


def main() -> int:
    path = os.path.join(_HERE, "organic-absence-probe-260726.json")
    if not os.path.exists(path):
        print("FAIL: run probe_organic_absence_corpus.py first")
        return 2
    art = json.load(open(path, encoding="utf-8"))
    detail = art["transfer_test"]["detail"]

    by = collections.defaultdict(lambda: [0, 0])
    for r in detail:
        by[r["repo"]][0] += r["routes_matched"]
        by[r["repo"]][1] += r["labelled_routes"]
    by = {k: v for k, v in by.items() if v[1]}
    if len(by) < 3:
        print("FAIL: too few repositories to group over")
        return 2

    print(f"{'repository':<42} {'hit':>4} {'sites':>6} {'recall':>8}")
    for repo, (h, w) in sorted(by.items(), key=lambda kv: -kv[1][1]):
        print(f"  {repo:<40} {h:>4} {w:>6} {h/w:>8.3f}")

    H = sum(v[0] for v in by.values())
    W = sum(v[1] for v in by.values())
    rates = [v[0] / v[1] for v in by.values()]
    slo, shi = wilson(H, W)

    rng = random.Random(SEED)
    repos = list(by)
    boot = []
    for _ in range(4000):
        pick = [rng.choice(repos) for _ in repos]
        h = sum(by[r][0] for r in pick)
        w = sum(by[r][1] for r in pick)
        if w:
            boot.append(h / w)
    boot.sort()
    glo, ghi = boot[int(0.025 * len(boot))], boot[int(0.975 * len(boot))]

    print(f"\npooled, SITE as unit   : {H}/{W} = {H/W:.3f}   95% CI [{slo:.3f}, {shi:.3f}]"
          f"  width {shi-slo:.3f}")
    print(f"mean, REPO as unit     : {statistics.mean(rates):.3f}   ({len(rates)} repositories)")
    print(f"grouped bootstrap      : 95% CI [{glo:.3f}, {ghi:.3f}]  width {ghi-glo:.3f}")

    # The pooled figure is dominated by whichever repository contributed most sites.
    top = max(by.items(), key=lambda kv: kv[1][1])
    print(f"\nlargest single repository: {top[0]} — {top[1][1]}/{W} = {top[1][1]/W:.0%} of all sites, "
          f"recall {top[1][0]/top[1][1]:.3f}")
    print("The pooled number moves with that one repository; the repo-level mean does not.")

    excludes = ghi < CORPUS_RECALL or glo > CORPUS_RECALL
    print(f"\ncorpus comparator {CORPUS_RECALL:.3f} lies "
          f"{'OUTSIDE' if excludes else 'INSIDE'} the grouped interval — "
          f"{'distinguishable' if excludes else 'INDISTINGUISHABLE at repo level too'}")

    need = math.ceil(len(rates) * ((ghi - glo) / TARGET_WIDTH) ** 2)
    print(f"\nrepositories needed for a +/-{TARGET_WIDTH/2:.3f} interval: ~{need}")
    print("Assumes interval width scales as 1/sqrt(repositories) and that further repositories resemble")
    print("these. Both are assumptions, not measurements — the number is a target, not a promise.")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(),
           "question": "does the organic transfer conclusion survive repo-level grouping, and how many "
                       "repositories would a real claim need?",
           "repositories": len(rates), "sites": W, "hits": H,
           "pooled_site_level": {"recall": round(H / W, 4), "ci": [round(slo, 4), round(shi, 4)],
                                 "width": round(shi - slo, 4)},
           "repo_level": {"mean_recall": round(statistics.mean(rates), 4),
                          "grouped_ci": [round(glo, 4), round(ghi, 4)],
                          "width": round(ghi - glo, 4)},
           "largest_repo": {"repo": top[0], "sites": top[1][1],
                            "share_of_sites": round(top[1][1] / W, 4),
                            "recall": round(top[1][0] / top[1][1], 4)},
           "corpus_comparator": CORPUS_RECALL,
           "distinguishable_at_repo_level": excludes,
           "repositories_needed": need, "target_interval_width": TARGET_WIDTH,
           "projection_assumptions": "width ~ 1/sqrt(n) and further repositories resemble these"}
    with open(os.path.join(_HERE, "organic-grouped-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
