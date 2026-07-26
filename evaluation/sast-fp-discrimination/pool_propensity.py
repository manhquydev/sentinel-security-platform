"""Pool the repeated-reading runs over the same files into one per-file propensity estimate.

E43 measured per-file propensity at k=3, which resolves a file only to the nearest third — enough to show
the distribution is a mixture, too coarse to say where it sits or to test its load-bearing claim that no
file is reliably reported. A second run of k=6 over the identical files pools to k=9.

Pooling is legitimate here only because the two runs are the same design on the same files with the same
prompt and classifier: each reading is an independent draw from that file's propensity, so the counts add.
The runs are NOT averaged as two equal estimates — a k=3 estimate and a k=6 estimate carry different
weight, and averaging them would quietly upweight the smaller one.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/pool_propensity.py
"""

from __future__ import annotations

import glob
import json
import os
import random

_HERE = os.path.dirname(os.path.abspath(__file__))
# Globbed rather than listed: every propensity run over these files is another set of independent draws
# from the same per-file propensities, so a new run should widen the estimate automatically instead of
# waiting for someone to remember to add its filename here.
_SOURCES = tuple(sorted(os.path.basename(p) for p in
                        glob.glob(os.path.join(_HERE, "attribution-propensity-*.json"))))


def wilson(hits: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson interval — behaves at 0 hits, where the normal approximation returns a zero-width lie."""
    if n == 0:
        return (0.0, 1.0)
    p = hits / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def boot_diff(a: list[float], b: list[float], seed: int = 5, draws: int = 20000):
    rnd = random.Random(seed)
    out = [sum(rnd.choice(a) for _ in a) / len(a) - sum(rnd.choice(b) for _ in b) / len(b)
           for _ in range(draws)]
    out.sort()
    return out[int(0.025 * draws)], out[int(0.975 * draws)]


def main() -> int:
    pooled: dict[tuple[str, str], dict] = {}
    used = []
    for name in _SOURCES:
        path = os.path.join(_HERE, name)
        if not os.path.exists(path):
            continue
        used.append(name)
        for r in json.load(open(path))["rows"]:
            key = (r["repo"], r["file"])
            slot = pooled.setdefault(key, {"group": r["group"], "hits": 0, "k": 0})
            slot["hits"] += r["hits"]
            slot["k"] += r["k"]
    if len(used) < 2:
        print(f"FAIL: pooling needs at least two runs; found {used}")
        return 2

    print(f"pooled from {len(used)} runs over {len(pooled)} files\n")
    # The repo is printed, not just the path. Two repos in this corpus both contain `app/app.py` and
    # `backend/app/main.py`; without the repo the table reads as if one file sat in both groups at once,
    # which would look like a design error rather than a naming coincidence.
    print(f"{'group':6} {'repo/file':58} {'hits/k':>8} {'propensity':>11}  95% CI")
    rows = []
    for (repo, f), v in sorted(pooled.items(), key=lambda kv: (kv[1]["group"], -kv[1]["hits"] / kv[1]["k"])):
        p = v["hits"] / v["k"]
        lo, hi = wilson(v["hits"], v["k"])
        rows.append({"repo": repo, "file": f, "group": v["group"], "hits": v["hits"], "k": v["k"],
                     "propensity": round(p, 3), "ci95": [round(lo, 3), round(hi, 3)]})
        label = f"{repo}/{f}"
        print(f"{v['group']:6} {label[-58:]:58} {v['hits']:3}/{v['k']:<4} {p:11.3f}  [{lo:.3f}, {hi:.3f}]")

    pe = [r["propensity"] for r in rows if r["group"] == "ever"]
    pn = [r["propensity"] for r in rows if r["group"] == "never"]
    me, mn = sum(pe) / len(pe), sum(pn) / len(pn)
    lo, hi = boot_diff(pe, pn)
    top = max(r["propensity"] for r in rows)
    top_lo, top_hi = max((r["ci95"] for r in rows if r["propensity"] == top), key=lambda c: c[1])

    print(f"\nEVER  mean {me:.3f}  {sorted(pe)}")
    print(f"NEVER mean {mn:.3f}  {sorted(pn)}")
    print(f"difference {me - mn:+.3f}  95% CI [{lo:+.3f}, {hi:+.3f}]")
    print(f"\nhighest per-file propensity = {top:.3f}, 95% CI [{top_lo:.3f}, {top_hi:.3f}]")
    # The load-bearing claim from E43 is that NO file is reliably reported. At k=9 that claim is only
    # supportable if the best file's interval excludes reliability; if it does not, the claim must soften
    # rather than be repeated at higher confidence.
    print("claim 'no file is reliably reported' is "
          + ("SUPPORTED — even the best file's interval excludes 1.0"
             if top_hi < 1.0 else "NOT SUPPORTED at this k — the best file's interval reaches 1.0"))

    out = {"pooled_from": used, "n_files": len(rows), "ever_mean": round(me, 4),
           "never_mean": round(mn, 4), "difference": round(me - mn, 4),
           "difference_ci95": [round(lo, 4), round(hi, 4)],
           "max_propensity": top, "max_propensity_ci95": [top_lo, top_hi], "rows": rows}
    with open(os.path.join(_HERE, "propensity-pooled-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
