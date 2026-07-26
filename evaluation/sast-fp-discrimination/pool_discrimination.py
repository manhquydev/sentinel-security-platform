"""Pool the repeated readings of the headline discrimination design.

E46 measured, for class attribution, that repeated reading delivers steadily less than an independence
model predicts and that no file is ever reported every time. E47 asked the same of decision 0027's PRIMARY
claim — file-level discrimination between absence-class files and clean controls — on two readings, and
found the two halves behave differently: specificity looked like a floor, sensitivity like a rate.

Two readings and an overlap of two cannot characterise anything, so this pools every available reading of
that design and reports each half separately, because conflating them is exactly the error E47 exists to
prevent:

  SENSITIVITY  per-file hit counts over k readings, the union curve, and how far the union falls short of
               what independence would predict.
  SPECIFICITY  the clean-control arm, where the claim is not a low rate but a floor at zero. For that
               half the interesting quantity is simply whether it has ever been breached, so it is
               reported as a count and never as a curve.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/pool_discrimination.py
"""

from __future__ import annotations

import glob
import itertools
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.abspath(os.path.join(_HERE, "..", "..")), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from pool_propensity import wilson  # noqa: E402

_SOURCES = (["generative-260726.json"]
            + sorted(os.path.basename(p) for p in
                     glob.glob(os.path.join(_HERE, "generative-rerun*-260726.json"))))


def main() -> int:
    runs = []
    for name in _SOURCES:
        path = os.path.join(_HERE, name)
        if os.path.exists(path):
            runs.append((name, {(r["repo"], r["file"]): r
                                for r in json.load(open(path))["rows"]}))
    if len(runs) < 2:
        print(f"FAIL: need at least two readings; found {[n for n, _ in runs]}")
        return 2

    # Only files present in EVERY reading can be compared per file. The original run sampled more files
    # than the re-runs, and silently pooling the extras would mix a k=1 measurement into a k=n one.
    shared = set.intersection(*(set(d) for _, d in runs))
    pos = sorted(k for k in shared if runs[0][1][k]["arm"] == "positive")
    neg = sorted(k for k in shared if runs[0][1][k]["arm"] == "negative")
    R = len(runs)
    print(f"{R} readings: {[n for n, _ in runs]}")
    print(f"files shared by all readings: {len(shared)}  (positive {len(pos)}, clean control {len(neg)})\n")

    flagged = [{k: d[k]["verdict"] == "flagged" for k in pos} for _, d in runs]
    hits = {k: sum(f[k] for f in flagged) for k in pos}

    print("SENSITIVITY — per-file hit counts over the readings")
    for h in range(R + 1):
        c = sum(1 for k in pos if hits[k] == h)
        if c:
            lo, hi = wilson(h, R)
            print(f"  {h}/{R} readings: {c:3} files   propensity {h/R:.3f}  [{lo:.3f}, {hi:.3f}]")
    never = sum(1 for k in pos if hits[k] == 0)
    always = sum(1 for k in pos if hits[k] == R)
    lo, hi = wilson(never, len(pos))
    print(f"  never flagged: {never}/{len(pos)} = {never/len(pos):.3f}  95% CI [{lo:.3f}, {hi:.3f}]")
    print(f"  flagged in ALL {R} readings: {always}/{len(pos)}")

    p1 = sum(hits.values()) / (R * len(pos))
    print(f"\n  union curve (mean single-reading rate p = {p1:.3f})")
    print(f"  {'k':>2}  {'observed':>16}  {'independence':>13}  {'delivered':>10}")
    for k in range(1, R + 1):
        tot = cnt = 0
        for combo in itertools.combinations(range(R), k):
            tot += sum(1 for key in pos if any(flagged[i][key] for i in combo))
            cnt += 1
        obs = tot / cnt / len(pos)
        ind = 1 - (1 - p1) ** k
        print(f"  {k:>2}  {obs:.3f} ({tot/cnt:4.1f}/{len(pos)})  {ind:13.3f}  {obs/ind*100:9.0f}%")

    # Specificity is a floor, so it gets a count and a breach check — not a curve, which would imply a
    # rate that could be traded off against something.
    breaches = [(name, k) for (name, d) in runs for k in neg if d[k]["verdict"] == "flagged"]
    print(f"\nSPECIFICITY — clean controls, {len(neg)} files x {R} readings = {len(neg)*R} observations")
    print(f"  flags on clean controls: {len(breaches)}")
    for name, k in breaches:
        print(f"    BREACH in {name}: {k[1]}")

    out = {"readings": [n for n, _ in runs], "k": R,
           "n_positive": len(pos), "n_clean": len(neg),
           "hit_counts": {str(h): sum(1 for k in pos if hits[k] == h) for h in range(R + 1)},
           "never_flagged": never, "flagged_in_all": always,
           "single_reading_rate": round(p1, 4),
           "clean_control_flags": len(breaches),
           "clean_control_observations": len(neg) * R}
    with open(os.path.join(_HERE, "discrimination-pooled-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
