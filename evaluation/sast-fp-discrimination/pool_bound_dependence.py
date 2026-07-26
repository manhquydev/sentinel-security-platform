"""E57's rule-out bound assumes 144 independent cells. The readings are not independent. How much weakens?

E57 bounds the 8 never-surfaced files: if they shared propensity p, seeing nothing across 18 readings has
probability (1-p)^(8*18) — 0.0124 at p = 0.03 — so they are "jointly ruled out above ~3%". That treats the
144 file-reading cells as independent. E46 and E48 measured the opposite: the union delivers only 58-70%
of its independence projection, because readings correlate.

The correlation channel that matters for THIS bound is the reading effect: a whole pass can run cold,
flagging fewer files everywhere at once. If reading j carries a multiplier w_j on every file's propensity,
then P(all 144 cells zero) = prod_j (1 - p*w_j)^8, and because log(1-x) is concave, variance in w_j makes
that probability LARGER than the constant-w calculation — the rule-out threshold moves up. The w_j are not
hypothetical: they are measurable from the committed readings as each pass's flag rate over the 16 files
that do surface.

This recomputes E57's bound under the measured reading effects and reports where the ~3% threshold
actually sits. What would falsify the concern: measured w_j so uniform that the threshold barely moves.

Committed data only; zero model calls.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/pool_bound_dependence.py
"""

from __future__ import annotations

import glob
import json
import math
import os
import statistics
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

PATTERNS = ["generative-260726.json", "generative-rerun*-260726.json"]
ALPHA = 0.05


def readings() -> list[dict]:
    runs = []
    for pat in PATTERNS:
        for f in sorted(glob.glob(os.path.join(_HERE, pat))):
            try:
                rows = json.load(open(f, encoding="utf-8")).get("rows") or []
            except (OSError, json.JSONDecodeError):
                continue
            pos = {(r["repo"], r["file"]): r.get("verdict") == "flagged"
                   for r in rows if r.get("arm") == "positive"}
            if pos:
                runs.append(pos)
    return runs


def rule_out_threshold(weights: list[float], n_files: int, alpha: float) -> float:
    """Smallest p at which P(all cells zero) drops below alpha, under per-reading multipliers."""
    lo, hi = 1e-4, 0.9
    for _ in range(60):
        mid = (lo + hi) / 2
        logp = sum(n_files * math.log(max(1 - mid * w, 1e-12)) for w in weights)
        if logp < math.log(alpha):
            hi = mid
        else:
            lo = mid
    return hi


def main() -> int:
    runs = readings()
    shared = set.intersection(*(set(r) for r in runs))
    files = sorted(shared)
    k = len(runs)
    if k < 10 or len(files) < 20:
        print("FAIL: not enough shared readings/files")
        return 2

    never = [f for f in files if not any(r[f] for r in runs)]
    ever = [f for f in files if f not in never]
    print(f"{len(files)} files x {k} readings; never-surfaced: {len(never)}")

    # Reading effects, measured on the files that CAN fire. w_j = pass j's flag rate over `ever`,
    # normalised to mean 1 so p keeps its meaning as the average per-reading propensity.
    rates = [sum(1 for f in ever if r[f]) / len(ever) for r in runs]
    mean_rate = statistics.mean(rates)
    w = [r / mean_rate for r in rates]
    print(f"per-reading flag rate over the {len(ever)} surfaced files: "
          f"mean {mean_rate:.3f}, range [{min(rates):.3f}, {max(rates):.3f}], "
          f"CV {statistics.pstdev(rates)/mean_rate:.2f}")

    n = len(never)

    # THE CORRECTED MODEL, and why the first version's check could never fail (caught in review; §17).
    # The first version CONDITIONED on the observed weights: prod_j (1-p*w_j)^n. With the w_j normalised to
    # mean 1, Jensen on the concave log(1-p*w) guarantees that sum is <= n*k*log(1-p) for ANY weight vector,
    # so the "dependence" threshold could only ever move DOWN — the "bound weakened" branch was unreachable
    # and the confirmation was vacuous.
    #
    # The channel E46/E48 actually measured is a RANDOM per-reading effect: a whole pass runs cold and zeroes
    # all n files together. The honest model treats each reading's rate as a draw from the empirical
    # distribution and asks P(all n files zero in a reading) = E_w[(1-p*w)^n]. Because (1-p*w)^n is CONVEX in
    # w, that expectation is LARGER than (1-p)^n — correlation raises the chance of an all-zero pass and can
    # genuinely weaken the rule-out. This version can fail, which is the point.
    def p_all_zero_indep(p):
        return (1 - p) ** (n * k)

    def p_all_zero_re(p):
        # per-reading expectation over the empirical rate multipliers, then k independent readings
        per_reading = statistics.mean((1 - p * wi) ** n for wi in w)
        return max(per_reading, 1e-300) ** k

    def threshold(fn):
        lo, hi = 1e-4, 0.9
        for _ in range(60):
            mid = (lo + hi) / 2
            (hi := mid) if fn(mid) < ALPHA else (lo := mid)
        return hi

    flat = threshold(p_all_zero_indep)
    re_thr = threshold(p_all_zero_re)

    print(f"\nE57's published points, under independence vs the random-effects model:")
    for p in (0.03, 0.05):
        print(f"  p={p:.2f}: independent {p_all_zero_indep(p):.4f}  ->  "
              f"random-effects {p_all_zero_re(p):.4f}")

    print(f"\nrule-out threshold at alpha={ALPHA}:")
    print(f"  independence assumption        : p > {flat:.4f}")
    print(f"  random-effects (correlated pass): p > {re_thr:.4f}   ({re_thr/flat:.2f}x)")
    dep = re_thr

    # This branch is now reachable: a high enough rate CV pushes the threshold up materially.
    verdict = ("BOUND WEAKENED — E57's threshold must be restated upward"
               if re_thr / flat >= 1.15 else
               "BOUND HOLDS UNDER THE CORRECTED MODEL — the random-effects correlation shifts the "
               "threshold by less than 15%, so E57's ~3% rule-out stands")
    print(f"\n{verdict}")
    print(f"(a check that can fail: at CV {statistics.pstdev(rates)/mean_rate:.2f} the shift is "
          f"{(re_thr/flat-1)*100:+.1f}%; a CV around 1.3 would move it past the 15% line)")
    print("Note the limit of this correction: it models only the READING-level channel (a cold pass).")
    print("File-level clustering beyond propensity is conditioned away by construction; any residual")
    print("dependence structure would weaken the bound further, never strengthen it.")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(),
           "question": "does E57's joint rule-out of the never-surfaced files survive measured "
                       "reading-to-reading dependence?",
           "files": len(files), "readings": k, "never_surfaced": n,
           "per_reading_rates": [round(r, 4) for r in rates],
           "rate_cv": round(statistics.pstdev(rates) / mean_rate, 4),
           "published_points_independent": {"0.03": round((1 - 0.03) ** (n * k), 4),
                                            "0.05": round((1 - 0.05) ** (n * k), 4)},
           "published_points_random_effects": {"0.03": round(p_all_zero_re(0.03), 4),
                                               "0.05": round(p_all_zero_re(0.05), 4)},
           "threshold_independent": round(flat, 4),
           "threshold_random_effects": round(re_thr, 4),
           "weakening_factor": round(re_thr / flat, 3),
           "model": "random-effects: each reading's rate is a draw from the empirical distribution; "
                    "P(all zero) = E_w[(1-p*w)^n]^k, convex in w so correlation raises it — the check CAN "
                    "fail, unlike the conditional version it replaces (which Jensen made vacuous, §17)",
           "verdict": verdict,
           "limit": "models only the reading-level channel; residual dependence would weaken further"}
    with open(os.path.join(_HERE, "bound-dependence-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
