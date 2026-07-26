"""E37 — the powered class-asymmetry test, over the union of k independent readings.

E39 asked whether the model names absent ownership/authentication more often than absent rate limiting,
on the 53 corpus files that carry both. It was published as an ESTIMATE, not a test, because the
significance test had been cancelled at the power gate: 43% power on a single reading.

E42 then measured the correlation between readings on this exact material — two runs' attributions
overlapping in 0 of 6 files, against 0.68 expected under independence — and independence turned out to be
the best-supported model. Under it, the k=3 union design reaches 94.6% power, so the cancellation was
superseded and the test is runnable.

THE ESTIMAND IS DIFFERENT AND MUST BE READ AS DIFFERENT. This does not ask "does one reading name the
class more often". It asks **"is the class named in at least one of three readings"**. Given E43 — per-file
propensities form a mixture topping out at 0.667, so no single reading is representative — the union is
the product-relevant quantity: it is what a tool that reads three times would actually surface. But it is
a different number from E39's, it will be larger, and quoting it as if it were the single-reading figure
would inflate the result while appearing to report the same thing.

Paired exact McNemar, one-sided, on the discordant files: those where one class was named across the
three readings and the other was not. Files naming both or neither carry no information about which class
is easier and are correctly ignored by the test.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/pool_asymmetry_union.py
"""

from __future__ import annotations

import glob
import json
import os
import sys
from math import comb

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.abspath(os.path.join(_HERE, "..", "..")), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_RUNS = sorted(glob.glob(os.path.join(_HERE, "class-asymmetry-e37-run*-260726.json")))


def mcnemar_one_sided(b: int, c: int) -> float:
    """P(B >= b) under the null that a discordant file is equally likely to fall either way."""
    n = b + c
    return 1.0 if n == 0 else sum(comb(n, k) for k in range(b, n + 1)) / 2 ** n


def main() -> int:
    if len(_RUNS) < 2:
        print(f"FAIL: found {len(_RUNS)} E37 run(s); the union design needs at least 2")
        return 2

    union: dict[tuple[str, str], dict] = {}
    empties = 0
    for path in _RUNS:
        doc = json.load(open(path))
        empties += doc.get("empty_responses", 0)
        for r in doc["rows"]:
            key = (r["repo"], r["file"])
            slot = union.setdefault(key, {"own": False, "rl": False, "reads": 0})
            slot["own"] |= bool(r["named_own_authn"])
            slot["rl"] |= bool(r["named_rate_limit"])
            slot["reads"] += 1

    k = min(v["reads"] for v in union.values())
    n = len(union)
    n_own = sum(v["own"] for v in union.values())
    n_rl = sum(v["rl"] for v in union.values())
    b = sum(1 for v in union.values() if v["own"] and not v["rl"])
    c = sum(1 for v in union.values() if v["rl"] and not v["own"])
    p = mcnemar_one_sided(b, c)

    print(f"E37 union over {len(_RUNS)} runs, k={k} readings per file, n={n} files\n")
    print(f"  named ownership/authn absence in >=1 reading : {n_own}/{n} = {n_own/n:.3f}")
    print(f"  named rate-limit absence in >=1 reading      : {n_rl}/{n} = {n_rl/n:.3f}")
    print(f"  discordant: ownership-only={b}  rate-limit-only={c}")
    print(f"  exact McNemar, one-sided: p = {p:.6g}")
    print(f"  {'REJECTS' if p < 0.05 else 'does NOT reject'} the null of no class asymmetry at alpha=0.05")
    if empties:
        # A failed call scores as "not named", so empties push both arms toward the null. Reported rather
        # than absorbed, because a test that quietly swallowed dead calls would understate the effect and
        # look conservative while actually being unmeasured.
        print(f"\n  WARNING: {empties} empty responses across all runs; they bias BOTH arms toward the null")

    print("\n  ESTIMAND: 'named in at least one of k readings'. This is NOT E39's single-reading figure")
    print("  (6/53 vs 1/53) and must never be quoted as if it were — it is larger by construction.")

    out = {"runs": [os.path.basename(r) for r in _RUNS], "k": k, "n": n,
           "estimand": "named in at least one of k independent readings; NOT the single-reading rate",
           "named_own_authn_union": n_own, "named_rate_limit_union": n_rl,
           "discordant_own_only": b, "discordant_rate_limit_only": c,
           "mcnemar_p_one_sided": round(p, 8), "empty_responses_total": empties,
           "preregistered_power": "94.6% at k=3 under the independence measured in E42"}
    with open(os.path.join(_HERE, "asymmetry-union-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
