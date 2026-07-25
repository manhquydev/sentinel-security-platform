"""Per-repository multi-engine recall, with intervals — the grouped re-audit of decision 0022.

0022 published "union recall +44% relative at no precision cost" as a bare micro-averaged point
estimate: every finding from every repo pooled into one ratio, no interval, no grouping. E14 showed
what that structure hides — the same shape turned a "+0.069, significant" into a tie once the split
respected repository boundaries.

This instrument keeps per-repo counts so the gain can be bootstrapped over REPOSITORIES, which is the
unit that actually varies. Note what is NOT being tested: union recall is monotonically >= single-engine
recall (a union only ever adds matches), so "is the gain positive" cannot come out false and is not a
hypothesis. The questions worth asking are magnitude, breadth, and whether the "no precision cost"
clause survives its own interval.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/run_multiengine_grouped.py
"""

from __future__ import annotations

import json
import os
import random
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import run_spike as rs            # noqa: E402
import run_multiengine as rm      # noqa: E402

# The committed baseline these per-repo counts must sum back to. A mismatch means the environment
# drifted (engine version, corpus, rules) — in which case the run must NOT be published under 0022's
# name, because it would be a different measurement wearing the old claim's label.
# Findings counts are pinned alongside true positives because precision is tp/findings: a ruleset
# update that adds findings matching no ground truth leaves every TP untouched, sails through a
# TP-only abort, and moves H3 — and because it enlarges the union denominator, it moves H3 in the
# NEGATIVE direction. The drift most able to falsify the precision clause was the one the abort could
# not see. All six numbers come from the committed baseline.
EXPECTED = {"repos": 63, "real": 1790, "bandit_tp": 234, "semgrep_tp": 212, "union_tp": 336,
            "bandit_findings": 1764, "semgrep_findings": 675, "union_findings": 2439}


def per_repo_stats() -> list[dict]:
    """Recall/precision inputs for every repo, kept separate instead of pooled."""
    out = []
    for slug in sorted(os.listdir(rs.REPOS)):
        gt = rs.load_gt(slug)
        if not gt:
            continue
        path = os.path.join(rs.REPOS, slug)
        real = sum(1 for g in gt if g["is_vulnerable"])

        bandit = rs.bandit_findings(path)
        semgrep = rm.semgrep_findings(path)

        # Each engine gets its own claim set; the union gets one shared set so a ground-truth entry is
        # credited at most once no matter how many engines flag it.
        c_b: set[int] = set()
        tp_b = sum(1 for f in bandit if rs.match(f, gt, c_b))
        c_s: set[int] = set()
        tp_s = sum(1 for f in semgrep if rs.match(f, gt, c_s))
        c_u: set[int] = set()
        allf = bandit + semgrep
        tp_u = sum(1 for f in allf if rs.match(f, gt, c_u))

        out.append({"repo": slug, "real": real,
                    "bandit_findings": len(bandit), "bandit_tp": tp_b,
                    "semgrep_findings": len(semgrep), "semgrep_tp": tp_s,
                    "union_findings": len(allf), "union_tp": tp_u})
    return out


def _pooled(stats: list[dict]) -> dict:
    """Pool a (possibly resampled) list of repos into the same ratios 0022 published."""
    real = sum(s["real"] for s in stats)
    if real == 0:
        return {}
    out = {}
    for eng in ("bandit", "semgrep", "union"):
        tp = sum(s[f"{eng}_tp"] for s in stats)
        fi = sum(s[f"{eng}_findings"] for s in stats)
        out[eng] = {"recall": tp / real, "precision": (tp / fi) if fi else None}
    return out


def main() -> int:
    if not os.path.isdir(rs.REPOS):
        print(f"FAIL: corpus not fetched — run {os.path.join(_HERE, 'fetch.sh')}")
        return 2

    stats = per_repo_stats()
    tot = {"repos": len(stats), "real": sum(s["real"] for s in stats),
           "bandit_tp": sum(s["bandit_tp"] for s in stats),
           "semgrep_tp": sum(s["semgrep_tp"] for s in stats),
           "union_tp": sum(s["union_tp"] for s in stats),
           "bandit_findings": sum(s["bandit_findings"] for s in stats),
           "semgrep_findings": sum(s["semgrep_findings"] for s in stats),
           "union_findings": sum(s["union_findings"] for s in stats)}
    print(f"per-repo totals: {tot}")
    drift = {k: (EXPECTED[k], tot[k]) for k in EXPECTED if EXPECTED[k] != tot[k]}
    if drift:
        # Fail closed: publishing different numbers under 0022's name would be a silent re-measurement.
        print(f"ABORT: totals differ from the committed baseline {drift} — the environment has drifted. "
              "Refusing to publish this run under decision 0022's claim.")
        return 2
    print("totals reproduce the committed baseline exactly — no environment drift")

    point = _pooled(stats)
    rel_gain = (point["union"]["recall"] - point["bandit"]["recall"]) / point["bandit"]["recall"]
    prec_delta = point["union"]["precision"] - point["bandit"]["precision"]

    # H2: breadth. Per-repo absolute recall gain, only over repos that HAVE real vulns.
    gains = sorted((s["union_tp"] - s["bandit_tp"]) / s["real"] for s in stats if s["real"])
    median_gain = gains[len(gains) // 2]
    zero_gain = sum(1 for s in stats if s["union_tp"] == s["bandit_tp"])

    # H1/H3: bootstrap over REPOSITORIES.
    random.seed(7)
    rels, precs = [], []
    for _ in range(2000):
        sample = [random.choice(stats) for _ in stats]
        p = _pooled(sample)
        if not p or not p["bandit"]["recall"]:
            continue
        rels.append((p["union"]["recall"] - p["bandit"]["recall"]) / p["bandit"]["recall"])
        if p["union"]["precision"] is not None and p["bandit"]["precision"] is not None:
            precs.append(p["union"]["precision"] - p["bandit"]["precision"])
    rels.sort(); precs.sort()
    r_lo, r_hi = rels[int(.025 * len(rels))], rels[int(.975 * len(rels))]
    p_lo, p_hi = precs[int(.025 * len(precs))], precs[int(.975 * len(precs))]

    print(f"\npooled point estimates (reproducing 0022): "
          f"bandit recall={point['bandit']['recall']:.4f}  union recall={point['union']['recall']:.4f}")
    print(f"\nH1 magnitude — relative recall gain = {rel_gain*100:+.1f}%  "
          f"95%CI=[{r_lo*100:+.1f}%,{r_hi*100:+.1f}%] (bootstrap over {len(stats)} repos)")
    print(f"   H1 {'HOLDS' if r_lo > 0.10 else 'FALSIFIED'} (predicted lower bound > +10%)")
    print(f"\nH2 breadth — median per-repo absolute recall gain = {median_gain:+.4f}; "
          f"{zero_gain}/{len(stats)} repos gain nothing")
    print(f"   H2 {'HOLDS' if median_gain > 0 else 'FALSIFIED'} (predicted median > 0)")
    print(f"\nH3 precision clause — delta = {prec_delta:+.4f}  95%CI=[{p_lo:+.4f},{p_hi:+.4f}]")
    if p_hi < 0:
        h3 = "FALSIFIED — adding an engine measurably COSTS precision"
    elif p_lo > 0:
        h3 = "precision measurably IMPROVES (CI excludes 0 upward)"
    else:
        h3 = "HOLDS — no measurable precision cost (CI includes 0); the point estimate alone means nothing"
    print(f"   H3 {h3}")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "totals": tot,
           "primary_estimand": "micro-pooled recall ratio; macro per-repo agrees (+40.7%)",
           "pooled": point, "relative_recall_gain": round(rel_gain, 4),
           "relative_gain_ci95": [round(r_lo, 4), round(r_hi, 4)],
           "median_per_repo_gain": round(median_gain, 4),
           "repos_with_zero_gain": zero_gain,
           "precision_delta": round(prec_delta, 4),
           "precision_delta_ci95": [round(p_lo, 4), round(p_hi, 4)],
           "corpus_note": "RealVuln repos are vc-*-seeded-v2-* with llm_generated_corpus=true "
                          "(LLM-seeded, not organic CVEs)",
           "per_repo": stats}
    with open(os.path.join(_HERE, "multiengine-grouped-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
