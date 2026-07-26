"""Ranking baselines + the self-red-team that corrected decision 0021.

Compares three ways to order SAST findings for a human triager (NONE of which ever drops a finding —
recall is always 1.0):

  1. deterministic severity        — the scanner's own severity
  2. deterministic CWE-prior       — Laplace-smoothed P(real|CWE) fit on a labelled dev split (SUPERVISED)
  3. LLM annotator                 — agent/verifier/annotate.py, ZERO-SHOT (no labels needed)

The finding (0021 amendment): where labels exist the free CWE-prior SIGNIFICANTLY beats the LLM
(paired bootstrap excludes 0), so the LLM belongs only in the cold-start / no-labels case. Reads the
committed annotate baseline, so it re-runs offline with no gateway.

    rag/.venv/bin/python evaluation/sast-fp-discrimination/rank_baselines.py
"""

from __future__ import annotations

import json
import os
import random
from collections import defaultdict

_HERE = os.path.dirname(os.path.abspath(__file__))
BASELINE = os.path.join(_HERE, "annotate-baseline-260725.json")
SEVERITY = {"HIGH": 1.0, "MEDIUM": 0.6, "LOW": 0.3, "": 0.5}


def auc(pairs: list[tuple[float, bool]]) -> float | None:
    """Concordance: P(score[real] > score[fp]), ties 0.5."""
    tp = [s for s, v in pairs if v]
    fp = [s for s, v in pairs if not v]
    if not tp or not fp:
        return None
    return sum(1.0 if a > b else 0.5 if a == b else 0.0 for a in tp for b in fp) / (len(tp) * len(fp))


def fit_cwe_prior(rows: list[dict]) -> tuple[dict, float]:
    """Laplace-smoothed P(real vulnerability | CWE) from LABELLED findings (supervised)."""
    counts: dict = defaultdict(lambda: [0, 0])
    for r in rows:
        c = counts[r["cwe"]]
        c[0] += bool(r["is_vulnerable"])
        c[1] += 1
    prior = {k: (v[0] + 1) / (v[1] + 2) for k, v in counts.items()}
    base = sum(bool(r["is_vulnerable"]) for r in rows) / len(rows) if rows else 0.5
    return prior, base


def score_rows(rows: list[dict], kind: str, prior: dict, base: float) -> list[tuple[float, bool]]:
    out = []
    for r in rows:
        if kind == "severity":
            s = r.get("det_score", SEVERITY.get((r.get("severity") or "").upper(), 0.5))
        elif kind == "cwe_prior":
            s = prior.get(r["cwe"], base)
        else:  # llm
            p = r.get("llm_priority")
            s = p if p is not None else 0.5
        out.append((s, bool(r["is_vulnerable"])))
    return out


def main() -> int:
    if not os.path.exists(BASELINE):
        print(f"FAIL: {BASELINE} missing — run run_annotate.py first")
        return 2
    rows = json.load(open(BASELINE, encoding="utf-8"))["rows"]
    rs = rows[:]
    random.seed(0)
    random.shuffle(rs)
    half = len(rs) // 2
    dev, held = rs[:half], rs[half:]
    # NOTE: this split is BY ROW, and rows from one repo land on both sides. It prevents row leakage
    # but not REPO leakage, which is the leakage that matters: the prior learns a repo's answer key and
    # is then graded on that same repo. Measured cost of this mistake: +0.057 AUC (E14). Kept only to
    # demonstrate the artefact; the verdict now comes from rank_grouped.py.
    prior, base = fit_cwe_prior(dev)

    res = {k: auc(score_rows(held, k, prior, base)) for k in ("severity", "cwe_prior", "llm")}
    ntp = sum(bool(r["is_vulnerable"]) for r in held)
    print(f"held-out n={len(held)} (TP={ntp}, FP={len(held)-ntp}); prior fit on {len(dev)} labelled findings")
    for k, v in res.items():
        print(f"  {k:12s} AUC={v:.3f}" if v is not None else f"  {k}: n/a")

    # paired bootstrap: is the deterministic prior reliably better than the LLM?
    random.seed(1)
    diffs = []
    for _ in range(2000):
        samp = [random.choice(held) for _ in held]
        a = auc(score_rows(samp, "cwe_prior", prior, base))
        b = auc(score_rows(samp, "llm", prior, base))
        if a is not None and b is not None:
            diffs.append(a - b)
    diffs.sort()
    lo, hi = diffs[int(0.025 * len(diffs))], diffs[int(0.975 * len(diffs))]
    print(f"\n[ROW-SPLIT — LEAKY, NOT A VERDICT] AUC(cwe_prior) - AUC(llm) = "
          f"{sum(diffs)/len(diffs):+.3f} 95%CI=[{lo:+.3f},{hi:+.3f}]")
    print("This number is RETRACTED as a finding. The split above is by ROW, so rows from one repo sit\n"
          "on both sides and the prior is graded on repos it was fitted on. Under leave-one-repo-out the\n"
          "SAME data gives +0.012 [-0.006,+0.035] — a TIE (E14; decision 0021 as amended).\n"
          "For the verdict run: rank_grouped.py")
    print("NOTE: the prior is SUPERVISED (needs labels); the LLM is ZERO-SHOT. Use the prior where "
          "labels exist; the LLM only for cold start (decision 0021 amendment).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
