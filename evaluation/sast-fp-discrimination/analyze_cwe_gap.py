"""Per-CWE detection-gap analysis: which vulnerability classes does each engine actually cover?

Decision 0022 measured that Bandit ∪ Semgrep reach 18.8% recall and miss 81%. Aggregate recall does not
say WHICH classes are missed, and that is what decides which further engines (OpenGrep, gosec,
Brakeman, js-x-ray…) or which detection MODE (runtime/DAST) is worth adding. This breaks the corpus
down per CWE: how many real vulnerabilities exist, how many each engine detects, and which classes are
detected by nobody ("blind" classes).

Pure analysis over the fetched corpus + the engines' own output — deterministic, no LLM, reproducible.

    rag/.venv/bin/python evaluation/sast-fp-discrimination/analyze_cwe_gap.py
"""

from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for p in (_ROOT, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

import run_spike as rs                        # noqa: E402
from run_multiengine import semgrep_findings  # noqa: E402

ENGINES = {"bandit": rs.bandit_findings, "semgrep": semgrep_findings}
LINE_TOL = rs.LINE_TOL


def match_index(finding: dict, gt: list[dict], claimed: set[int]) -> int | None:
    """Same rule as run_spike.match (file + CWE + line ±10, claim-once) but returns WHICH ground-truth
    entry matched, so the hit can be attributed to that entry's CWE."""
    for i, g in enumerate(gt):
        if i in claimed:
            continue
        if not (finding["file"].endswith(g["file"]) or g["file"].endswith(finding["file"])):
            continue
        if finding["cwe"] is not None and finding["cwe"] not in g["cwes"]:
            continue
        if abs(finding["line"] - g["line"]) > LINE_TOL:
            continue
        claimed.add(i)
        return i
    return None


def _primary(g: dict):
    return min(g["cwes"]) if g["cwes"] else None


def main() -> int:
    if not os.path.isdir(rs.REPOS):
        print(f"FAIL: corpus not fetched — run {os.path.join(_HERE, 'fetch.sh')}")
        return 2

    total: dict = defaultdict(int)
    hit = {name: defaultdict(int) for name in ENGINES}
    hit["union"] = defaultdict(int)

    for slug in sorted(os.listdir(rs.REPOS)):
        repo = os.path.join(rs.REPOS, slug)
        gt = rs.load_gt(slug)
        for g in gt:
            if g["is_vulnerable"]:
                total[_primary(g)] += 1

        per_engine = {name: fn(repo) for name, fn in ENGINES.items()}
        for name, fs in per_engine.items():
            claimed: set[int] = set()
            for f in fs:
                idx = match_index(f, gt, claimed)
                if idx is not None and gt[idx]["is_vulnerable"]:
                    hit[name][_primary(gt[idx])] += 1
        claimed_u: set[int] = set()
        for f in [x for fs in per_engine.values() for x in fs]:
            idx = match_index(f, gt, claimed_u)
            if idx is not None and gt[idx]["is_vulnerable"]:
                hit["union"][_primary(gt[idx])] += 1

    rows = []
    for cwe, n in sorted(total.items(), key=lambda kv: -kv[1]):
        u = hit["union"].get(cwe, 0)
        rows.append({"cwe": cwe, "real": n, "bandit": hit["bandit"].get(cwe, 0),
                     "semgrep": hit["semgrep"].get(cwe, 0), "union": u,
                     "recall": round(u / n, 3) if n else None})

    blind = [r for r in rows if r["union"] == 0]
    blind_n = sum(r["real"] for r in blind)
    total_real = sum(total.values())
    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "total_real": total_real,
           "classes": len(rows), "blind_classes": len(blind), "blind_real_vulns": blind_n,
           "per_cwe": rows}
    with open(os.path.join(_HERE, "cwe-gap-260725.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    print(f"corpus: {total_real} real vulns across {len(rows)} CWE classes")
    print(f"{'CWE':>7} {'real':>5} {'bandit':>7} {'semgrep':>8} {'union':>6} {'recall':>7}")
    for r in rows[:18]:
        print(f"{str(r['cwe']):>7} {r['real']:>5} {r['bandit']:>7} {r['semgrep']:>8} "
              f"{r['union']:>6} {str(r['recall']):>7}")
    print(f"\nBLIND classes (union detects 0): {len(blind)}/{len(rows)} classes = {blind_n} real vulns "
          f"({blind_n/total_real:.0%} of the corpus)")
    print(f"  blind CWEs by volume: {[r['cwe'] for r in sorted(blind, key=lambda r: -r['real'])[:12]]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
