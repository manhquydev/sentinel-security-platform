"""What does the deterministic rule add to the model, on a denominator anyone can check?

E58 answered this and published **+0.104 at k=1 (0.208 -> 0.312)**. That number was computed inline and
**no instrument was ever committed**, so it cannot be re-derived — which is the whole point of the guards
this project runs. Its denominator implies 48 files (10/48 -> 15/48); the two statable file sets in the
committed artefacts are 60 (every distinct file in the positive arm) and 40 (those carrying a ground-truth
CWE-306/862 entry, the only ones the rule can reach). Neither is 48. So the published figure is not
reproducible and this script replaces it.

TWO IMPROVEMENTS OVER WHAT IT REPLACES.

1. **Both denominators are reported**, because they answer different questions. Over all positive-arm
   files, the rule looks weaker than it is: it covers two CWE classes and the arm contains many others.
   Over absence-class-eligible files it is measured where it can actually fire. Neither is "the" number
   and quoting either without saying which is the mistake E58 made.

2. **k=1 is averaged over every reading on disk, not taken from one.** E47 established the model behaves
   as a rate, so a single reading's k=1 is one draw. Every `generative*-260726.json` with a positive arm
   contributes one reading; the rule is deterministic and identical in all of them.

WHAT WOULD FALSIFY THE COMPLEMENTARITY CLAIM: overlap at or above the independence expectation, or a mean
increment whose spread across readings covers zero.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/pool_rule_model_union.py
"""

from __future__ import annotations

import glob
import json
import os
import statistics
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import run_spike as rs  # noqa: E402
import detect_absent_auth as det  # noqa: E402


def _norm(p: str) -> str:
    return p.replace("\\", "/")


def detector_hits(files: list[tuple[str, str]]) -> set[tuple[str, str]]:
    """Files where the rule makes a CORRECT detection — matched against ground truth, not merely fired.

    E58's first pass counted file-level firing rather than correctness and overstated the result 3x. The
    matcher is the project's own: file + CWE + line tolerance, claim-once.
    """
    hit = set()
    for slug, rel in files:
        path = os.path.join(rs.REPOS, slug, rel)
        try:
            src = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        gt = rs.load_gt(slug) or []
        claimed: set[int] = set()
        if any(rs.match(f, gt, claimed) for f in det.findings_for(src, rel)):
            hit.add((slug, rel))
    return hit


def absence_eligible(files: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Files carrying a ground-truth CWE-306/862 entry — where the rule can fire at all."""
    out = []
    for slug, rel in files:
        gt = rs.load_gt(slug) or []
        if any(e["is_vulnerable"] and (306 in e["cwes"] or 862 in e["cwes"])
               and _norm(e["file"]) == _norm(rel) for e in gt):
            out.append((slug, rel))
    return out


def readings() -> list[tuple[str, list[dict]]]:
    """Every committed generative artefact carrying a positive arm, one reading each."""
    out = []
    for path in sorted(glob.glob(os.path.join(_HERE, "generative*-260726.json"))):
        try:
            rows = json.load(open(path, encoding="utf-8")).get("rows") or []
        except (OSError, json.JSONDecodeError):
            continue
        pos = [r for r in rows if r.get("arm") == "positive"]
        if pos:
            out.append((os.path.basename(path), pos))
    return out


def report(name: str, eligible: set[tuple[str, str]], reads: list[tuple[str, list[dict]]]) -> dict:
    """Per reading, measure BOTH arms on the files that reading actually read.

    Pooling against one fixed universe is wrong here: the disjoint-sample readings cover a different file
    set by design, so intersecting them with another reading's files scores them as "the model flagged
    nothing" and inflates the rule's increment. Each reading therefore contributes its own denominator —
    its positive-arm files that are eligible — and the rule is re-measured on exactly those files.
    """
    per = []
    for art, pos in reads:
        seen = {(r["repo"], r["file"]) for r in pos} & eligible
        if len(seen) < 10:
            continue                      # too few shared files for a rate to mean anything
        rule = detector_hits(sorted(seen))
        model = {(r["repo"], r["file"]) for r in pos if r.get("verdict") == "flagged"} & seen
        k = len(seen)
        union = model | rule
        per.append({"artefact": art, "files": k, "model": len(model) / k, "rule": len(rule) / k,
                    "union": len(union) / k, "overlap": len(model & rule),
                    "exp_overlap": len(model) * len(rule) / k,
                    "increment": (len(union) - len(model)) / k})
    if not per:
        return {}
    n = round(statistics.mean(p["files"] for p in per))
    m = [p["model"] for p in per]
    u = [p["union"] for p in per]
    inc = [p["increment"] for p in per]
    ov = [p["overlap"] for p in per]
    rule = int(round(statistics.mean(p["rule"] for p in per) * n))
    exp_ov = statistics.mean(p["exp_overlap"] for p in per)
    d = {"denominator": name, "mean_files_per_reading": n, "readings": len(per),
         "rule_correct_mean": rule, "rule_recall": round(rule / n, 4),
         "model_mean": round(statistics.mean(m), 4),
         "model_range": [round(min(m), 4), round(max(m), 4)],
         "union_mean": round(statistics.mean(u), 4),
         "increment_mean": round(statistics.mean(inc), 4),
         "increment_range": [round(min(inc), 4), round(max(inc), 4)],
         "increment_covers_zero": min(inc) <= 0,
         "overlap_mean": round(statistics.mean(ov), 3),
         "overlap_expected_if_independent": round(exp_ov, 3)}
    print(f"\n=== {name} — {n} files/reading (mean), {len(per)} readings ===")
    print(f"  rule (deterministic, correct)     : {rule}/{n} = {rule/n:.3f}")
    print(f"  model, mean over readings         : {statistics.mean(m):.3f} "
          f"[{min(m):.3f}, {max(m):.3f}]")
    print(f"  union, mean over readings         : {statistics.mean(u):.3f}")
    print(f"  RULE ADDS, mean                   : +{statistics.mean(inc):.3f} "
          f"[{min(inc):.3f}, {max(inc):.3f}]")
    print(f"  overlap observed / independent    : {statistics.mean(ov):.2f} / {exp_ov:.2f}")
    return d


def main() -> int:
    if not os.path.isdir(rs.REPOS):
        print("FAIL: corpus not fetched")
        return 2
    if not det.self_test():
        print("FAIL: the detector no longer separates protected from unprotected routes.")
        return 2
    reads = readings()
    if not reads:
        print("FAIL: no committed generative artefact carries a positive arm.")
        return 2
    base = json.load(open(os.path.join(_HERE, "generative-260726.json"), encoding="utf-8"))
    files = sorted({(r["repo"], r["file"]) for r in base["rows"] if r["arm"] == "positive"})
    print(f"readings found: {len(reads)}   positive-arm files: {len(files)}")

    every = sorted({(r["repo"], r["file"]) for _, pos in reads for r in pos})
    all_files = report("all positive-arm files", set(every), reads)
    elig = report("files carrying a GT CWE-306/862 entry", set(absence_eligible(every)), reads)

    print("\nE58 published +0.104 at k=1 on a denominator of 48, which matches neither file set and was")
    print("computed with no committed instrument. It is superseded by the figures above.")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(),
           "question": "what does the deterministic rule add to the model, per reading?",
           "supersedes": "E58's +0.104, which had no committed instrument and a denominator of 48 that "
                         "matches neither statable file set",
           "matcher": "run_spike.match — file + CWE + line tolerance, claim-once; correctness, not firing",
           "results": [d for d in (all_files, elig) if d]}
    with open(os.path.join(_HERE, "rule-model-union-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
