"""Multi-engine deterministic recall experiment (the 'ground the AI in more real tools' leg).

The single-engine baseline is the real problem: Bandit finds ~13% of RealVuln's real vulnerabilities.
No amount of LLM ranking fixes a miss — only more/better DETECTION does. This measures whether adding a
second deterministic engine (Semgrep security rulesets) raises the union recall, and what it costs in
precision, entirely without an LLM.

Per engine and for the union it reports: findings, matched true-positives, recall over the corpus's
real vulnerabilities, and precision. Ground-truth matching mirrors RealVuln (file + CWE + line ±10,
each ground-truth entry claimed once) — reusing run_spike's loaders so the two experiments agree.

    rag/.venv/bin/python evaluation/sast-fp-discrimination/run_multiengine.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for p in (_ROOT, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

import run_spike as rs  # noqa: E402  (bandit_findings / load_gt / match / _cwe_int)

SEMGREP_CONFIGS = ["p/security-audit", "p/owasp-top-ten", "p/python"]


def semgrep_findings(repo_path: str) -> list[dict]:
    """Run Semgrep security rulesets; normalise to the same finding shape as bandit_findings."""
    cmd = ["semgrep", "--json", "--quiet", "--disable-version-check", "--timeout", "20"]
    for c in SEMGREP_CONFIGS:
        cmd += ["--config", c]
    cmd.append(repo_path)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        results = json.loads(out.stdout).get("results", [])
    except Exception:
        return []
    findings = []
    for r in results:
        md = (r.get("extra") or {}).get("metadata") or {}
        cwes = md.get("cwe") or []
        cwe = rs._cwe_int(cwes[0].split(":")[0].strip()) if cwes else None
        findings.append({
            "rule_id": r.get("check_id", "semgrep"), "cwe": cwe,
            "file": os.path.relpath(r.get("path", ""), repo_path),
            "line": int((r.get("start") or {}).get("line", 0)),
            "code_slice": ((r.get("extra") or {}).get("lines") or "")[:400],
            "severity": ((r.get("extra") or {}).get("severity") or "").upper(),
        })
    return findings


def main() -> int:
    if not os.path.isdir(rs.REPOS):
        print(f"FAIL: corpus not fetched — run {os.path.join(_HERE, 'fetch.sh')}")
        return 2
    engines = {"bandit": rs.bandit_findings, "semgrep": semgrep_findings}
    stats = {k: {"findings": 0, "tp": 0} for k in engines}
    stats["union"] = {"findings": 0, "tp": 0}
    total_real = 0

    for slug in sorted(os.listdir(rs.REPOS)):
        repo = os.path.join(rs.REPOS, slug)
        gt = rs.load_gt(slug)
        total_real += sum(1 for g in gt if g["is_vulnerable"])

        per_engine = {name: fn(repo) for name, fn in engines.items()}
        for name, fs in per_engine.items():
            claimed: set[int] = set()      # independent claim set per engine
            stats[name]["findings"] += len(fs)
            stats[name]["tp"] += sum(1 for f in fs if rs.match(f, gt, claimed))

        # union: one shared claim set, so a ground-truth entry is credited at most once
        claimed_u: set[int] = set()
        allf = [f for fs in per_engine.values() for f in fs]
        stats["union"]["findings"] += len(allf)
        stats["union"]["tp"] += sum(1 for f in allf if rs.match(f, gt, claimed_u))

    for k, s in stats.items():
        s["recall"] = round(s["tp"] / total_real, 4) if total_real else None
        s["precision"] = round(s["tp"] / s["findings"], 4) if s["findings"] else None

    result = {"generated_at": datetime.now(timezone.utc).isoformat(),
              "repos": len(os.listdir(rs.REPOS)), "real_vulns_in_corpus": total_real,
              "semgrep_configs": SEMGREP_CONFIGS, "engines": stats}
    with open(os.path.join(_HERE, "multiengine-baseline-260725.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    print(f"corpus: {result['repos']} repos, {total_real} real vulnerabilities")
    for k in ("bandit", "semgrep", "union"):
        s = stats[k]
        print(f"  {k:8s} findings={s['findings']:5d}  TP={s['tp']:4d}  "
              f"recall={s['recall']:.3f}  precision={s['precision'] if s['precision'] is not None else 'n/a'}")
    b, u = stats["bandit"]["recall"], stats["union"]["recall"]
    if b is not None and u is not None:
        print(f"\nunion vs bandit-only: recall {b:.3f} -> {u:.3f} ({u-b:+.3f}, "
              f"{'+' if u > b else ''}{(u/b-1)*100:.0f}% relative)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
