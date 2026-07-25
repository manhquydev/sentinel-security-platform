"""Ranking experiment: does the NON-LOAD-BEARING LLM annotator rank real vulns above FP-traps
better than a deterministic severity ranking? (The honest upgrade from decision 0020.)

Nothing is dropped — recall is preserved by construction — so the only question is ranking QUALITY.
Measured as AUC (concordance): over all (true-positive, false-positive) finding pairs, the fraction
where the ranker scored the TP strictly higher (ties count 0.5). AUC 0.5 = no value, >0.5 = surfaces
real vulns first, <0.5 = actively misleading. Compares: deterministic severity ranking vs the LLM
annotator (agent/verifier/annotate.py). If the LLM does not beat deterministic, deterministic wins
(the measured-not-trusted ethos), and this is an honest negative — like the drop-verifier spike.

    set -a; . infra/.env; set +a
    rag/.venv/bin/python evaluation/sast-fp-discrimination/run_annotate.py
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for p in (_ROOT, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

import run_spike as rs                          # reuse bandit_findings/load_gt/match  # noqa: E402
from agent.verifier import annotate as ann      # noqa: E402

_SEV = {"HIGH": 1.0, "MEDIUM": 0.6, "LOW": 0.3, "": 0.5}


def _auc(scored: list[tuple[float, bool]]) -> float | None:
    """Concordance: P(score[TP] > score[FP]) over all TP/FP pairs, ties=0.5."""
    tp = [s for s, v in scored if v]
    fp = [s for s, v in scored if not v]
    if not tp or not fp:
        return None
    wins = sum((1.0 if a > b else 0.5 if a == b else 0.0) for a in tp for b in fp)
    return round(wins / (len(tp) * len(fp)), 4)


def main() -> int:
    if not os.path.isdir(rs.REPOS):
        print(f"FAIL: corpus not fetched — run {os.path.join(_HERE, 'fetch.sh')}")
        return 2
    live = bool(os.environ.get("LITELLM_MASTER_KEY"))
    model = os.environ.get("RECON_MODEL", "sast-grok45")

    findings = []
    for slug in sorted(os.listdir(rs.REPOS)):
        gt = rs.load_gt(slug)
        claimed: set[int] = set()
        for f in rs.bandit_findings(os.path.join(rs.REPOS, slug)):
            f["is_vulnerable"] = bool(rs.match(f, gt, claimed))
            findings.append(f)

    det = [(_SEV.get(f.get("severity", ""), 0.5), f["is_vulnerable"]) for f in findings]
    rows = [{"cwe": f["cwe"], "severity": f.get("severity"), "is_vulnerable": f["is_vulnerable"],
             "det_score": _SEV.get(f.get("severity", ""), 0.5)} for f in findings]

    llm_scored, llm_ok = None, 0
    if live:
        llm = []
        for f, r in zip(findings, rows):
            p = ann.annotate(f["rule_id"], f["cwe"], f.get("severity", ""), model=model)
            r["llm_priority"] = p
            llm_ok += int(p is not None)
            llm.append((p if p is not None else 0.5, f["is_vulnerable"]))  # unparseable -> neutral
        llm_scored = llm

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(), "live": live, "model": model,
        "n_findings": len(findings), "tp": sum(f["is_vulnerable"] for f in findings),
        "fp": sum(not f["is_vulnerable"] for f in findings),
        "recall": 1.0,  # nothing is ever dropped — the whole point
        "auc_deterministic_severity": _auc(det),
        "auc_llm_annotator": _auc(llm_scored) if llm_scored else None,
        "llm_conformance": {"ok": llm_ok, "total": len(findings)} if live else None,
    }
    with open(os.path.join(_HERE, "annotate-baseline-260725.json"), "w", encoding="utf-8") as fh:
        json.dump({**result, "rows": rows}, fh, indent=2)

    print(json.dumps({k: v for k, v in result.items()}, indent=2))
    det_auc, llm_auc = result["auc_deterministic_severity"], result["auc_llm_annotator"]
    print(f"\nRESULT (recall=1.0, nothing dropped): deterministic-severity AUC={det_auc}"
          + (f"  vs  LLM-annotator AUC={llm_auc} (conformance {llm_ok}/{len(findings)})" if live else " (LLM SKIP: no key)"))
    if live and det_auc is not None and llm_auc is not None:
        verdict = ("LLM ADDS ranking value" if llm_auc > det_auc + 0.02 else
                   "deterministic ranking is as good or better (ethos holds)")
        print(f"VERDICT: {verdict}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
