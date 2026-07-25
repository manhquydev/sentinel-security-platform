"""Live viability spike: Bandit -> match to RealVuln ground truth -> clean-room verifier -> score.

Runs the SAST engine (Bandit — high-volume Python engine, the FP source the verifier is meant to
filter) over the fetched subset, matches each finding to RealVuln's ground truth (file + CWE + line
±10, claim-once), triages the residual through agent/verifier (LIVE gateway), and scores the
verifier's MARGINAL FP-reduction with scorer.py. Writes verdict fixtures + a baseline snapshot so the
scoring re-runs offline. A miss is an accepted, documented negative result (no module built).

    set -a; . infra/.env; set +a
    rag/.venv/bin/python evaluation/sast-fp-discrimination/run_spike.py
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

from agent.verifier import gate, verify as vmod   # noqa: E402
import importlib.util                              # noqa: E402
_sc = importlib.util.spec_from_file_location("scorer", os.path.join(_HERE, "scorer.py"))
scorer = importlib.util.module_from_spec(_sc); _sc.loader.exec_module(scorer)  # type: ignore

CORPUS = os.path.join(_HERE, "corpus")
REPOS = os.path.join(CORPUS, "repos")
GT_DIR = os.path.join(CORPUS, "Real-Vuln-Benchmark", "ground-truth")
BANDIT = os.path.join(_ROOT, "rag", ".venv", "bin", "bandit")
MODEL = os.environ.get("RECON_MODEL", "sast-sol")
LINE_TOL = 10


def _cwe_int(s) -> int | None:
    if isinstance(s, int):
        return s
    if isinstance(s, str) and s.upper().startswith("CWE-"):
        try:
            return int(s.split("-", 1)[1])
        except ValueError:
            return None
    return None


def bandit_findings(repo_path: str) -> list[dict]:
    out = subprocess.run([BANDIT, "-r", repo_path, "-f", "json", "-q"],
                         capture_output=True, text=True)
    try:
        results = json.loads(out.stdout).get("results", [])
    except json.JSONDecodeError:
        return []
    findings = []
    for r in results:
        cwe = _cwe_int((r.get("issue_cwe") or {}).get("id"))
        rel = os.path.relpath(r["filename"], repo_path)
        findings.append({"rule_id": r.get("test_id", "bandit"), "cwe": cwe, "file": rel,
                         "line": int(r.get("line_number", 0)), "code_slice": r.get("code", ""),
                         "severity": (r.get("issue_severity") or "").upper()})
    return findings


def load_gt(slug: str) -> list[dict]:
    path = os.path.join(GT_DIR, slug, "ground-truth.json")
    if not os.path.exists(path):
        return []
    data = json.load(open(path, encoding="utf-8"))
    entries = data if isinstance(data, list) else next(
        (v for v in data.values() if isinstance(v, list)), [])
    gt = []
    for e in entries:
        cwes = {_cwe_int(c) for c in ([e.get("primary_cwe")] + (e.get("acceptable_cwes") or []))}
        gt.append({"is_vulnerable": bool(e.get("is_vulnerable")),
                   "cwes": {c for c in cwes if c is not None},
                   "file": e.get("file", ""),
                   "line": int((e.get("location") or {}).get("start_line", 0))})
    return gt


def match(finding: dict, gt: list[dict], claimed: set[int]) -> bool | None:
    """Return the matched entry's is_vulnerable, or None if unmatched. Claim-once."""
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
        return g["is_vulnerable"]
    return None


def main() -> int:
    if not os.path.isdir(REPOS):
        print(f"FAIL: corpus not fetched — run {os.path.join(_HERE, 'fetch.sh')}")
        return 2
    live = bool(os.environ.get("LITELLM_MASTER_KEY"))
    # 1. collect findings + ground-truth match ONCE (deterministic, no LLM)
    findings = []
    for slug in sorted(os.listdir(REPOS)):
        gt = load_gt(slug)
        claimed: set[int] = set()
        for f in bandit_findings(os.path.join(REPOS, slug)):
            f["is_vulnerable"] = bool(match(f, gt, claimed))
            f["gate_autokept"] = gate.is_high_precision(f["rule_id"])
            findings.append(f)

    # 2. score under each provenance condition (target-derived = security-correct; operator = the
    #    forbidden trust downgrade — measured only to show inaccurate-vs-unreachable, mirroring W10)
    conditions = {}
    for prov in (["target-derived", "operator"] if live else []):
        records, captured, integ = [], [], {}
        for f in findings:
            rec = {"is_vulnerable": f["is_vulnerable"], "gate_autokept": f["gate_autokept"]}
            if f["gate_autokept"]:
                rec["verifier_effective"] = None
            else:
                v = vmod.verify(vmod.Finding(f["rule_id"], f["cwe"], f["file"], f["line"], f["code_slice"]),
                                model=MODEL, provenance=prov)
                rec["verifier_effective"] = v.effective
                integ[v.integrity] = integ.get(v.integrity, 0) + 1
                captured.append({"provenance": prov, "cwe": f["cwe"], "file": f["file"], "line": f["line"],
                                 "matched_is_vulnerable": f["is_vulnerable"], "raw": v.raw,
                                 "effective": v.effective, "integrity": v.integrity})
            records.append(rec)
        conditions[prov] = {"score": scorer.score(records), "integrity": integ, "verdicts": captured}

    subset = sorted(os.listdir(REPOS))
    snapshot = {"generated_at": datetime.now(timezone.utc).isoformat(), "live": live, "model": MODEL,
                "subset": subset, "n_findings": len(findings),
                "conditions": {k: {"score": v["score"], "integrity": v["integrity"]}
                               for k, v in conditions.items()}}
    with open(os.path.join(_HERE, "baseline-260725.json"), "w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, indent=2)
    os.makedirs(os.path.join(_HERE, "captured"), exist_ok=True)
    with open(os.path.join(_HERE, "captured", "verdicts.json"), "w", encoding="utf-8") as fh:
        json.dump({"model": MODEL, "conditions": {k: v["verdicts"] for k, v in conditions.items()}}, fh, indent=2)

    print(f"live={live} model={MODEL} findings={len(findings)} "
          f"(TP={sum(f['is_vulnerable'] for f in findings)}, FP={sum(not f['is_vulnerable'] for f in findings)})")
    for prov, c in conditions.items():
        s = c["score"]; vm = s["verifier_marginal"]
        print(f"\n[{prov}] FP-reduction={vm['fp_reduction_rate']} ({vm['fp_removed']}/{vm['fp_total']})  "
              f"precision {s['gate_only']['precision']}->{s['gate_plus_verifier']['precision']}  "
              f"recall_ok={s['recall_ok']}  integrity={c['integrity']}")
    if not live:
        print("SKIP: no LITELLM_MASTER_KEY — live measurement needs the gateway.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
