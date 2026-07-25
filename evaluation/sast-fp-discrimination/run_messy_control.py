"""E18 arm B — does the model manufacture absence-class findings on merely messy code?

E17 showed the model flags absence-class vulnerable files more than CLEAN files. Clean files cannot
distinguish "detects absent controls" from "reacts to defective code", because they differ in both.
This arm holds defectiveness FIXED: every file here has real ground-truth vulnerabilities, but only of
PRESENCE classes (XSS, hardcoded credentials, cleartext storage...). None has an absent control.

The classifier counts only absence-of-control vocabulary, so a model that correctly reports "XSS here"
scores clean — which is right. A high flag rate in this arm means the model invents absence-class
language when shown bad code; a low one means it is discriminating by class.

Everything imported from run_generative is FROZEN (prompt, classifier, positive control).

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/run_messy_control.py
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

import run_spike as rs  # noqa: E402
from agent import trace  # noqa: E402
from run_generative import (BLIND, MAX_BYTES, _BINARY_RUBRIC, _CANARY_SRC, _load_gt_index,
                            classify_prose)  # noqa: E402

N_B = int(os.environ.get("E18_N", "80"))


def pick_messy_no_absence(seed: int = 11) -> list[tuple]:
    """Files with REAL vulnerabilities, none of them absence-class."""
    idx = _load_gt_index()
    out = []
    for (slug, f), entries in idx.items():
        vuln = [e for e in entries if e["is_vulnerable"]]
        if not vuln:
            continue
        if {e["primary"] for e in vuln} & BLIND:
            continue                      # has an absent control -> belongs to arm A, not here
        out.append((slug, f))
    rnd = random.Random(seed)
    rnd.shuffle(out)
    return out[:N_B]


def main() -> int:
    if not os.environ.get("LITELLM_MASTER_KEY"):
        print("FAIL: no gateway credential — a zero from a dead model is not a measurement.")
        return 2
    model = os.environ.get("RECON_MODEL", "sast-grok45")
    from agent import llm

    def query(slug, relpath, literal=None):
        if literal is not None:
            body = literal
        else:
            try:
                src = open(os.path.join(rs.REPOS, slug, relpath), encoding="utf-8",
                           errors="replace").read()[:MAX_BYTES]
            except OSError:
                return ""
            body = "\n".join(f"{i+1}: {ln}" for i, ln in enumerate(src.splitlines()))
        try:
            return llm.chat([llm.Msg("system", _BINARY_RUBRIC, llm.operator()),
                             llm.Msg("user", f"file: {relpath}\n\n{body}",
                                     llm.target_derived(source="corpus-file", target=slug))],
                            model=model, max_tokens=160, temperature=0.0)
        except Exception:
            return ""

    if classify_prose(query("__canary__", "canary.py", literal=_CANARY_SRC)) != "flagged":
        print("FAIL: positive control did not fire; the harness, not the hypothesis, would be measured.")
        return 2
    print("positive control PASSED")

    files = pick_messy_no_absence()
    print(f"arm B: {len(files)} files with REAL vulns but NO absence-class vuln, model={model}\n")
    counts, rows = {}, []
    for slug, relpath in files:
        raw = query(slug, relpath)
        v = classify_prose(raw)
        counts[v] = counts.get(v, 0) + 1
        rows.append({"repo": slug, "file": relpath, "verdict": v,
                     "response": trace.redact_persisted(raw[:600])})

    flagged = counts.get("flagged", 0)
    print(f"arm B verdicts: {counts}")
    print(f"absence-class flag rate on MESSY-but-no-absence files = {flagged}/{len(files)} = "
          f"{flagged/len(files):.3f}")
    print(f"(arm A, E17: 10/60 = 0.167)")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "model": model,
           "arm": "messy-no-absence", "n": len(files), "counts": counts,
           "flag_rate": round(flagged / len(files), 4), "rows": rows}
    with open(os.path.join(_HERE, "messy-control-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
