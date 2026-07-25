"""E19 arm C — the filename-only control, built BEFORE E19's result was read.

E19 strips two things at once: identifier/route identity (the memorisation cue) and the filename. A
filename like `accounts/views.py` is not only identity, it is semantic context — it says "this handles
requests", which is where absent controls live. So a drop in E19 would be ambiguous.

This arm shows the ORIGINAL, UNMUTATED source under a generic filename. It isolates the filename's
contribution:

    original + real filename   (E17)          -> 10/53
    original + generic filename (this arm)    -> ?
    mutated  + generic filename (E19)         -> ?

If this arm matches E17, the filename carries nothing and E19's delta is attributable to identity.
If this arm drops on its own, the filename was doing work and E19's delta cannot be read as memorisation.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/run_filename_control.py
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import run_spike as rs  # noqa: E402
from agent import trace  # noqa: E402
from mutate_source import mutate, structure_preserved  # noqa: E402
from run_generative import (MAX_BYTES, _BINARY_RUBRIC, _CANARY_SRC, classify_prose)  # noqa: E402

PRIOR = os.path.join(_HERE, "generative-260726.json")


def main() -> int:
    if not os.environ.get("LITELLM_MASTER_KEY"):
        print("FAIL: no gateway credential.")
        return 2
    model = os.environ.get("RECON_MODEL", "sast-grok45")
    from agent import llm

    def ask(shown_name: str, body: str, target: str) -> str:
        try:
            return llm.chat([llm.Msg("system", _BINARY_RUBRIC, llm.operator()),
                             llm.Msg("user", f"file: {shown_name}\n\n{body}",
                                     llm.target_derived(source="corpus-file", target=target))],
                            model=model, max_tokens=160, temperature=0.0)
        except Exception:
            return ""

    canary_ok = False
    for attempt in range(3):
        reply = ask("canary.py", _CANARY_SRC, "__canary__")
        if not reply.strip():
            print(f"  canary attempt {attempt + 1}: transport failure, retrying")
            continue
        canary_ok = classify_prose(reply) == "flagged"
        break
    if not canary_ok:
        print("FAIL: positive control did not fire on a substantive reply.")
        return 2
    print("positive control PASSED")

    prior = {(r["repo"], r["file"]): r["verdict"]
             for r in json.load(open(PRIOR, encoding="utf-8"))["rows"] if r["arm"] == "positive"}

    rows, pairs = [], []
    for (slug, rel), orig in prior.items():
        try:
            src = open(os.path.join(rs.REPOS, slug, rel), encoding="utf-8",
                       errors="replace").read()[:MAX_BYTES]
        except OSError:
            continue
        m = mutate(src)
        if not m or not structure_preserved(src, m):
            continue          # identical inclusion rule to E19, so the arms are comparable
        body = "\n".join(f"{i+1}: {ln}" for i, ln in enumerate(src.splitlines()))  # ORIGINAL source
        raw = ask("module.py", body, slug)                                          # generic filename
        v = classify_prose(raw)
        pairs.append((orig, v))
        rows.append({"repo": slug, "file": rel, "original": orig, "generic_name": v,
                     "response": trace.redact_persisted(raw[:600])})

    n = len(pairs)
    o = sum(1 for a, _ in pairs if a == "flagged")
    g = sum(1 for _, b in pairs if b == "flagged")
    b_lost = sum(1 for a, x in pairs if a == "flagged" and x != "flagged")
    c_gain = sum(1 for a, x in pairs if a != "flagged" and x == "flagged")
    from math import comb
    nd = b_lost + c_gain
    p = sum(comb(nd, k) for k in range(b_lost, nd + 1)) / (2 ** nd) if nd else 1.0

    print(f"\npaired files: {n}")
    print(f"  ORIGINAL + real filename   : {o}/{n} = {o/n:.3f}")
    print(f"  ORIGINAL + generic filename: {g}/{n} = {g/n:.3f}")
    print(f"  lost={b_lost} gained={c_gain}  McNemar exact one-sided p = {p:.4f}")
    print("  -> " + ("the FILENAME carries detection signal; E19's delta cannot be read as memorisation"
                     if p < 0.05 else
                     "the filename carries no measurable signal; E19's delta is attributable to identity"))

    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "model": model, "arm": "filename-only",
           "n_pairs": n, "original_flagged": o, "generic_name_flagged": g,
           "lost": b_lost, "gained": c_gain, "mcnemar_p_one_sided": round(p, 4), "rows": rows}
    with open(os.path.join(_HERE, "filename-control-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
