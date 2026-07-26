"""E32 — does detection survive SURFACE + STRUCTURAL anonymisation?

E23 changed names and left shapes. This changes both: identifiers, route literals and filename are
anonymised, and top-level definitions are permuted where that is provably safe.

Both arms measured fresh in the same run and compared as aggregate rates, because the instrument flips
~40% of raw verdicts (E22/E29) and a per-file comparison would measure the noise.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/run_structural_transfer.py
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
from mutate_structure import mutate_full  # noqa: E402
from run_generative import (MAX_BYTES, _BINARY_RUBRIC, _CANARY_SRC, classify_prose)  # noqa: E402

PRIOR = os.path.join(_HERE, "generative-260726.json")


def main() -> int:
    if not os.environ.get("LITELLM_MASTER_KEY"):
        print("FAIL: no gateway credential.")
        return 2
    model = os.environ.get("RECON_MODEL", "sast-grok45")
    from agent import llm

    def ask(name: str, body: str, target: str) -> str:
        try:
            return llm.chat([llm.Msg("system", _BINARY_RUBRIC, llm.operator()),
                             llm.Msg("user", f"file: {name}\n\n{body}",
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

    files = [(r["repo"], r["file"]) for r in json.load(open(PRIOR, encoding="utf-8"))["rows"]
             if r["arm"] == "positive"]

    rows = []
    for slug, rel in files:
        path = os.path.join(rs.REPOS, slug, rel)
        if not os.path.exists(path):
            continue
        src = open(path, encoding="utf-8", errors="replace").read()[:MAX_BYTES]
        mut = mutate_full(src)
        if not mut or mut == src:
            continue                                   # excluded, never forced

        o_body = "\n".join(f"{i+1}: {ln}" for i, ln in enumerate(src.splitlines()))
        m_body = "\n".join(f"{i+1}: {ln}" for i, ln in enumerate(mut.splitlines()))

        raw_o = ask(rel, o_body, slug)                 # original, real filename
        raw_m = ask("module.py", m_body, "anonymised")  # anonymised + reordered
        rows.append({"repo": slug, "file": rel,
                     "original": classify_prose(raw_o), "mutated": classify_prose(raw_m),
                     "resp_original": trace.redact_persisted(raw_o[:4000]),
                     "resp_mutated": trace.redact_persisted(raw_m[:4000])})

    n = len(rows)
    o = sum(1 for r in rows if r["original"] == "flagged")
    m = sum(1 for r in rows if r["mutated"] == "flagged")

    rnd = random.Random(23)
    diffs = []
    for _ in range(20000):
        s = [rnd.choice(rows) for _ in rows]
        diffs.append(sum(1 for r in s if r["mutated"] == "flagged") / n
                     - sum(1 for r in s if r["original"] == "flagged") / n)
    diffs.sort()
    lo, hi = diffs[int(.025 * len(diffs))], diffs[int(.975 * len(diffs))]

    print(f"\nfiles measured fresh in BOTH conditions: {n}")
    print(f"  ORIGINAL                       : {o}/{n} = {o/n:.3f}")
    print(f"  ANONYMISED + REORDERED         : {m}/{n} = {m/n:.3f}")
    print(f"  difference = {(m-o)/n:+.3f}  95%CI=[{lo:+.3f},{hi:+.3f}]")
    verdict = ("structural anonymisation REDUCES detection -> structural familiarity contributes"
               if hi < -0.05 else
               "no collapse detected; equivalence NOT established at this power" if lo > -0.05 else
               "INCONCLUSIVE — interval too wide")
    print(f"  -> {verdict}")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "model": model,
           "mutation": "surface (identifiers/routes/filename) + structural (top-level def reorder)",
           "n_files": n, "original_flagged": o, "mutated_flagged": m,
           "difference": round((m - o) / n, 4), "ci95": [round(lo, 4), round(hi, 4)],
           "verdict": verdict,
           "limit": "reordering changes FILE-level shape only; intra-function control flow untouched",
           "rows": rows}
    with open(os.path.join(_HERE, "structural-transfer-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
