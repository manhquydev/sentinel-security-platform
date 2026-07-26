"""E23 — memorisation, re-done after E22 showed the instrument flips 36% of verdicts.

E19 asked the right question with a design that could not survive a noisy instrument: it paired freshly
measured mutated verdicts against REUSED original ones. At a 36% flip rate, its perfect null is what the
noise alone produces.

This measures BOTH arms fresh, in the same run, on the same files, and compares AGGREGATE rates — the
same noise applies to both, so it does not bias the difference. Per-file verdicts are never compared,
because at this flip rate an individual verdict carries no information.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/run_memorisation_v2.py
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
from mutate_source import mutate, structure_preserved  # noqa: E402
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
        mut = mutate(src)
        if not mut or not structure_preserved(src, mut):
            continue                       # identical inclusion rule to E19

        orig_body = "\n".join(f"{i+1}: {ln}" for i, ln in enumerate(src.splitlines()))
        mut_body = "\n".join(f"{i+1}: {ln}" for i, ln in enumerate(mut.splitlines()))

        # BOTH measured fresh, same run. Nothing reused.
        raw_o = ask(rel, orig_body, slug)
        raw_m = ask("module.py", mut_body, "anonymised")
        rows.append({"repo": slug, "file": rel,
                     "original": classify_prose(raw_o), "mutated": classify_prose(raw_m),
                     "resp_original": trace.redact_persisted(raw_o[:400]),
                     "resp_mutated": trace.redact_persisted(raw_m[:400])})

    n = len(rows)
    o = sum(1 for r in rows if r["original"] == "flagged")
    m = sum(1 for r in rows if r["mutated"] == "flagged")

    # Bootstrap the AGGREGATE difference over files. Per-file verdicts are noise; rates are not.
    rnd = random.Random(21)
    diffs = []
    for _ in range(20000):
        s = [rnd.choice(rows) for _ in rows]
        a = sum(1 for r in s if r["original"] == "flagged") / n
        b = sum(1 for r in s if r["mutated"] == "flagged") / n
        diffs.append(b - a)
    diffs.sort()
    lo, hi = diffs[int(.025 * len(diffs))], diffs[int(.975 * len(diffs))]

    print(f"\nfiles measured fresh in BOTH conditions: {n}")
    print(f"  ORIGINAL source  : {o}/{n} = {o/n:.3f}")
    print(f"  ANONYMISED source: {m}/{n} = {m/n:.3f}")
    print(f"  aggregate difference (anonymised - original) = {(m-o)/n:+.3f}  95%CI=[{lo:+.3f},{hi:+.3f}]")
    if hi < -0.05:
        verdict = "anonymisation REDUCES detection -> memorisation contributes"
    elif lo > -0.05:
        verdict = ("no collapse detected; a >5pt reduction is excluded, but equivalence is NOT "
                   "established at this power")
    else:
        verdict = "INCONCLUSIVE — interval too wide to distinguish"
    print(f"  -> {verdict}")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "model": model,
           "n_files": n, "original_flagged": o, "mutated_flagged": m,
           "aggregate_difference": round((m - o) / n, 4), "ci95": [round(lo, 4), round(hi, 4)],
           "verdict": verdict,
           "design_note": "both arms measured fresh in the same run; per-file verdicts never compared "
                          "because E22 measured 36% verdict instability",
           "rows": rows}
    with open(os.path.join(_HERE, "memorisation-v2-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
