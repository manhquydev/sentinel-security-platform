"""E19 — does detection survive when every surface cue is anonymised?

The generative-role finding (0027) rests on a public, LLM-seeded corpus, so capability and memorisation
are inseparable. This re-presents the SAME files with identifiers, route literals and the filename
replaced, and the semantics — including the absent control — untouched. Paired against verdicts already
measured in E17, so file-to-file variation drops out.

Survives => reasoning. Collapses => recall.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/run_mutation_transfer.py
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
        print("FAIL: no gateway credential — a zero from a dead model is not a measurement.")
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
            return ""      # transport failure, indistinguishable here from an empty reply

    # The canary must separate "the harness cannot reach the model" from "the model did not flag it".
    # A transient network error aborted a previous run of this experiment even though the canary fires
    # reliably (verified 3/3 directly), so an EMPTY reply is retried; a SUBSTANTIVE reply that fails to
    # flag is fatal on the first occurrence and is never retried into a pass.
    canary_ok = False
    for attempt in range(3):
        reply = ask("canary.py", _CANARY_SRC, "__canary__")
        if not reply.strip():
            print(f"  canary attempt {attempt + 1}: empty/transport failure, retrying")
            continue
        canary_ok = classify_prose(reply) == "flagged"
        break                              # a real answer decides it, pass or fail
    if not canary_ok:
        print("FAIL: positive control did not fire on a substantive reply; the harness would be what "
              "is measured, not the hypothesis.")
        return 2
    print("positive control PASSED")

    prior = {(r["repo"], r["file"]): r["verdict"]
             for r in json.load(open(PRIOR, encoding="utf-8"))["rows"] if r["arm"] == "positive"}

    pairs, rows = [], []
    for (slug, rel), orig_verdict in prior.items():
        try:
            src = open(os.path.join(rs.REPOS, slug, rel), encoding="utf-8",
                       errors="replace").read()[:MAX_BYTES]
        except OSError:
            continue
        mutated = mutate(src)
        if not mutated or not structure_preserved(src, mutated):
            continue                      # excluded, never forced
        body = "\n".join(f"{i+1}: {ln}" for i, ln in enumerate(mutated.splitlines()))
        raw = ask("module.py", body, "anonymised")   # filename identity removed too
        mut_verdict = classify_prose(raw)
        pairs.append((orig_verdict, mut_verdict))
        rows.append({"repo": slug, "file": rel, "original": orig_verdict, "mutated": mut_verdict,
                     "response": trace.redact_persisted(raw[:600])})

    n = len(pairs)
    o_flag = sum(1 for o, _ in pairs if o == "flagged")
    m_flag = sum(1 for _, m in pairs if m == "flagged")
    # McNemar discordant cells
    b = sum(1 for o, m in pairs if o == "flagged" and m != "flagged")   # lost by mutation
    c = sum(1 for o, m in pairs if o != "flagged" and m == "flagged")   # gained by mutation

    print(f"\npaired files: {n}")
    print(f"  ORIGINAL flagged: {o_flag}/{n} = {o_flag/n:.3f}")
    print(f"  MUTATED  flagged: {m_flag}/{n} = {m_flag/n:.3f}")
    print(f"  discordant: lost-by-mutation={b}  gained-by-mutation={c}")

    # Exact McNemar (binomial on the discordant pairs), one-sided: does mutation REDUCE detection?
    from math import comb
    nd = b + c
    p = sum(comb(nd, k) for k in range(b, nd + 1)) / (2 ** nd) if nd else 1.0
    print(f"  McNemar exact one-sided p = {p:.4f} -> "
          f"{'DROP is significant (memorisation contributes)' if p < 0.05 else 'no significant drop'}")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "model": model,
           "n_pairs": n, "original_flagged": o_flag, "mutated_flagged": m_flag,
           "lost_by_mutation": b, "gained_by_mutation": c, "mcnemar_p_one_sided": round(p, 4),
           "rows": rows}
    with open(os.path.join(_HERE, "mutation-transfer-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
