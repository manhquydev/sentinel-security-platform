"""E20 — is it the file ROLE (an endpoint) or the missing CONTROL?

E18 established the effect is class-specific, and named the confound it could not remove: absence-class
vulnerabilities cluster in request handlers, so arm A and arm B differed in file ROLE as well as class.
This arm holds role FIXED — every file here is an endpoint handler — and varies only whether an absent
control is present.

    arm A' : handler files WITH an absence-class vuln    (E17, frozen instrument) -> 7/28 = 0.250
    arm C  : handler files WITHOUT one (all 42 in corpus) -> measured here

If arm C matches arm A', the model is reacting to endpoint-ness and 0027's mechanism claim collapses to
"recognises request-handling code". If arm C stays low, the model is responding to the missing control.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/run_role_control.py
"""

from __future__ import annotations

import json
import os
import re
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

# The file ROLE where absent controls live. Held fixed across both arms.
ROLE = re.compile(r"(views?\.py$|routes?/|_routes\.py$|/api/|endpoints?\.py$|handlers?\.py$|"
                  r"resources?\.py$|controllers?/|urls\.py$)", re.I)


def arm_c() -> list[tuple]:
    """Every endpoint-handler file in the corpus with NO absence-class vulnerability."""
    idx = _load_gt_index()
    absence = {k for k, v in idx.items()
               if any(e["is_vulnerable"] and e["primary"] in BLIND for e in v)}
    return sorted(k for k in idx if ROLE.search(k[1]) and k not in absence)


def arm_a_prime(limit: int = 40) -> list[tuple]:
    """Endpoint-handler files WITH an absence-class vulnerability, measured FRESH.

    E20 reused E17's verdicts for this arm. Under a 36%-unstable instrument (E22) that makes the two
    arms incomparable, which is why E20 was withdrawn. Both arms are now measured in the same run.
    """
    idx = _load_gt_index()
    out = sorted(k for k, v in idx.items()
                 if ROLE.search(k[1]) and any(e["is_vulnerable"] and e["primary"] in BLIND for e in v))
    return out[:limit]


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

    # Retry only a transport failure; a substantive non-flag is fatal at once (E19's scar).
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

    files = arm_c()
    print(f"arm C: {len(files)} endpoint-handler files with NO absence-class vuln (whole population)\n")
    counts, rows = {}, []
    for slug, rel in files:
        try:
            src = open(os.path.join(rs.REPOS, slug, rel), encoding="utf-8",
                       errors="replace").read()[:MAX_BYTES]
        except OSError:
            continue
        body = "\n".join(f"{i+1}: {ln}" for i, ln in enumerate(src.splitlines()))
        raw = ask(rel, body, slug)
        v = classify_prose(raw)
        counts[v] = counts.get(v, 0) + 1
        rows.append({"repo": slug, "file": rel, "verdict": v,
                     "response": trace.redact_persisted(raw[:4000])})

    n = len(rows)
    flagged = counts.get("flagged", 0)
    from math import comb

    def fisher(a, b, c, d):
        tot = a + b + c + d
        r1, c1 = a + b, a + c
        return sum(comb(c1, k) * comb(tot - c1, r1 - k) for k in range(a, min(r1, c1) + 1)) / comb(tot, r1)

    aA, nA = 7, 28                       # arm A' from E17, same instrument
    p = fisher(aA, nA - aA, flagged, n - flagged)
    print(f"arm C verdicts: {counts}")
    print(f"  arm A' (handlers WITH an absent control, E17): {aA}/{nA} = {aA/nA:.3f}")
    print(f"  arm C  (handlers WITHOUT one)                : {flagged}/{n} = {flagged/n:.3f}")
    print(f"  one-sided Fisher p = {p:.4f} -> "
          f"{'MISSING CONTROL drives it, not file role' if p < 0.05 else 'no significant difference'}")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "model": model,
           "arm": "handler-no-absence", "n": n, "counts": counts,
           "flag_rate": round(flagged / n, 4) if n else None,
           "arm_a_prime": {"flagged": aA, "n": nA, "rate": round(aA / nA, 4)},
           "fisher_p_one_sided": round(p, 4), "rows": rows}
    with open(os.path.join(_HERE, "role-control-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
