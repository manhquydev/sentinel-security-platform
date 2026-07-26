"""Is the missing rate limit invisible, or is it just losing to a louder defect in the same file?

E39 measured that across 53 corpus files all carrying a real CWE-307 defect, the model named the missing
rate limit in one. E40 tried to settle capability-versus-salience by asking about CWE-307 directly, and
was abandoned at the canary gate: a leading question reported the rate limit absent on code that has one,
so no instrument survived to run.

This asks the same question without ever changing the prompt. E39's files all carry an ownership or
authentication defect ALONGSIDE the missing rate limit — an IDOR in the same file is a louder finding, and
one open-ended answer has room for one headline. So run the identical open-ended prompt over the files
whose ground truth carries CWE-307 and **no other absence class at all**. Nothing competes for the answer.

    contested   (E39, n=53): CWE-307 + an ownership/authn class     -> named 1/53 = 0.019
    uncontested (here, n=16): CWE-307 and nothing else absent        -> measured by this run

If the uncontested rate is much higher, the near-zero was competition for attention and the model can see
this class — which makes it a prompt-and-orchestration problem with a real fix. If it stays near zero with
nothing to compete against, salience is not the explanation and CWE-307 is outside what this role delivers.

PREREGISTERED AS A TEST, one-sided Fisher against E39's 1/53. Power at n=16: 86% to detect an uncontested
rate of 0.30, 74% at 0.25, 57% at 0.20. The gate sits where the decision changes — a recovery below ~0.20
would not change what can be promised about this class, so being unable to resolve 0.15 costs nothing.

THE CONFOUND, MEASURED RATHER THAN ASSUMED. Files with only one absence class may simply be smaller or
simpler, and "smaller file" would explain a higher detection rate without any competition effect. Source
size is recorded for both arms so the comparison can be read against it instead of around it.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/run_class_competition.py
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
from run_class_asymmetry import OWN_AUTHN, RATE_LIMIT  # noqa: E402
from run_generative import (MAX_BYTES, _BINARY_RUBRIC, _CANARY_SRC, _load_gt_index,
                            canary_passes, classify_prose, names_class_absence)  # noqa: E402
from stats import fisher_one_sided  # noqa: E402

# CWE-200 counts as competition even though it is excluded from attribution: the question here is what
# else in the file could take the model's answer, and an information-exposure defect can, whether or not
# our vocabulary is specific enough to score it.
COMPETING = OWN_AUTHN | {200}


def uncontested_files() -> list[tuple[str, str]]:
    """Files whose ground truth carries CWE-307 and no other absence class."""
    out = []
    for (slug, relpath), entries in _load_gt_index().items():
        cwes: set[int] = set()
        for e in entries:
            if e["is_vulnerable"]:
                cwes |= set(e["cwes"])
        if RATE_LIMIT in cwes and not (cwes & COMPETING):
            out.append((slug, relpath))
    out.sort()
    return out


def _source_size(slug: str, relpath: str) -> int:
    try:
        return len(open(os.path.join(rs.REPOS, slug, relpath), encoding="utf-8",
                        errors="replace").read()[:MAX_BYTES].splitlines())
    except OSError:
        return 0


def main() -> int:
    if not os.path.isdir(rs.REPOS):
        print("FAIL: corpus not fetched")
        return 2
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

    # Read the control repeatedly, not once: the canary itself was measured firing on only 4 of 5
    # identical calls, so a single reading blocked about one legitimate run in five. A dead harness
    # still scores zero however often it is read, which is the failure this gate exists for.
    _ok, _tally = canary_passes(lambda: query("__canary__", "canary.py", literal=_CANARY_SRC))
    print(f"positive control readings: {_tally}")
    if not _ok:
        print("FAIL: positive control did not fire; the harness, not the hypothesis, would be measured.")
        return 2
    print("positive control PASSED")

    files = uncontested_files()
    print(f"{len(files)} files carrying CWE-307 and NO other absence class, model={model}\n")

    rows, named, empty = [], 0, 0
    for slug, relpath in files:
        # Protocol: score the text that is persisted, so the number re-derives from committed evidence.
        raw = query(slug, relpath)
        # A failed call returns the empty string, which the classifier reads as "said nothing" and the
        # analysis would count as a miss — a dead call scoring identically to a model that declined, with
        # the error running toward the null. That is the shape of this lab's RECALL=0.000 incident, so
        # empty responses are counted and reported rather than absorbed into the result.
        if not raw.strip():
            empty += 1
        kept = trace.redact_persisted(raw[:4000])
        said = names_class_absence(kept, RATE_LIMIT)
        named += said
        rows.append({"repo": slug, "file": relpath, "verdict": classify_prose(kept),
                     "named_rate_limit": said, "loc": _source_size(slug, relpath),
                     "response": kept})

    n = len(rows)
    # E39's contested arm, read from its committed artefact rather than retyped from the log.
    e39 = json.load(open(os.path.join(_HERE, "class-asymmetry-260726.json")))
    c_named, c_n = e39["named_rate_limit"], e39["n"]
    p = fisher_one_sided(named, n - named, c_named, c_n - c_named)

    loc_u = sorted(r["loc"] for r in rows)
    med_u = loc_u[len(loc_u) // 2] if loc_u else 0
    loc_c = sorted(_source_size(r["repo"], r["file"]) for r in e39["rows"])
    med_c = loc_c[len(loc_c) // 2] if loc_c else 0

    print(f"uncontested: named missing rate limit {named}/{n} = {named/n:.3f}")
    print(f"contested (E39):                      {c_named}/{c_n} = {c_named/c_n:.3f}")
    print(f"one-sided Fisher p = {p:.5g}")
    if empty:
        print(f"WARNING: {empty}/{n} calls returned nothing. Those are indistinguishable from a model "
              "that found nothing, and they bias this measurement toward the null.")
    print(f"\nconfound check — median source lines: uncontested={med_u}  contested={med_c}")
    if med_u < 0.5 * med_c:
        print("  NOTE: the uncontested files are markedly smaller; size is a live alternative "
              "explanation for any difference above and must be reported alongside it.")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "model": model,
           "question": "is CWE-307's near-invisibility competition for the answer, or capability?",
           "preregistered": "one-sided Fisher vs E39's contested arm; power 86% at 0.30, 74% at 0.25",
           "n": n, "named_rate_limit": named, "empty_responses": empty,
           "contested_named": c_named, "contested_n": c_n,
           "fisher_p_one_sided": round(p, 6),
           "median_loc_uncontested": med_u, "median_loc_contested": med_c,
           "rows": rows}
    with open(os.path.join(_HERE, "class-competition-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
