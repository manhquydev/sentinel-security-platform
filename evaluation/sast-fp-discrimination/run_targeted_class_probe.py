"""Can't the model see a missing rate limit, or does it just not mention it?

E39 measured the practically important number: across 53 corpus files that all carry a real CWE-307
defect — no limit on repeated authentication attempts — the model named the missing rate limit in **one**.
CWE-307 is the most common absence class in this corpus, so that near-zero is the finding with the
clearest commercial consequence.

But "named it when asked to report absence-class vulnerabilities generally" and "can recognise it when
asked directly" are different claims, and only the second is about capability. The first is about
salience: with one open-ended question the model spends its answer on whatever it considers most
important, and a missing lockout may simply lose to an IDOR sitting in the same file. If a targeted
question recovers the misses, the product answer is per-class prompting and this is a prompt-design
problem. If it does not, CWE-307 is outside what this role delivers and no prompt fixes it.

PREREGISTERED AS A TEST. Paired within file (same 53 files, exact McNemar, one-sided) against E39's
measured 1/53 = 0.019 under the general prompt. Power at these 53 files: 90% to detect recovery to 20%,
70% to 15%, and only 36% to 10%. That gate is set where the DECISION changes, not where a p-value
becomes obtainable: recovering under ~10% would not justify running one call per class per file, so a
design that cannot resolve a 7% recovery is not failing at anything worth resolving. If observed recovery
lands below that, the result is reported as an upper bound with an interval, not as a null test.

THE LEADING-QUESTION PROBLEM, AND THE CONTROL FOR IT. Asking "is the rate limit missing?" invites yes.
A model that answers yes indiscriminately would look like total recovery while detecting nothing, and the
comparison against E39's open-ended prompt cannot catch that, because the two prompts differ in exactly
the way that produces the artefact. So the probe carries BOTH canaries and refuses to run unless both
behave: a login handler with no attempt limiting (must say absent) and the same handler WITH a limiter
(must say present). One canary here would be worse than none — it would license the failure it cannot see.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/run_targeted_class_probe.py
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from math import comb

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import run_spike as rs  # noqa: E402
from agent import trace  # noqa: E402
from run_class_asymmetry import RATE_LIMIT, paired_files  # noqa: E402
from run_generative import MAX_BYTES, names_class_absence  # noqa: E402

# Prose, not a structured verdict. The first version of this probe demanded one word — ABSENT / PRESENT
# / NA — and the model ignored the instruction on BOTH canaries, answering with a rewritten copy of the
# file instead. That is E16a replicating on a fourth output format: this model does not conform to
# machine-readable output contracts, and a probe built on one measures the contract, not the code. So the
# question stays targeted while the answer stays prose, and the reading is done by the same deterministic
# classifier every other experiment here uses.
_RUBRIC = (
    "You are auditing one Python web source file for ONE specific weakness: an absent limit on repeated "
    "authentication attempts (CWE-307) — no rate limiting, no lockout, no throttling and no backoff on a "
    "login, token, password-reset or other credential-checking path.\n"
    "Say briefly whether such a path exists in this file and whether anything limits repeated attempts "
    "against it. Do not discuss any other weakness. Do not rewrite the file."
)

# A login handler with no attempt limiting whatsoever. The probe must call this ABSENT.
_CANARY_ABSENT = """1: @app.route('/login', methods=['POST'])
2: def login():
3:     data = request.get_json() or {}
4:     user = User.query.filter_by(email=data.get('email')).first()
5:     if user and user.check_password(data.get('password')):
6:         return jsonify({'token': make_token(user)})
7:     return jsonify({'error': 'invalid credentials'}), 401
"""

# The SAME handler with a limiter applied. The probe must call this PRESENT. Without this second canary
# a model that simply always answers ABSENT would score as complete recovery while measuring nothing.
_CANARY_PRESENT = """1: @app.route('/login', methods=['POST'])
2: @limiter.limit('5 per minute')
3: def login():
4:     data = request.get_json() or {}
5:     user = User.query.filter_by(email=data.get('email')).first()
6:     if user and user.check_password(data.get('password')):
7:         return jsonify({'token': make_token(user)})
8:     return jsonify({'error': 'invalid credentials'}), 401
"""


def read_verdict(text: str) -> str:
    """absent | not-absent — read from the model's prose by the shared class-absence rule.

    Deliberately only two outcomes. A structured three-way verdict was tried first and the model would
    not produce one, so distinguishing "there is no login path here" from "there is one and it is
    limited" is not available from prose without inventing a second classifier to do it. Both mean the
    same thing for this measurement — the missing rate limit was not reported — and collapsing them keeps
    the reading on an instrument whose specificity has been measured (CWE-307: fires on 9.5% of prose
    claiming a defect, 0% of prose concluding all-clear).
    """
    if not (text or "").strip():
        return "not-absent"
    return "absent" if names_class_absence(text, RATE_LIMIT) else "not-absent"


def mcnemar_one_sided(b: int, c: int) -> float:
    n = b + c
    return 1.0 if n == 0 else sum(comb(n, k) for k in range(b, n + 1)) / 2 ** n


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
            return llm.chat([llm.Msg("system", _RUBRIC, llm.operator()),
                             llm.Msg("user", f"file: {relpath}\n\n{body}",
                                     llm.target_derived(source="corpus-file", target=slug))],
                            model=model, max_tokens=160, temperature=0.0)
        except Exception:
            return ""

    pos = read_verdict(query("__canary__", "login_unlimited.py", literal=_CANARY_ABSENT))
    neg = read_verdict(query("__canary__", "login_limited.py", literal=_CANARY_PRESENT))
    print(f"canaries: missing-limit -> {pos}   limit-present -> {neg}")
    if pos != "absent" or neg != "not-absent":
        print("FAIL: the probe cannot tell the two canaries apart. A leading question that answers the "
              "same way regardless of the code measures the question, not the file.")
        return 2
    print("both canaries PASSED — the probe discriminates\n")

    files = paired_files()
    rows, counts = [], {}
    for slug, relpath, _cwes in files:
        # Score the persisted text, as E39 established: a verdict derived from prose that cannot be
        # committed is a verdict nobody can re-check.
        kept = trace.redact_persisted(query(slug, relpath)[:4000])
        v = read_verdict(kept)
        counts[v] = counts.get(v, 0) + 1
        rows.append({"repo": slug, "file": relpath, "verdict": v, "response": kept})

    n = len(rows)
    absent = counts.get("absent", 0)
    # Every one of these files carries a real CWE-307 defect, so `absent` is a true-positive count and
    # `present` is a miss stated with confidence — the worst kind for a security tool.
    print(f"targeted probe over {n} files (all carrying a REAL missing rate limit): {counts}")
    print(f"recovered = {absent}/{n} = {absent/n:.3f}   (general prompt, E39: 1/{n} = 0.019)")

    # Paired against E39's per-file result on the identical file set.
    e39 = {(r["repo"], r["file"]): r["named_rate_limit"]
           for r in json.load(open(os.path.join(_HERE, "class-asymmetry-260726.json")))["rows"]}
    b = sum(1 for r in rows if r["verdict"] == "absent" and not e39.get((r["repo"], r["file"])))
    c = sum(1 for r in rows if r["verdict"] != "absent" and e39.get((r["repo"], r["file"])))
    p = mcnemar_one_sided(b, c)
    print(f"discordant: targeted-only={b}  general-only={c}   exact McNemar one-sided p = {p:.5g}")
    if absent / n < 0.10:
        print("NOTE: recovery is below the 10% the power gate was set at; read this as an upper bound "
              "on what per-class prompting buys, not as a powered null.")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "model": model,
           "question": "does a CWE-307-targeted prompt recover misses the general prompt makes?",
           "preregistered": "paired exact McNemar vs E39 on the identical 53 files; powered 90% for "
                            "recovery to 0.20, 70% to 0.15; below 0.10 report as an upper bound",
           "n": n, "counts": counts, "recovered_absent": absent,
           "general_prompt_absent": sum(1 for v in e39.values() if v),
           "discordant_targeted_only": b, "discordant_general_only": c,
           "mcnemar_p_one_sided": round(p, 6),
           "canaries": {"missing_limit": pos, "limit_present": neg},
           "rows": rows}
    with open(os.path.join(_HERE, "targeted-class-probe-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
