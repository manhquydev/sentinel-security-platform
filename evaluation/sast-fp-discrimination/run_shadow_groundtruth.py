"""Does the model find real absent controls that the corpus never labelled?

This is the question E53 forced open. One of the two clean-arm "false positives" turned out to be the
model correctly reporting an unbounded client-controlled `limit` — a genuine CWE-770 — on a file whose
ground truth records nothing. A deterministic scan then found the corpus labels CWE-770 **zero times**
across every endpoint that has it. So at least one absent-control class exists in this corpus, is real,
is mechanically confirmable, and is invisible to the yardstick every precision figure has been measured
against.

If the model tracks such defects generally, then **measured precision is a floor rather than an
estimate**, and the bottleneck on this whole line of work is the labels rather than the model. If it does
not, the corpus-gap story cannot rescue precision and the measured numbers stand as they are.

THE SHADOW GROUND TRUTH. Five absent-control conditions that can be confirmed by reading the source with
no model and no judgement: an unbounded `limit` parameter (CWE-770), `DEBUG=True` (489), a CORS wildcard
origin (942), a session cookie with Secure/HttpOnly disabled (1004), and a wildcard `ALLOWED_HOSTS` (16).
Each detector carries a positive and a negative form in its self-test, so it cannot pass by firing on
everything: `limit: int = 200` fires while `limit: int = Query(50, le=100)` does not.

DESIGN, PREREGISTERED AS A TEST.

    arm S  9 files where a detector confirms an absent control AND ground truth records nothing at all
    arm C 30 files with no detector hit and no ground truth — ordinary clean controls

Arm S is restricted to files with **no** ground-truth entry on purpose: a flag there cannot be explained
by the model having found some other, labelled defect. One-sided Fisher on the k=3 union. Power against
the measured clean-arm rate (2/328 single-reading, treated conservatively as 0.05): **84% at S=0.50, 94%
at 0.60, 68% at 0.40**. Below ~0.40 the design cannot resolve the effect, and a low result is therefore
reported as an upper bound rather than as a null — but an effect that small would not support the "labels
are the bottleneck" claim anyway, which is where the gate was deliberately set.

WHAT WOULD FALSIFY IT. Arm S flagging at the clean-arm rate. That is a real possible outcome — the clean
arm has produced 2 flags in 328 observations, so a null here is entirely available to the data, and the
null calibration check returns 2.1%.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/run_shadow_groundtruth.py
"""

from __future__ import annotations

import json
import os
import random
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
from run_generative import (MAX_BYTES, _BINARY_RUBRIC, _CANARY_SRC, canary_passes,
                            classify_prose)  # noqa: E402
from stats import fisher_one_sided  # noqa: E402

K = int(os.environ.get("SHADOW_K", "3"))
N_CONTROL = int(os.environ.get("SHADOW_CONTROLS", "30"))

# (label, pattern meaning the control is ABSENT, pattern meaning it is PRESENT nearby)
DETECTORS = {
    770: ("unbounded client-controlled limit",
          re.compile(r"\blimit\s*:\s*int\s*=\s*[^,\)\n]*"),
          re.compile(r"\ble\s*=|\blt\s*=|min\s*\(\s*limit|conint|Le\(|max_value")),
    489: ("DEBUG left on", re.compile(r"^\s*DEBUG\s*=\s*True", re.M), None),
    942: ("CORS wildcard origin",
          re.compile(r'allow_origins\s*=\s*\[\s*["\']\*["\']|CORS_ORIGIN_ALLOW_ALL\s*=\s*True'), None),
    1004: ("session cookie flags disabled",
           re.compile(r"SESSION_COOKIE_HTTPONLY\s*=\s*False|SESSION_COOKIE_SECURE\s*=\s*False|"
                      r"set_cookie\([^)]*httponly\s*=\s*False"), None),
    16: ("wildcard ALLOWED_HOSTS", re.compile(r'ALLOWED_HOSTS\s*=\s*\[\s*["\']\*["\']\s*\]'), None),
}

# Each detector must fire on the defective form and stay silent on the repaired one. A detector that
# fires on both would populate arm S with files that have nothing wrong, which is the only way this
# experiment could manufacture its own positive result.
SELF_TEST = [(770, "limit: int = 200,", True), (770, "limit: int = Query(50, le=100),", False),
             (489, "DEBUG = True", True), (489, "DEBUG = False", False),
             (942, 'allow_origins=["*"]', True), (942, 'allow_origins=["https://a.com"]', False),
             (1004, "SESSION_COOKIE_SECURE = False", True), (1004, "SESSION_COOKIE_SECURE = True", False),
             (16, "ALLOWED_HOSTS = ['*']", True), (16, "ALLOWED_HOSTS = ['a.com']", False)]


def _fires(cwe: int, text: str) -> bool:
    _, pat, bound = DETECTORS[cwe]
    for m in pat.finditer(text):
        if bound is None or not bound.search(text[m.start():m.start() + 220]):
            return True
    return False


def self_test() -> bool:
    ok = True
    for cwe, txt, want in SELF_TEST:
        got = _fires(cwe, txt)
        if got != want:
            print(f"  DETECTOR SELF-TEST FAILED: CWE-{cwe} on {txt!r} -> {got}, wanted {want}")
            ok = False
    return ok


def arms(seed: int = 31):
    """(arm S, arm C) — confirmed-but-unlabelled defects, and clean controls."""
    labelled = set()
    for slug in sorted(os.listdir(rs.REPOS)):
        for g in (rs.load_gt(slug) or []):
            if g.get("is_vulnerable"):
                labelled.add((slug, g["file"]))
    shadow, clean = [], []
    for slug in sorted(os.listdir(rs.REPOS)):
        root = os.path.join(rs.REPOS, slug)
        if not os.path.isdir(root):
            continue
        for dp, _, fns in os.walk(root):
            for fn in fns:
                if not fn.endswith(".py"):
                    continue
                path = os.path.join(dp, fn)
                rel = os.path.relpath(path, root)
                if (slug, rel) in labelled:
                    continue                       # only files ground truth says nothing about
                try:
                    src = open(path, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                hits = [c for c in DETECTORS if _fires(c, src)]
                (shadow if hits else clean).append((slug, rel, hits))
    rnd = random.Random(seed)
    rnd.shuffle(clean)
    return sorted(shadow), clean[:N_CONTROL]


def main() -> int:
    if not os.path.isdir(rs.REPOS):
        print("FAIL: corpus not fetched")
        return 2
    if not self_test():
        print("FAIL: a detector does not discriminate the defect from its repair.")
        return 2
    print("detector self-test PASSED (10 cases, defective and repaired forms)")
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

    ok, tally = canary_passes(lambda: query("__canary__", "canary.py", literal=_CANARY_SRC))
    print(f"positive control readings: {tally}")
    if not ok:
        print("FAIL: positive control never fired.")
        return 2

    shadow, clean = arms()
    print(f"arm S (confirmed defect, unlabelled): {len(shadow)}   arm C (clean control): {len(clean)}")
    print(f"k={K} readings each, model={model}\n")

    rows, empty = [], 0
    # Interleaved so a truncated run still leaves a comparison rather than one finished arm.
    ordered = []
    for i in range(max(len(shadow), len(clean))):
        if i < len(shadow):
            ordered.append(("shadow", shadow[i]))
        if i < len(clean):
            ordered.append(("clean", clean[i]))
    for arm, (slug, rel, hits) in ordered:
        flagged = 0
        keeps = []
        for _ in range(K):
            raw = query(slug, rel)
            if not raw.strip():
                empty += 1
            kept = trace.redact_persisted(raw[:4000])   # score what is persisted (protocol section 14)
            flagged += classify_prose(kept) == "flagged"
            keeps.append(kept)
        rows.append({"arm": arm, "repo": slug, "file": rel, "detectors": hits,
                     "flagged_in": flagged, "k": K, "union_flagged": flagged > 0,
                     "verdict": classify_prose(keeps[0]), "response": keeps[0],
                     "all_responses": keeps})
        print(f"  [{arm:6}] {rel[:46]:46} {flagged}/{K}  {hits if hits else ''}")

    s = [r for r in rows if r["arm"] == "shadow"]
    c = [r for r in rows if r["arm"] == "clean"]
    sf = sum(r["union_flagged"] for r in s)
    cf = sum(r["union_flagged"] for r in c)
    p = fisher_one_sided(sf, len(s) - sf, cf, len(c) - cf)
    print(f"\narm S union-flagged: {sf}/{len(s)} = {sf/len(s):.3f}")
    print(f"arm C union-flagged: {cf}/{len(c)} = {cf/len(c):.3f}")
    print(f"one-sided Fisher p = {p:.5g}   {'REJECTS' if p < 0.05 else 'does NOT reject'} the null at 0.05")
    if sf / len(s) < 0.40:
        print("NOTE: arm S is below the 0.40 the power gate was set at — read this as an upper bound on "
              "how well the model tracks unlabelled defects, not as a powered null.")
    if empty:
        print(f"WARNING: {empty} empty responses; they bias both arms toward the null.")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "model": model, "k": K,
           "question": "does the model flag real absent controls the corpus never labelled?",
           "preregistered": "one-sided Fisher on the k=3 union; power 84% at S=0.50, 94% at 0.60; "
                            "below 0.40 report as an upper bound",
           "n_shadow": len(s), "n_clean": len(c),
           "shadow_union_flagged": sf, "clean_union_flagged": cf,
           "fisher_p_one_sided": round(p, 6), "empty_responses": empty, "rows": rows}
    with open(os.path.join(_HERE, "shadow-groundtruth-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
