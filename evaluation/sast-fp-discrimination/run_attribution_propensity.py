"""Is per-file class attribution a lottery, or real signal that two runs happened to sample differently?

E42 found that two independent runs over the same 53 files reproduced the ownership-attribution RATE
exactly — 6/53 both times — while the two sets of six files overlapped in **none**. Two readings of six
cannot separate the explanations, and they lead to opposite product decisions:

  LOTTERY   every file has roughly the same ~0.11 chance of being reported, and the tool is a sampler.
            Repeated readings buy nothing but a longer list at the same rate.
  SIGNAL    some files have a high propensity and most have near zero, and each single run samples a few
            of the high ones. Repeated readings then genuinely recover detections, at k times the cost.

The discriminator is the SHAPE of the per-file propensity distribution, which needs repeated readings of
the same file — E31's design, applied to class attribution rather than to the file-level verdict.

DESIGN. Two groups, k readings each. Group EVER = files reported by either E39 or E42; group NEVER = an
equal number reported by neither, drawn with a fixed seed. Both groups are capped so the run fits a
bounded call budget — when the budget binds, group size gives way rather than k, because k is what decides
whether a propensity distribution can be told apart from a flat rate at all. Under the lottery hypothesis the two groups have
the SAME underlying propensity and any gap is regression to the mean — EVER was selected precisely
because it fired, so a lottery predicts it falls back toward 0.11 on fresh readings. Under the signal
hypothesis EVER stays high and NEVER stays near zero.

PREREGISTERED AS ESTIMATION. Group size is set by the prior runs and the call budget, not chosen for
power, so the output is two propensity distributions with a bootstrap interval on their difference and no
p-value. What the estimate must do is separate "both groups near 0.11" from "EVER far above NEVER"; an
interval does that honestly, where a significance test on a dozen files would dress it up as more.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/run_attribution_propensity.py
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
from run_class_asymmetry import OWN_AUTHN  # noqa: E402
from run_generative import (MAX_BYTES, _BINARY_RUBRIC, _CANARY_SRC, classify_prose,
                            names_class_absence)  # noqa: E402

K = int(os.environ.get("PROPENSITY_K", "5"))
# Group size is capped so the run fits a bounded call budget. k is the parameter that decides whether a
# propensity distribution can be told apart from a flat rate, so when the budget binds it is the group
# size that gives way, not the number of readings per file.
GROUP_CAP = int(os.environ.get("PROPENSITY_GROUP", "6"))
_RUNS = ("class-asymmetry-260726.json", "class-asymmetry-replication-260726.json")


def groups(seed: int = 21) -> tuple[list[dict], list[dict]]:
    """(EVER reported, NEVER reported) — from the two committed runs, not from a fresh judgement."""
    seen: dict[tuple[str, str], dict] = {}
    ever: set[tuple[str, str]] = set()
    for name in _RUNS:
        for r in json.load(open(os.path.join(_HERE, name)))["rows"]:
            key = (r["repo"], r["file"])
            seen[key] = r
            if r["named_own_authn"]:
                ever.add(key)
    ever_rows = [seen[k] for k in sorted(ever)]
    if len(ever_rows) > GROUP_CAP:
        random.Random(seed).shuffle(ever_rows)
        ever_rows = ever_rows[:GROUP_CAP]
    never = sorted(k for k in seen if k not in ever)
    rnd = random.Random(seed)
    rnd.shuffle(never)
    return ever_rows, [seen[k] for k in never[:len(ever_rows)]]


def boot_diff(a: list[float], b: list[float], seed: int = 5, draws: int = 20000):
    rnd = random.Random(seed)
    out = []
    for _ in range(draws):
        x = sum(rnd.choice(a) for _ in a) / len(a)
        y = sum(rnd.choice(b) for _ in b) / len(b)
        out.append(x - y)
    out.sort()
    return out[int(0.025 * draws)], out[int(0.975 * draws)]


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

    if classify_prose(query("__canary__", "canary.py", literal=_CANARY_SRC)) != "flagged":
        print("FAIL: positive control did not fire.")
        return 2
    print("positive control PASSED")

    ever, never = groups()
    print(f"EVER-reported n={len(ever)}   NEVER-reported n={len(never)}   k={K} readings each\n")

    rows, empty = [], 0
    for label, group in (("ever", ever), ("never", never)):
        for r in group:
            slug, relpath = r["repo"], r["file"]
            own = r["gt_own_authn"]
            hits, keeps = 0, []
            for _ in range(K):
                raw = query(slug, relpath)
                if not raw.strip():
                    empty += 1
                kept = trace.redact_persisted(raw[:4000])
                hits += any(names_class_absence(kept, c) for c in own)
                keeps.append(kept)
            rows.append({"repo": slug, "file": relpath, "group": label, "gt_own_authn": own,
                         "hits": hits, "k": K, "propensity": round(hits / K, 3),
                         "verdict": classify_prose(keeps[0]), "response": keeps[0],
                         "all_responses": keeps})
            print(f"  [{label:5}] {relpath[:44]:44} {hits}/{K}")

    pe = [r["propensity"] for r in rows if r["group"] == "ever"]
    pn = [r["propensity"] for r in rows if r["group"] == "never"]
    me, mn = sum(pe) / len(pe), sum(pn) / len(pn)
    lo, hi = boot_diff(pe, pn)
    print(f"\nEVER  mean propensity = {me:.3f}   distribution = {sorted(pe)}")
    print(f"NEVER mean propensity = {mn:.3f}   distribution = {sorted(pn)}")
    print(f"difference = {me - mn:+.3f}  95% CI [{lo:+.3f}, {hi:+.3f}]")
    # The lottery hypothesis predicts BOTH means land near the population rate of 0.113.
    print(f"\nlottery predicts both means near 0.113; signal predicts EVER high and NEVER near 0")
    if empty:
        print(f"WARNING: {empty} calls returned nothing; they bias this toward the null.")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "model": model, "k": K,
           "question": "is per-file class attribution a lottery at a fixed rate, or real per-file signal?",
           "preregistered": "estimation only; two propensity distributions and a bootstrap interval on "
                            "their difference. No p-value: 12 files per group is what the prior runs "
                            "define, not a number chosen for power",
           "ever_mean": round(me, 4), "never_mean": round(mn, 4),
           "difference": round(me - mn, 4), "difference_ci95": [round(lo, 4), round(hi, 4)],
           "population_rate_for_comparison": 0.113,
           "empty_responses": empty, "rows": rows}
    with open(os.path.join(_HERE, "attribution-propensity-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
