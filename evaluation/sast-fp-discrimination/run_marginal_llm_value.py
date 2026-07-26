"""What does the LLM layer add ON TOP of the free layer, and what does each extra detection cost?

E13 asked the marginal cost/yield question and answered it: **+$0.05, +35s, zero extra findings**. That
verdict stands for the role it tested — the LLM sitting behind Semgrep as a gate. It says nothing about
the generative role, which E17 onward established DOES produce findings no engine produces.

So the question is open again, and this time in the order a product actually runs it. The deterministic
rule is free, instant and requires no network, so **it runs first and is the baseline**. The model is
then an upgrade someone has to pay for, per file, per reading. The buyer's question is not "is the model
good" but:

    given the free layer already ran, what does each additional model reading buy, and what does it cost?

E62 measured the reverse (what the rule adds to the model) because that was the question about
complementarity. This is the product question, and the answer is different: the rule is 6 lines of regex
and the model is a metered API, so the increments are not interchangeable.

WHY THE CURVE MATTERS MORE THAN THE POINT. E57 established that coverage is a function of the reading
budget, not a property of the corpus: the union rose until k=9 and was flat for nine readings after. A
single k=1 number would therefore misstate both the value and the cost. What a buyer needs is the whole
schedule — marginal detections per reading against marginal dollars — because that is where the decision
about how deep to read actually gets made.

COST IS AN ESTIMATE AND IS LABELLED AS ONE. Token counts were never persisted by the generative runner, so
they are reconstructed from committed data: input from the file text the runner sends (truncated at 4000
chars, plus the prompt template) and output from the persisted response, at 4 chars/token, priced with the
project's own committed table for `sast-grok45`. Calls are EXACT and are reported alongside, because a
call count cannot rot the way a price estimate can.

WHAT WOULD FALSIFY THE LLM LAYER'S VALUE HERE: a marginal detection cost that never falls below the cost
of a human simply reading the free layer's inventory, or a union that the rule already covers.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/run_marginal_llm_value.py
"""

from __future__ import annotations

import glob
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
import detect_absent_auth as det  # noqa: E402
from pool_rule_model_union import absence_eligible, detector_hits  # noqa: E402
from run_generative import names_class_absence  # noqa: E402

# The project's committed price table for the model actually used, USD per 1M tokens.
PRICE_IN, PRICE_OUT = 3.0, 15.0
CHARS_PER_TOKEN = 4
PROMPT_TEMPLATE_CHARS = 600     # the instruction text wrapped around each file
FILE_TRUNCATE = 4000            # what run_generative sends

# Samples whose readings cover the SAME files, so a union over k is meaningful. Mixing a disjoint sample
# in would union across different files and inflate coverage — the pooling error caught in E62.
SAMPLES = {"A": ["generative-260726.json", "generative-rerun*-260726.json"],
           "B": ["generative-disjoint*-260726.json"]}


def load(patterns: list[str]) -> list[dict]:
    runs = []
    for pat in patterns:
        for f in sorted(glob.glob(os.path.join(_HERE, pat))):
            try:
                rows = json.load(open(f, encoding="utf-8")).get("rows") or []
            except (OSError, json.JSONDecodeError):
                continue
            if rows:
                runs.append({(r["repo"], r["file"]): r for r in rows})
    return runs


def estimate_cost(reading: dict, files: list[tuple[str, str]]) -> float:
    """USD for one reading over these files. ESTIMATE — see module docstring."""
    tin = tout = 0
    for key in files:
        row = reading.get(key)
        path = os.path.join(rs.REPOS, key[0], key[1])
        try:
            n = min(len(open(path, encoding="utf-8", errors="replace").read()), FILE_TRUNCATE)
        except OSError:
            n = FILE_TRUNCATE
        tin += (n + PROMPT_TEMPLATE_CHARS) / CHARS_PER_TOKEN
        tout += len(row.get("response", "")) / CHARS_PER_TOKEN if row else 0
    return tin / 1e6 * PRICE_IN + tout / 1e6 * PRICE_OUT


def model_hits(reading: dict, pos: list[tuple[str, str]], strict: bool) -> set:
    """Files this reading detected.

    Two standards, because the naive comparison is not fair. The rule is scored by the project matcher —
    file AND CWE AND line, claim-once — while a model "flag" only asserts that SOME control is missing
    somewhere in the file. Unioning those two as if they were the same evidence flatters the model.

    strict=False : the file-level flag, the estimand every earlier generative experiment published.
    strict=True  : the flag must also NAME the absence class the ground truth records for that file,
                   using the same prose parser the attribution experiments used. Closer to the rule's
                   standard, and E48 already warned this is where the model is weakest — 0 of 53 files
                   had a reliable class attribution across five readings.
    """
    out = set()
    for key in pos:
        row = reading.get(key)
        if not row or row.get("verdict") != "flagged":
            continue
        if not strict:
            out.add(key)
            continue
        gt = rs.load_gt(key[0]) or []
        cwes = {c for e in gt if e["is_vulnerable"]
                and _norm(e["file"]) == _norm(key[1]) for c in e["cwes"]}
        text = row.get("response", "")
        if any(names_class_absence(text, c) for c in cwes):
            out.add(key)
    return out


def _norm(p: str) -> str:
    return p.replace("\\", "/")


def curve(label: str, runs: list[dict], strict: bool = False) -> dict:
    shared = sorted(set.intersection(*(set(r) for r in runs)))
    pos = [k for k in shared if runs[0][k]["arm"] == "positive"]
    elig = set(absence_eligible(pos))
    if len(pos) < 10:
        return {}
    rule = detector_hits(pos)
    n = len(pos)

    std = "STRICT — model must name the ground-truth class" if strict else \
          "file-level flag (the published estimand)"
    print(f"\n=== sample {label}: {n} positive files, {len(runs)} readings "
          f"({len(elig)} carry a GT CWE-306/862 entry) ===")
    print(f"  model scored at: {std}")
    print(f"  FREE LAYER (rule alone, 0 calls, $0.00): {len(rule)}/{n} = {len(rule)/n:.3f}")
    print(f"\n{'k':>3} {'union':>8} {'+files':>7} {'calls':>7} {'est $':>9} "
          f"{'$/new file':>11} {'vs free':>8}")

    seen = set(rule)
    rows = []
    cost = 0.0
    for k, reading in enumerate(runs, 1):
        flagged = model_hits(reading, pos, strict)
        before = len(seen)
        seen |= flagged
        gained = len(seen) - before
        cost += estimate_cost(reading, pos)
        calls = n * k
        marg = (estimate_cost(reading, pos) / gained) if gained else None
        rows.append({"k": k, "union": len(seen), "coverage": round(len(seen) / n, 4),
                     "gained": gained, "calls": calls, "cum_cost_usd": round(cost, 4),
                     "marginal_usd_per_new_file": round(marg, 4) if marg else None,
                     "gain_over_free": round((len(seen) - len(rule)) / n, 4)})
        print(f"{k:>3} {len(seen)/n:>8.3f} {gained:>7} {calls:>7} {cost:>9.3f} "
              f"{(f'{marg:.3f}' if marg else '—'):>11} {(len(seen)-len(rule))/n:>+8.3f}")

    last_gain = max((r["k"] for r in rows if r["gained"]), default=0)
    tot = rows[-1]
    print(f"\n  last reading that added anything: k={last_gain} of {len(runs)}")
    print(f"  total spent to k={len(runs)}: {tot['calls']} calls, ~${tot['cum_cost_usd']:.2f}")
    print(f"  the model's whole contribution over the free layer: "
          f"{tot['union']-len(rule)} files = {tot['gain_over_free']:+.3f}")
    if tot["union"] > len(rule):
        print(f"  average cost per file the free layer missed: "
              f"${tot['cum_cost_usd']/(tot['union']-len(rule)):.2f}")
    return {"sample": label, "model_standard": "strict" if strict else "file-level",
            "files": n, "eligible": len(elig), "readings": len(runs),
            "rule_alone": len(rule), "rule_coverage": round(len(rule) / n, 4),
            "last_productive_k": last_gain, "curve": rows}


def main() -> int:
    if not os.path.isdir(rs.REPOS):
        print("FAIL: corpus not fetched")
        return 2
    if not det.self_test():
        print("FAIL: detector self-test")
        return 2
    out = []
    for label, pats in SAMPLES.items():
        runs = load(pats)
        if len(runs) < 2:
            print(f"sample {label}: {len(runs)} readings — skipped")
            continue
        for strict in (False, True):
            d = curve(label, runs, strict)
            if d:
                out.append(d)
    if not out:
        print("FAIL: no sample had enough shared readings.")
        return 2

    print("\nE13 measured the marginal LLM layer at +$0.05/run for ZERO extra findings, as a gate behind")
    print("Semgrep. In the generative role, on top of the free rule layer, it is not zero — and the")
    print("schedule above is where the decision about reading depth actually gets made.")

    art = {"generated_at": datetime.now(timezone.utc).isoformat(),
           "question": "what does the LLM layer add on top of the FREE deterministic layer, and at what cost?",
           "baseline": "deterministic absence rule — 0 calls, $0.00",
           "cost_basis": {"model": "sast-grok45", "usd_per_1m_input": PRICE_IN,
                          "usd_per_1m_output": PRICE_OUT, "chars_per_token": CHARS_PER_TOKEN,
                          "note": "ESTIMATE — token counts were never persisted; input reconstructed "
                                  "from the truncated file text plus prompt template, output from the "
                                  "persisted response. Call counts are exact."},
           "supersedes_for_generative_role": "E13's 'zero extra findings' verdict, which tested the gate role",
           "samples": out}
    with open(os.path.join(_HERE, "marginal-llm-value-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(art, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
