"""What inventory would the LLM produce on a real repository, next to the free layer's 27 decisions?

E76/E78 measured the deterministic layer's output on production web applications: a median of **27
file-level decisions** per app. Nothing has ever measured the other side. Every LLM number in this project
comes from a benchmark of small teaching files where 38% carry a defect; on the one occasion the model met
real code (E79) it flagged the **repaired** version of a file at 0.200, against a corpus clean-arm rate of
about 1% — a twentyfold difference that nobody has followed up, on n=10.

That single number decides the product fork from the cost side. If the model flags a fifth of a production
repository's route files, then on a 500-file app it proposes ~100 items against the free layer's ~27, and
the "LLM adds coverage" argument has to be paid for in triage the inventory framing cannot absorb.

WHAT THIS MEASURES. Both tools pointed at the same real repositories, each run the way it actually would be:

  - the deterministic layer reads whole files (it is free and offline, so nothing stops it);
  - the model gets what fits its budget — `_BINARY_RUBRIC` at 160 tokens over the first 4000 characters,
    which is the corpus instrument applied verbatim. Truncation is not a flaw of this experiment; it is what
    happens when you point that instrument at a 2000-line production file, and pretending otherwise would
    measure a tool nobody has.

There is no ground truth here and none is needed: this is a **volume and overlap** measurement, not an
accuracy one. Flag rate, non-answer rate, and how much of each tool's output the other also names.

WHAT WOULD MAKE THE MODEL LOOK GOOD, and is available: a low flag rate that concentrates on files the
detector also flags — i.e. a second opinion on a small set rather than a second, larger pile.

    LITELLM_MASTER_KEY=... rag/.venv/bin/python -W ignore \\
        evaluation/sast-fp-discrimination/run_production_inventory.py
"""

from __future__ import annotations

import collections
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

import detect_absent_auth as det  # noqa: E402
from run_generative import classify_prose, canary_passes, _BINARY_RUBRIC  # noqa: E402
from pool_propensity import wilson  # noqa: E402
from agent import trace as _trace  # noqa: E402

MODEL = os.environ.get("PROD_MODEL", "sast-grok45")
CLONES = os.path.join(os.environ.get("TMPDIR", "/tmp"), "volume-census-clones")
SEED = 20260727
PER_REPO = int(os.environ.get("PROD_PER_REPO", "12"))
MAX_CHARS = 4000
MAX_TOK = 160
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "tests", "test"}


def ask(src: str, label: str) -> tuple[str, str]:
    """One reading, through the corpus instrument exactly: binary rubric, 160 tokens, redacted scoring."""
    from agent import llm
    body = "\n".join(f"{i+1}: {ln}" for i, ln in enumerate(src[:MAX_CHARS].splitlines()))
    try:
        out = llm.chat(
            [llm.Msg("system", _BINARY_RUBRIC, llm.operator()),
             llm.Msg("user", f"file: {label}\n\n{body}",
                     llm.target_derived(source="production-clone", target=label))],
            model=MODEL, max_tokens=MAX_TOK, temperature=0.0)
    except Exception as exc:
        return "error", f"error: {str(exc)[:100]}"
    kept = _trace.redact_persisted(out[:4000])
    return classify_prose(kept), kept


def route_files(root: str) -> list[str]:
    """Python files carrying at least one route declaration — where absence classes can exist at all."""
    out = []
    for dp, dirs, fns in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in fns:
            if not fn.endswith(".py") or fn.startswith("test_"):
                continue
            path = os.path.join(dp, fn)
            try:
                src = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            if det.ROUTE.search(src):
                out.append(path)
    return sorted(out)


def main() -> int:
    if not os.environ.get("LITELLM_MASTER_KEY"):
        print("FAIL: LITELLM_MASTER_KEY not set")
        return 2
    if not os.path.isdir(CLONES):
        print(f"FAIL: no production clones at {CLONES} — run run_volume_census.py first")
        return 2
    if not det.self_test():
        print("FAIL: detector self-test")
        return 2

    ok, seen = canary_passes(lambda: ask(
        "@app.route('/admin/delete/<int:uid>', methods=['POST'])\n"
        "def delete_user(uid):\n"
        "    User.query.filter_by(id=uid).delete()\n"
        "    db.session.commit()\n"
        "    return 'ok'\n", "canary.py")[1], n=3, need=1)
    print(f"canary: {'PASS' if ok else 'FAIL'} {seen}")
    if not ok:
        print("ABORT: harness cannot surface a planted defect; no volume number would mean anything.")
        return 2

    rng = random.Random(SEED)
    rows, per_repo = [], {}
    for name in sorted(os.listdir(CLONES)):
        root = os.path.join(CLONES, name)
        if not os.path.isdir(root):
            continue
        files = route_files(root)
        if len(files) < 5:
            continue                                  # not a route-bearing application
        sample = rng.sample(files, min(PER_REPO, len(files)))
        repo = name.replace("__", "/")
        per_repo[repo] = {"route_files": len(files), "sampled": len(sample),
                          "model_flagged": 0, "detector_flagged": 0, "both": 0, "nonanswer": 0}
        print(f"\n{repo}: {len(files)} route-bearing files, sampling {len(sample)}")
        for path in sample:
            try:
                src = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            rel = os.path.relpath(path, root)
            det_hit = bool(det.findings_for(src, rel))
            verdict, _ = ask(src, rel)
            m_hit = verdict == "flagged"
            na = verdict not in ("flagged", "clean")
            per_repo[repo]["model_flagged"] += int(m_hit)
            per_repo[repo]["detector_flagged"] += int(det_hit)
            per_repo[repo]["both"] += int(m_hit and det_hit)
            per_repo[repo]["nonanswer"] += int(na)
            rows.append({"repo": repo, "file": rel, "verdict": verdict,
                         "model_flagged": m_hit, "detector_flagged": det_hit,
                         "chars": len(src), "truncated": len(src) > MAX_CHARS})
            mark = "M" if m_hit else ("m" if na else "-")
            print(f"    {mark}{'D' if det_hit else '-'}  {rel[:58]}")

    if len(rows) < 20:
        print(f"FAIL: only {len(rows)} files sampled")
        return 2

    n = len(rows)
    mf = sum(1 for r in rows if r["model_flagged"])
    df = sum(1 for r in rows if r["detector_flagged"])
    both = sum(1 for r in rows if r["model_flagged"] and r["detector_flagged"])
    na = sum(1 for r in rows if r["verdict"] not in ("flagged", "clean"))
    trunc = sum(1 for r in rows if r["truncated"])
    mlo, mhi = wilson(mf, n)
    dlo, dhi = wilson(df, n)

    print(f"\n=== {n} route-bearing production files across {len(per_repo)} repositories ===")
    print(f"  MODEL flags     : {mf}/{n} = {mf/n:.3f}  [{mlo:.3f}, {mhi:.3f}]")
    print(f"  DETECTOR flags  : {df}/{n} = {df/n:.3f}  [{dlo:.3f}, {dhi:.3f}]")
    print(f"  both            : {both}   model-only: {mf-both}   detector-only: {df-both}")
    print(f"  non-answers     : {na}/{n} = {na/n:.3f}")
    print(f"  files truncated at {MAX_CHARS} chars: {trunc}/{n} = {trunc/n:.3f}")

    print(f"\n  corpus comparators: model clean-arm ~0.01 (E52), detector site-precision 0.125 (E71/E78)")
    ratio = (mf / n) / 0.01 if mf else 0
    print(f"  the model's production flag rate is ~{ratio:.0f}x its corpus clean-arm rate")

    print("\n  per repository:")
    for repo, v in sorted(per_repo.items()):
        s = v["sampled"] or 1
        print(f"    {repo:<34} model {v['model_flagged']:>2}/{s:<3} "
              f"detector {v['detector_flagged']:>2}/{s:<3} both {v['both']:>2}  "
              f"-> projected over {v['route_files']:>4} route files: "
              f"model ~{round(v['model_flagged']/s*v['route_files']):>4}, "
              f"detector ~{round(v['detector_flagged']/s*v['route_files']):>4}")

    verdict = ("MODEL PRODUCES A LARGER INVENTORY than the free layer on production code"
               if mf > df else
               "model inventory is no larger than the free layer's")
    print(f"\n  {verdict}")
    print("  Volume and overlap only — no ground truth here, so nothing about which flags are correct.")
    print("  What it bounds is TRIAGE COST, which is the axis the inventory product lives or dies on.")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(),
           "question": "what inventory would the LLM produce on real repositories, next to the free "
                       "layer's ~27 decisions per production web app (E76/E78)?",
           "instrument": "corpus instrument verbatim: _BINARY_RUBRIC, 160 tokens, first 4000 chars, "
                         "scored on trace.redact_persisted output",
           "asymmetry_disclosed": "the detector reads whole files (free, offline); the model sees the "
                                  "first 4000 chars. That is how each tool would actually run, and it is "
                                  "the comparison a buyer faces, not a handicap invented here",
           "no_ground_truth": "volume and overlap only; says nothing about which flags are correct",
           "model": MODEL, "seed": SEED, "files": n, "repositories": len(per_repo),
           "model_flag_rate": round(mf / n, 4), "model_ci": [round(mlo, 4), round(mhi, 4)],
           "detector_flag_rate": round(df / n, 4), "detector_ci": [round(dlo, 4), round(dhi, 4)],
           "both": both, "model_only": mf - both, "detector_only": df - both,
           "non_answer_rate": round(na / n, 4), "truncated_fraction": round(trunc / n, 4),
           "corpus_clean_arm_rate": 0.01,
           "canary": {"passed": ok, "verdicts": seen},
           "verdict": verdict,
           "per_repo": per_repo, "rows": rows}
    with open(os.path.join(_HERE, "production-inventory-260727.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print("\nwrote production-inventory-260727.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
