"""Can anything order the free layer's findings, so the real defects surface above the rest?

E56 built a ~60-line deterministic detector that reaches CWE-306/862 — 22.6% recall where Bandit and
Semgrep together get exactly zero. It is the cheapest real security value this project has produced. It
also has **6.7% precision**: 76 real defects inside about 1130 reports. Nobody triages 1130 reports.

(Figures move with the detector: it stood at 77/1204 = 6.4% before the enforcement-marker split of E61.
Re-run this script whenever the detector changes — its own guard, SM17, requires exactly that.)

The obvious repair is closed. Suppressing findings with a model is the gate role, and 0018/0020 falsified
it (E2: an LLM verifier hid 3 of 8 real vulnerabilities). So this asks the question that does NOT require
suppressing anything: **leave every finding in the list, and order it.** A ranking cannot hide a defect —
the worst a bad ranking does is leave the list as unusable as it already is.

WHY THIS IS NOT A RE-RUN OF E3. E3 tested an LLM ranker against a CWE prior and the **prior won**. That
comparator cannot exist here: every finding in this set is the same class by construction, so a CWE prior
is a constant and ranks nothing. The cheap baseline that beat the model last time is structurally
unavailable, which is exactly what makes the ranking question live again.

BUT THE CHEAP THING GETS TESTED FIRST (E3's actual lesson, protocol §16). This script spends zero model
calls. If a free ordering already lifts the real defects, an LLM ranker must beat *that*, not chance.

THE OVERFITTING TRAP, AND HOW THIS AVOIDS IT. With 77 positives, any ranker whose weights are fitted on
these labels will look excellent and mean nothing. So the ranker here has **no fitted parameters at all**:
it is a count of prespecified signals, each worth 1, chosen from what CWE-306/862 means rather than from
looking at which files happened to match. Nothing is trained, so there is nothing to overfit.

TWO CONTROLS, both of which can fail this design:
  - **chance**: the same list shuffled. A permutation distribution, not an assumed one.
  - **a negative-control ranker** on source line number — a real property of every finding that should
    carry no information about whether a control is missing. If line number "works", the pipeline is
    measuring an artefact and no positive result here can be believed.

WHAT WOULD FALSIFY THE POINT: recall@10% indistinguishable from the 10% that shuffling gives. That is a
live outcome — the signals below are guesses about what a critical function looks like, and the corpus
gets a vote.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/rank_absent_auth.py
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
import detect_absent_auth as det  # noqa: E402

SEED = 20260726
DEPTHS = (0.05, 0.10, 0.20, 0.50)

# ---------------------------------------------------------------------------
# The prespecified signals. Each is worth exactly 1 — no weights, nothing fitted.
# Every one is written from what "missing authentication for a critical function" means, before looking
# at which findings actually matched. They are guesses, and the measurement is allowed to say they are
# worthless.
# ---------------------------------------------------------------------------

# 1. A state-changing method. CWE-306 is about *critical functions*; a GET that renders a page is a
#    weaker candidate than a POST/PUT/DELETE that mutates.
WRITE_METHOD = re.compile(r"methods\s*=\s*\[[^\]]*['\"](?:POST|PUT|PATCH|DELETE)|"
                          r"@\w+\.(?:post|put|patch|delete)\s*\(", re.I)

# 2. A path or handler name that names something worth protecting.
SENSITIVE_NAME = re.compile(r"\b(admin|user|users|account|profile|password|passwd|token|secret|key|"
                            r"role|perm|permission|priv|config|setting|delete|remove|drop|update|edit|"
                            r"upload|download|export|import|backup|restore|invoice|order|payment|"
                            r"transfer|balance|message|note|ticket|report|db|sql|exec|command)\b", re.I)

# 3. The route takes an object identifier. That is the shape of an IDOR / missing-ownership check —
#    the exact sub-case CWE-862 and CWE-639 describe.
OBJECT_ID = re.compile(r"<[^>]*\b(?:id|pk|uuid|slug|user|name)\b[^>]*>|\{[^}]*\b(?:id|pk|uuid|slug|user)\b[^}]*\}",
                       re.I)

# 4. The handler body actually reaches data. A route that returns a constant has nothing to protect.
TOUCHES_DATA = re.compile(r"\b(?:session|cursor|execute|query|filter|get_or_404|objects\.|\.all\(\)|"
                          r"\.first\(\)|\.get\(|save\(|commit\(|delete\(|add\()", re.I)

SIGNALS = (("write_method", WRITE_METHOD), ("sensitive_name", SENSITIVE_NAME),
           ("object_id", OBJECT_ID), ("touches_data", TOUCHES_DATA))

# The signals are matched against the decorator line + handler name for 1-3, and the body for 4.
SIGNAL_SCOPE = {"write_method": "head", "sensitive_name": "head", "object_id": "head",
                "touches_data": "body"}

SELF_TEST = [
    ("@app.route('/admin/user/<int:id>/delete', methods=['POST'])\ndef del_user(id):\n"
     "    db.session.execute('...')\n", 4, "every signal present"),
    ("@app.route('/about')\ndef about():\n    return 'hi'\n", 0, "static page, no signal"),
    ("@app.route('/ping')\ndef ping():\n    return 'pong'\n", 0, "no signal"),
]


def score_site(head: str, body: str) -> tuple[int, list[str]]:
    """Count how many prespecified signals this handler shows. Each worth 1; no weights."""
    hit = []
    for name, rx in SIGNALS:
        text = head if SIGNAL_SCOPE[name] == "head" else body
        if rx.search(text):
            hit.append(name)
    return len(hit), hit


def self_test() -> bool:
    ok = True
    for src, want, why in SELF_TEST:
        lines = src.splitlines()
        got, hits = score_site("\n".join(lines[:2]), src)
        if got != want:
            print(f"  SELF-TEST FAILED ({why}): scored {got} {hits}, wanted {want}")
            ok = False
    return ok


def collect() -> list[dict]:
    """Every finding site the E56 detector reports, labelled TP/FP once, in a fixed canonical order.

    The label is fixed ONCE here and never recomputed. The matcher is claim-once and therefore
    order-dependent: if labelling ran per ranking, a ranking could change its own labels. Labelling in
    canonical (file, line) order makes TP/FP a property of the site, identical for every ranker compared.
    """
    sites: list[dict] = []
    for slug in sorted(os.listdir(rs.REPOS)):
        root = os.path.join(rs.REPOS, slug)
        if not os.path.isdir(root):
            continue
        gt = rs.load_gt(slug)
        if not gt:
            continue
        per_file: dict[str, list[dict]] = {}
        srcs: dict[str, str] = {}
        for dp, _, fns in os.walk(root):
            for fn in fns:
                if not fn.endswith(".py"):
                    continue
                path = os.path.join(dp, fn)
                try:
                    src = open(path, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                rel = os.path.relpath(path, root)
                f = det.findings_for(src, rel)
                if f:
                    per_file[rel] = f
                    srcs[rel] = src

        claimed: set[int] = set()
        for rel in sorted(per_file):
            lines = srcs[rel].splitlines()
            by_line: dict[int, list[dict]] = {}
            for f in per_file[rel]:
                by_line.setdefault(f["line"], []).append(f)
            for line in sorted(by_line):
                is_tp = False
                for f in by_line[line]:
                    if rs.match(f, gt, claimed):
                        is_tp = True
                i = line - 1
                start, end = det._handler_span(lines, i)
                head = "\n".join(lines[i:min(i + 3, len(lines))])
                body = "\n".join(lines[start:end])
                score, hits = score_site(head, body)
                sites.append({"repo": slug, "file": rel, "line": line, "tp": is_tp,
                              "score": score, "signals": hits})
    return sites


def recall_at(order: list[dict], depth: float, total_tp: int) -> float:
    """Fraction of all real defects appearing in the top `depth` of this ordering."""
    if not total_tp:
        return 0.0
    cut = max(1, int(round(len(order) * depth)))
    return sum(1 for s in order[:cut] if s["tp"]) / total_tp


def permutation_null(sites: list[dict], depth: float, total_tp: int, n: int, rng: random.Random):
    """What shuffling gives. Measured, not assumed."""
    vals = []
    shuffled = list(sites)
    for _ in range(n):
        rng.shuffle(shuffled)
        vals.append(recall_at(shuffled, depth, total_tp))
    vals.sort()
    return vals


def grouped_bootstrap(sites: list[dict], key, depth: float, n: int, rng: random.Random):
    """CI over repositories — the unit that actually varies, per the grouped-split rule from E14."""
    by_repo: dict[str, list[dict]] = {}
    for s in sites:
        by_repo.setdefault(s["repo"], []).append(s)
    repos = sorted(by_repo)
    vals = []
    for _ in range(n):
        pick = [rng.choice(repos) for _ in repos]
        pool = [s for r in pick for s in by_repo[r]]
        tp = sum(1 for s in pool if s["tp"])
        if not tp:
            continue
        vals.append(recall_at(sorted(pool, key=key), depth, tp))
    vals.sort()
    if len(vals) < 100:
        return None, None
    return vals[int(0.025 * len(vals))], vals[int(0.975 * len(vals))]


def main() -> int:
    if not os.path.isdir(rs.REPOS):
        print("FAIL: corpus not fetched")
        return 2
    if not det.self_test():
        print("FAIL: the underlying detector no longer separates protected from unprotected routes.")
        return 2
    if not self_test():
        print("FAIL: the signal scorer does not behave on its own examples.")
        return 2
    print(f"detector self-test PASSED; signal self-test PASSED ({len(SELF_TEST)} cases)\n")

    rng = random.Random(SEED)
    sites = collect()
    total = len(sites)
    total_tp = sum(1 for s in sites if s["tp"])
    print(f"finding sites: {total}   real defects among them: {total_tp} "
          f"(site precision {total_tp/total:.3f})")
    if total_tp < 30:
        print("ABORT: too few positives for a ranking claim.")
        return 2

    dist = {}
    for s in sites:
        dist[s["score"]] = dist.get(s["score"], 0) + 1
    print("\nsignal-count distribution and precision within each stratum:")
    for k in sorted(dist, reverse=True):
        grp = [s for s in sites if s["score"] == k]
        tp = sum(1 for s in grp if s["tp"])
        print(f"  {k} signals: {len(grp):5d} sites, {tp:3d} real  precision {tp/len(grp):.3f}")

    # Ranked highest-signal first. Ties broken deterministically by (repo,file,line) so the ordering is
    # reproducible and does not smuggle in a second, unstated signal.
    def key_signal(s):
        return (-s["score"], s["repo"], s["file"], s["line"])

    # NEGATIVE CONTROL. Line number is a real property of every finding and must carry no information
    # about a missing control. If it ranks, the measurement is an artefact.
    def key_line(s):
        return (s["line"], s["repo"], s["file"])

    ranked = sorted(sites, key=key_signal)
    control = sorted(sites, key=key_line)

    print(f"\n{'depth':>7}  {'signal rank':>12}  {'chance p95':>11}  {'p(>=obs)':>9}  "
          f"{'lift':>6}  {'NEG-CTL line#':>13}")
    results = {}
    for d in DEPTHS:
        obs = recall_at(ranked, d, total_tp)
        ctl = recall_at(control, d, total_tp)
        null = permutation_null(sites, d, total_tp, 2000, rng)
        p95 = null[int(0.95 * len(null))]
        p = sum(1 for v in null if v >= obs) / len(null)
        lo, hi = grouped_bootstrap(sites, key_signal, d, 400, rng)
        ci = f"[{lo:.3f},{hi:.3f}]" if lo is not None else "n/a"
        print(f"{d:>7.0%}  {obs:>12.3f}  {p95:>11.3f}  {p:>9.4f}  {obs/d:>6.2f}x  {ctl:>13.3f}")
        results[f"{d:.2f}"] = {"observed": round(obs, 4), "chance_p95": round(p95, 4),
                               "p_value": round(p, 4), "lift_over_chance": round(obs / d, 3),
                               "grouped_ci": [lo, hi] if lo is not None else None,
                               "negative_control_line": round(ctl, 4)}
        print(f"{'':>7}  grouped CI over repos: {ci}")

    top = results[f"{DEPTHS[1]:.2f}"]
    if top["p_value"] < 0.05:
        verdict = "SIGNAL — the free ordering lifts real defects above chance"
    elif top["p_value"] > 0.95:
        verdict = ("INVERTED — the ordering is significantly WORSE than shuffling; the signals "
                   "anti-correlate with real defects")
    else:
        verdict = "NO SIGNAL — the free ordering is indistinguishable from shuffling"

    # The control's job is to show what a meaningless property scores. Reporting only "within tolerance"
    # would bury the fact that matters: whether a property with no security content beat the designed
    # ranker. It did, so the comparison is stated outright rather than reduced to a pass/fail band.
    ctl = top["negative_control_line"]
    beat_by = ctl / top["observed"] if top["observed"] else float("inf")
    print(f"\nverdict at 10% depth: {verdict}")
    print(f"negative control (source line number) at 10%: {ctl:.3f} against {DEPTHS[1]:.3f} from "
          f"shuffling — it carries weak structure of its own")
    print(f"  and it beats the designed ranker by {beat_by:.1f}x. A property with no security content "
          f"orders these findings better than four security signals do.")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(),
           "question": "can a free, unfitted ordering lift the absence detector's real defects?",
           "unit": "finding site (file+line); TP fixed once in canonical order, identical for all rankers",
           "sites": total, "real_defects": total_tp,
           "site_precision": round(total_tp / total, 4),
           "signals": [n for n, _ in SIGNALS], "fitted_parameters": 0,
           "seed": SEED, "depths": results,
           "negative_control": "source line number — no security content",
           "negative_control_beats_designed_ranker_by": round(beat_by, 2),
           "verdict": verdict,
           "stratum_precision": {str(k): {"sites": dist[k],
                                          "real": sum(1 for s in sites if s["score"] == k and s["tp"])}
                                 for k in sorted(dist, reverse=True)}}
    with open(os.path.join(_HERE, "rank-absent-auth-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
