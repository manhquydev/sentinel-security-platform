"""Does a reviewer-in-the-loop learner allocate inspection effort better than density ordering?

E60 built a ranker from four prespecified security signals and it came out **worse than chance** — the
signals anti-correlate with real defects on this corpus. E64 then found that ordering FILES by finding
density beats chance decisively, but proved the gain is entirely the unit of work rather than any
prioritisation: measured per finding read, the advantage vanishes.

External practice appears to supply a benchmark. HARMLESS (arxiv 1803.06545) reports finding **80, 90, 95,
99% of vulnerabilities by inspecting 10, 16, 20, 34% of source files** using active learning, against ~37%
for the density ordering here — apparently more than twice as efficient.

**THAT COMPARISON IS INADMISSIBLE, AND THIS SCRIPT PROVES IT RATHER THAN ASSUMING IT.** It computes the
ORACLE ordering — files opened in descending true-defect count, which no ranker can beat — and the oracle
needs **30.4%** of files to reach 90% here. HARMLESS's 16% is below what perfect knowledge achieves on this
corpus, so the gap is not a ranker deficit. Effort is a function of how concentrated defects are, and 38%
of these files carry one, against a small minority in the setting HARMLESS was measured on.

The oracle is therefore the only honest baseline, and it leaves the density ordering just **6.5 points**
from perfect. That is the headroom any prioritisation method is competing for.

THAT IS NOT AN EXTRA REQUIREMENT — IT IS THE WORKFLOW WE ALREADY HAVE. The inventory framing (E61, E64)
has a security owner opening files and answering "are these routes public by design?". Every answer is a
label. The reviewer IS an active-learning oracle, already present, already paid for.

THE PREDICTION THIS TESTS, AND WHY IT IS SHARP. E60's signals were not merely useless, they pointed the
WRONG WAY: precision fell monotonically 0.250 -> 0.062 as signals accumulated. A learner is not told which
direction is good — it estimates the sign from data. So if E60's finding is real rather than noise, a
learner should discover the negative weights and **beat both chance and the hand-built ranker**, using the
very features that failed when their direction was assumed. If it does not, E60's inversion was noise.

NO TEST-SET LEAKAGE IS POSSIBLE BY CONSTRUCTION. Evaluation is prequential: every file is scored and
chosen BEFORE its label is revealed, and the learner only ever trains on labels already paid for by a
reviewer who opened that file. This is the one setting where fitting on the evaluation corpus is legitimate,
and it is the reason this experiment can run at all with 70 positives.

THE CONTROL THAT CAN KILL IT: the identical pipeline with SHUFFLED labels. If that also beats chance, the
protocol manufactures its own result and nothing here can be believed.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/run_active_triage.py
"""

from __future__ import annotations

import collections
import json
import math
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
import rank_absent_auth as R  # noqa: E402

SEED = 20260726
SEED_FILES = 5          # opened before any learning is possible — the reviewer has to start somewhere
TARGETS = (0.80, 0.90, 0.95)   # the depths HARMLESS publishes, so the comparison is like for like
HARMLESS = {0.80: 0.10, 0.90: 0.16, 0.95: 0.20}


def features(sites: list[dict], repo: str, rel: str) -> set[str]:
    """Binary features for one FILE, the reviewer's unit of decision.

    Deliberately includes E60's four signals, whose assumed direction failed. A learner estimates the sign
    instead of being told it, which is exactly the difference under test.
    """
    f = set()
    scores = [s["score"] for s in sites]
    for s in sites:
        for sig in s["signals"]:
            f.add("sig:" + sig)
    f.add("maxsig:%d" % max(scores))
    f.add("nfind:%s" % ("1" if len(sites) == 1 else "2-4" if len(sites) <= 4 else
                        "5-9" if len(sites) <= 9 else "10+"))
    low = rel.lower()
    for seg in ("test", "admin", "api", "auth", "view", "route", "main", "app", "model"):
        if seg in low:
            f.add("path:" + seg)
    f.add("depth:%d" % min(low.count("/"), 3))
    try:
        n = len(open(os.path.join(rs.REPOS, repo, rel), encoding="utf-8", errors="replace").read())
    except OSError:
        n = 0
    f.add("size:%s" % ("s" if n < 2000 else "m" if n < 8000 else "l"))
    return f


class NaiveBayes:
    """Log-odds over binary features with Laplace smoothing.

    Chosen over anything heavier because the whole corpus offers ~70 positives: a model with many free
    parameters would fit the reviewer's first few answers and report its own noise back. This has one
    counter per feature and its weights are directly readable, which matters here — the experiment's claim
    is about the SIGN the learner recovers.
    """

    def __init__(self) -> None:
        self.pos = collections.Counter()
        self.neg = collections.Counter()
        self.npos = self.nneg = 0

    def learn(self, feats: set[str], label: bool) -> None:
        (self.pos if label else self.neg).update(feats)
        if label:
            self.npos += 1
        else:
            self.nneg += 1

    def score(self, feats: set[str]) -> float:
        if not self.npos or not self.nneg:
            return 0.0
        out = math.log(self.npos / self.nneg)
        for f in feats:
            p = (self.pos[f] + 1) / (self.npos + 2)
            q = (self.neg[f] + 1) / (self.nneg + 2)
            out += math.log(p / q)
        return out

    def weights(self) -> list[tuple[str, float]]:
        ws = []
        for f in set(self.pos) | set(self.neg):
            p = (self.pos[f] + 1) / (self.npos + 2)
            q = (self.neg[f] + 1) / (self.nneg + 2)
            ws.append((f, math.log(p / q)))
        return sorted(ws, key=lambda t: -abs(t[1]))


def run(files, feats, tps, total_tp, order_seed, shuffle_labels=False, rng=None):
    """Prequential active triage. Returns the cumulative defects-reached curve, one point per file opened."""
    labels = dict(tps)
    if shuffle_labels:
        vals = list(labels.values())
        rng.shuffle(vals)
        labels = dict(zip(labels, vals))

    remaining = list(files)
    rng.shuffle(remaining)
    opened, got, curve = [], 0, []
    nb = NaiveBayes()
    for _ in range(len(files)):
        if len(opened) < SEED_FILES:
            pick = remaining[0]                       # nothing learned yet; the reviewer just starts
        else:
            pick = max(remaining, key=lambda f: nb.score(feats[f]))
        remaining.remove(pick)
        opened.append(pick)
        got += labels[pick]                           # label revealed only AFTER the file was chosen
        nb.learn(feats[pick], labels[pick] > 0)
        curve.append(got / total_tp)
    return curve, nb


def effort_for(curve: list[float], target: float) -> float:
    for i, v in enumerate(curve, 1):
        if v >= target:
            return i / len(curve)
    return 1.0


def main() -> int:
    if not os.path.isdir(rs.REPOS):
        print("FAIL: corpus not fetched")
        return 2
    sites = R.collect()
    byfile = collections.defaultdict(list)
    for s in sites:
        byfile[(s["repo"], s["file"])].append(s)
    files = sorted(byfile)
    feats = {f: features(byfile[f], f[0], f[1]) for f in files}
    tps = {f: sum(1 for s in byfile[f] if s["tp"]) for f in files}
    total_tp = sum(tps.values())
    print(f"{len(files)} files, {len(sites)} findings, {total_tp} real defects")
    print(f"seed: {SEED_FILES} files opened before learning starts\n")

    rng = random.Random(SEED)
    N = 200
    real = [run(files, feats, tps, total_tp, SEED, False, rng) for _ in range(N)]
    ctrl = [run(files, feats, tps, total_tp, SEED, True, rng) for _ in range(N)]

    # THE ORACLE. Files opened in descending TRUE defect count — no ranker can beat this ordering, so it
    # is the ceiling this corpus permits. Without it, a comparison against a published curve from another
    # corpus is uninterpretable: an effort figure is a function of how concentrated the defects are, and
    # a benchmark where 38% of files carry a defect cannot produce the numbers of one where they are rare.
    oracle, ocurve, cum = sorted(files, key=lambda f: -tps[f]), [], 0
    for f in oracle:
        cum += tps[f]
        ocurve.append(cum / total_tp)
    files_with_defect = sum(1 for v in tps.values() if v)
    print(f"defect concentration: {files_with_defect}/{len(files)} files carry one "
          f"= {files_with_defect/len(files):.1%}\n")

    dense = sorted(files, key=lambda f: (-len(byfile[f]), f))
    dcurve, dgot = [], 0
    for f in dense:
        dgot += tps[f]
        dcurve.append(dgot / total_tp)

    print(f"{'reach':>6} {'ORACLE':>8} {'ACTIVE':>16} {'shuffled ctl':>13} {'density':>9} "
          f"{'random':>8} {'HARMLESS':>9}")
    results = {}
    for t in TARGETS:
        a = sorted(effort_for(c, t) for c, _ in real)
        c = sorted(effort_for(cc, t) for cc, _ in ctrl)
        med = a[len(a) // 2]
        lo, hi = a[int(0.05 * len(a))], a[int(0.95 * len(a))]
        cmed = c[len(c) // 2]
        print(f"{t:>6.0%} {effort_for(ocurve, t):>8.1%} {med:>9.1%} [{lo:.0%},{hi:.0%}] "
              f"{cmed:>12.1%} {effort_for(dcurve, t):>9.1%} {t:>8.0%} {HARMLESS[t]:>9.0%}")
        results[f"{t:.2f}"] = {"oracle_effort": round(effort_for(ocurve, t), 4),
                               "active_median_effort": round(med, 4),
                               "active_p05_p95": [round(lo, 4), round(hi, 4)],
                               "shuffled_control_median": round(cmed, 4),
                               "density_effort": round(effort_for(dcurve, t), 4),
                               "random_expected": t, "harmless_published": HARMLESS[t]}

    t90 = results["0.90"]
    ctl_ok = t90["shuffled_control_median"] >= 0.80          # a shuffled label set must not rank
    beats_density = t90["active_median_effort"] < t90["density_effort"]
    print(f"\ncontrol (shuffled labels) reaches 90% only at {t90['shuffled_control_median']:.0%} of files "
          f"— {'behaves: the protocol invents nothing' if ctl_ok else 'DOES NOT BEHAVE, results void'}")
    print(f"active vs density at 90%: {t90['active_median_effort']:.1%} vs "
          f"{t90['density_effort']:.1%} — {'learner wins' if beats_density else 'no gain over density'}")

    o90 = results["0.90"]["oracle_effort"]
    print(f"\nORACLE at 90% = {o90:.1%}. HARMLESS publishes {HARMLESS[0.90]:.0%} on ITS corpus, which is")
    print("below what any ordering can achieve here, so the two are NOT comparable: effort is a function")
    print(f"of defect concentration, and {files_with_defect}/{len(files)} files carrying a defect leaves")
    print(f"only {results['0.90']['density_effort'] - o90:+.1%} of headroom between density and perfect.")

    _, nb = real[0]
    print("\nwhat the learner concluded about E60's four signals "
          "(negative = predicts NO defect, which is what E60 measured):")
    for f, w in nb.weights():
        if f.startswith(("sig:", "maxsig:")):
            print(f"   {f:<22} {w:+.3f}")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(),
           "question": "does reviewer-in-the-loop learning beat density ordering on this inventory?",
           "protocol": "prequential — every file scored and chosen BEFORE its label is revealed; the "
                       "learner trains only on labels a reviewer already paid for by opening the file",
           "learner": "naive Bayes log-odds over binary file features, Laplace smoothed",
           "runs": N, "seed_files": SEED_FILES, "files": len(files), "real_defects": total_tp,
           "negative_control": "identical pipeline with shuffled labels",
           "control_behaves": ctl_ok, "beats_density_at_90": beats_density,
           "harmless_reference": "arxiv 1803.06545 — 80/90/95% of vulnerabilities at 10/16/20% of files, "
                                "on a corpus where vulnerable files are a small minority; NOT comparable "
                                "to this one, where the oracle itself cannot match those figures",
           "defect_concentration": round(files_with_defect / len(files), 4),
           "headroom_density_to_oracle_at_90": round(
               results["0.90"]["density_effort"] - results["0.90"]["oracle_effort"], 4),
           "targets": results,
           "learned_signal_weights": {f: round(w, 4) for f, w in nb.weights()
                                      if f.startswith(("sig:", "maxsig:"))}}
    with open(os.path.join(_HERE, "active-triage-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
