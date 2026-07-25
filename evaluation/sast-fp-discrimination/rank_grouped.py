"""Leave-one-repo-out ranking comparison: does the deterministic CWE prior really beat the LLM?

Decision 0021 first published "+0.069 AUC, deterministic prior WINS", then withdrew it in prose as a
row-split artefact and amended it to a tie. The withdrawal never reached the code: `rank_baselines.py`
kept its row-level `random.shuffle` and went on printing the retracted number with a confident verdict.
This module is the corrected instrument, and `tests/sast-measurement-test.sh` pins it.

Why the split matters. Rows drawn from the same repository are not independent: one repo's coding style
fixes both which CWEs appear and whether they are real. Fitting the CWE prior on a random half of the
ROWS therefore lets it learn each repo's answer key and then be graded on the same repos. Splitting by
REPOSITORY removes that channel, which is the deployment-realistic question anyway: the prior will meet
repos it was never fitted on.

The committed baseline records no repo field — the grouping unit was discarded when it was written,
which is precisely why no grouped analysis was ever reproducible from it. Repo labels are therefore
reconstructed deterministically (see `reconstruct_groups`) and the reconstruction is REJECTED unless it
matches the committed rows position-for-position.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/rank_grouped.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import random
import statistics
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import run_spike as rs  # noqa: E402

_rb = importlib.util.spec_from_file_location("rank_baselines", os.path.join(_HERE, "rank_baselines.py"))
rank_baselines = importlib.util.module_from_spec(_rb)
_rb.loader.exec_module(rank_baselines)

BASELINE = os.path.join(_HERE, "annotate-baseline-260725.json")
auc = rank_baselines.auc
fit_cwe_prior = rank_baselines.fit_cwe_prior
score_rows = rank_baselines.score_rows


def reconstruct_groups(rows: list[dict]) -> list[str] | None:
    """Recover each row's repository by replaying the deterministic half of `run_annotate.py`.

    That script appends exactly one row per Bandit finding, iterating `sorted(os.listdir(REPOS))` and
    dropping nothing, so per-repo finding counts are offsets into the row list. Returns None if the
    replay does not reproduce the committed rows exactly — an unverified join is worse than no analysis.
    """
    groups: list[str] = []
    replay: list[tuple] = []
    for slug in sorted(os.listdir(rs.REPOS)):
        for f in rs.bandit_findings(os.path.join(rs.REPOS, slug)):
            groups.append(slug)
            replay.append((f["cwe"], f.get("severity")))

    if len(replay) != len(rows):
        print(f"ABORT: replay produced {len(replay)} findings, committed baseline has {len(rows)}.")
        return None
    for i, (cwe, sev) in enumerate(replay):
        if cwe != rows[i]["cwe"] or sev != rows[i]["severity"]:
            print(f"ABORT: replay diverges from the committed baseline at row {i}.")
            return None
    return groups


def loso_scores(rows: list[dict], groups: list[str], key: str) -> list[tuple[float, bool]]:
    """Leave-one-repo-out scoring: the prior is fitted only on repos other than the one being scored.

    The LLM score is a fixed annotation, so it is unaffected by the split; it is routed through the same
    loop anyway so both arms are scored on an identical row set and the comparison stays paired.
    """
    out: list[tuple[float, bool]] = []
    for held_repo in sorted(set(groups)):
        dev = [r for r, g in zip(rows, groups) if g != held_repo]
        held = [r for r, g in zip(rows, groups) if g == held_repo]
        if not held:
            continue
        prior, base = fit_cwe_prior(dev)
        out.extend(score_rows(held, key, prior, base))
    return out


def _auc_by_repo(scored: dict[str, list[tuple[float, bool]]], repos: list[str]):
    """MICRO estimand: pool every scored row into one ranking and take a single AUC.

    An adversarial review measured that only **1.9%** of the TP/FP pairs this ranks are within-repo —
    98% of the comparison is "is repo A's true positive scored above repo B's false positive?". That is
    the right question only if findings from every application land in ONE global triage queue.
    """
    pooled: dict[str, list] = {k: [] for k in scored}
    for r in repos:
        for k in scored:
            pooled[k].extend(scored[k][r])
    return {k: auc(v) for k, v in pooled.items()}


def _auc_macro(scored: dict[str, list[tuple[float, bool]]], repos: list[str]):
    """MACRO estimand: AUC computed WITHIN each repo, then averaged over repos.

    This is the deployment-realistic question for this project's stated user: a pentest team works one
    client application at a time, so the ranking that matters is within an application. Nobody triages
    client A's SQL injection against client B's false positive in a single queue.
    """
    out = {}
    for k in scored:
        vals = [auc(scored[k][r]) for r in repos]
        vals = [v for v in vals if v is not None]     # repos lacking both classes have no AUC
        out[k] = statistics.fmean(vals) if vals else None
    return out


def matched_grouping_effect(rows, groups, repos) -> float:
    """The leakage attributable to GROUPING ALONE, holding fold count and train size fixed.

    The first version of this experiment subtracted a 61-fold grouped run from a 50/50 row split and
    published the difference (+0.057) as "the leakage". That subtraction confounded three things at
    once: grouping, training-set size (882 rows vs ~1735), and the evaluation set. Here the only thing
    that differs between the two arms is whether folds respect repository boundaries.
    """
    def pooled_delta(folds):
        sc = {k: [] for k in ("cwe_prior", "llm")}
        for held_idx in folds:
            hs = set(held_idx)
            dev = [rows[i] for i in range(len(rows)) if i not in hs]
            held = [rows[i] for i in held_idx]
            prior, base = fit_cwe_prior(dev)
            for k in sc:
                sc[k].extend(score_rows(held, k, prior, base))
        return auc(sc["cwe_prior"]) - auc(sc["llm"])

    grouped = [[i for i, g in enumerate(groups) if g == r] for r in repos]
    rnd = random.Random(3)
    perm = list(range(len(rows)))
    rnd.shuffle(perm)
    randfolds, p = [], 0
    for f in grouped:                                  # identical fold sizes -> identical train sizes
        randfolds.append(perm[p:p + len(f)])
        p += len(f)
    return pooled_delta(randfolds) - pooled_delta(grouped)


def main() -> int:
    if not os.path.exists(BASELINE):
        print(f"FAIL: {BASELINE} missing — run run_annotate.py first")
        return 2
    if not os.path.isdir(rs.REPOS):
        print(f"FAIL: corpus not fetched — run {os.path.join(_HERE, 'fetch.sh')}")
        return 2

    rows = json.load(open(BASELINE, encoding="utf-8"))["rows"]
    groups = reconstruct_groups(rows)
    if groups is None:
        print("FAIL: could not verify the row->repo reconstruction; refusing to report a grouped result.")
        return 2

    n_repos = len(set(groups))
    print(f"reconstruction verified: {len(rows)} rows across {n_repos} repos "
          f"(committed baseline records no repo field; labels replayed deterministically)")

    # Primary outcome: leave-one-repo-out, bootstrapped over REPOS (the grouping unit).
    per_repo: dict[str, dict[str, list]] = {k: {} for k in ("cwe_prior", "llm", "severity")}
    for key in per_repo:
        for held_repo in sorted(set(groups)):
            dev = [r for r, g in zip(rows, groups) if g != held_repo]
            held = [r for r, g in zip(rows, groups) if g == held_repo]
            prior, base = fit_cwe_prior(dev)
            per_repo[key][held_repo] = score_rows(held, key, prior, base)

    repos = sorted(set(groups))
    scorable = [r for r in repos if auc(per_repo["cwe_prior"][r]) is not None]

    micro = _auc_by_repo(per_repo, repos)
    macro = _auc_macro(per_repo, scorable)
    micro_d = micro["cwe_prior"] - micro["llm"]
    macro_d = macro["cwe_prior"] - macro["llm"]

    def ci(fn, pool, seed):
        rnd = random.Random(seed)
        ds = []
        for _ in range(2000):
            sample = [rnd.choice(pool) for _ in pool]
            a = fn(per_repo, sample)
            if a["cwe_prior"] is not None and a["llm"] is not None:
                ds.append(a["cwe_prior"] - a["llm"])
        ds.sort()
        return ds[int(.025 * len(ds))], ds[int(.975 * len(ds))]

    ma_lo, ma_hi = ci(_auc_macro, scorable, 11)
    mi_lo, mi_hi = ci(_auc_by_repo, repos, 1)

    print(f"\nPRIMARY — per-application ranking (MACRO: AUC within each repo, averaged over "
          f"{len(scorable)} scorable repos)")
    print(f"  prior={macro['cwe_prior']:.3f}  llm={macro['llm']:.3f}")
    print(f"  delta = {macro_d:+.3f}  95%CI=[{ma_lo:+.3f},{ma_hi:+.3f}]  -> "
          f"{'TIE (CI includes 0)' if ma_lo <= 0 <= ma_hi else 'deterministic prior WINS'}")
    print("  This is the estimand that matches how the tool is used: a pentest team triages ONE client")
    print("  application at a time, so what matters is the ranking within an application.")

    print(f"\nSECONDARY — one global cross-application queue (MICRO: all rows pooled)")
    print(f"  prior={micro['cwe_prior']:.3f}  llm={micro['llm']:.3f}")
    print(f"  delta = {micro_d:+.3f}  95%CI=[{mi_lo:+.3f},{mi_hi:+.3f}]  -> "
          f"{'TIE (CI includes 0)' if mi_lo <= 0 <= mi_hi else 'deterministic prior WINS'}")
    print("  Only 1.9% of the pairs this ranks are within-repo, so it answers a question nobody asks")
    print("  unless findings from every client land in one queue. Reported, not headlined.")

    grouping = matched_grouping_effect(rows, groups, repos)
    print(f"\nLEAKAGE — grouping effect at matched fold count and train size: {grouping:+.3f}")
    print("  An earlier version subtracted a 61-fold grouped run from a 50/50 row split and published")
    print("  the difference (+0.057) as 'the leakage'. That confounded grouping with train size and")
    print("  eval set; holding those fixed, grouping alone is worth the figure above.")

    out = {"n_rows": len(rows), "n_repos": n_repos, "n_scorable_repos": len(scorable),
           "primary_estimand": "macro-per-repo",
           "macro": {"auc": macro, "delta": round(macro_d, 4), "ci95": [round(ma_lo, 4), round(ma_hi, 4)],
                     "verdict": "tie" if ma_lo <= 0 <= ma_hi else "prior-wins"},
           "micro": {"auc": micro, "delta": round(micro_d, 4), "ci95": [round(mi_lo, 4), round(mi_hi, 4)],
                     "verdict": "tie" if mi_lo <= 0 <= mi_hi else "prior-wins",
                     "within_repo_pair_share": 0.019},
           "matched_grouping_effect": round(grouping, 4),
           "bootstrap_caveat": "resamples pre-computed LOSO scores without refitting the prior, so both "
                               "intervals are somewhat NARROWER than a fully nested procedure would give"}
    with open(os.path.join(_HERE, "rank-grouped-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
