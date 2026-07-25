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
    """Pool the scored rows of the given repos (with multiplicity) and return AUC per arm."""
    pooled: dict[str, list] = {k: [] for k in scored}
    for r in repos:
        for k in scored:
            pooled[k].extend(scored[k][r])
    return {k: auc(v) for k, v in pooled.items()}


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
    point = _auc_by_repo(per_repo, repos)
    print("\nleave-one-repo-out AUC:")
    for k in ("severity", "cwe_prior", "llm"):
        print(f"  {k:12s} AUC={point[k]:.3f}" if point[k] is not None else f"  {k}: n/a")

    random.seed(1)
    diffs = []
    for _ in range(2000):
        sample = [random.choice(repos) for _ in repos]
        a = _auc_by_repo(per_repo, sample)
        if a["cwe_prior"] is not None and a["llm"] is not None:
            diffs.append(a["cwe_prior"] - a["llm"])
    diffs.sort()
    lo, hi = diffs[int(0.025 * len(diffs))], diffs[int(0.975 * len(diffs))]
    delta = point["cwe_prior"] - point["llm"]
    ties = lo <= 0 <= hi
    print(f"\nPRIMARY (grouped by repo, bootstrap over {n_repos} repos):")
    print(f"  AUC(cwe_prior) - AUC(llm) = {delta:+.3f}  95%CI=[{lo:+.3f},{hi:+.3f}]  "
          f"-> {'TIE (CI includes 0)' if ties else 'prior WINS'}")

    # Secondary, exploratory: the row-split number on identical data, to size the leakage directly.
    rs_rows = rows[:]
    random.seed(0)
    random.shuffle(rs_rows)
    half = len(rs_rows) // 2
    prior, base = fit_cwe_prior(rs_rows[:half])
    row_delta = auc(score_rows(rs_rows[half:], "cwe_prior", prior, base)) - \
        auc(score_rows(rs_rows[half:], "llm", prior, base))
    print(f"\nEXPLORATORY (row split, the withdrawn method): {row_delta:+.3f}")
    print(f"  leakage gap = {row_delta - delta:+.3f} AUC attributable to splitting by row, not repo")

    out = {"n_rows": len(rows), "n_repos": n_repos, "loso_auc": point,
           "primary_delta": round(delta, 4), "ci95": [round(lo, 4), round(hi, 4)],
           "verdict": "tie" if ties else "prior-wins",
           "exploratory_row_split_delta": round(row_delta, 4)}
    with open(os.path.join(_HERE, "rank-grouped-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
