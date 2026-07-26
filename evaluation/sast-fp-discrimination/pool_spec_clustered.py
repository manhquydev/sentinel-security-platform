"""The corpus has 36 independent applications, not 63. Do the flagship intervals survive re-clustering?

The 40 `llm_generated` repositories are not 40 applications: the manifest shows they are **10 application
specs x 4 generators** (claude-code, codex, codex-high, kimi-code), each generator implementing the same
spec with the same seeding process. Four implementations of `crm-saas-django` share structure, route
names and seeded-defect placement — they are replicates, not independent draws. With the 26 human-authored
repositories that makes **36 independent applications**.

Every grouped statistic this project has published bootstraps over the 63 fetched repositories as if they
were independent. The flagship number — the multi-engine relative recall gain **+43.6% [31.5%, 58.4%]**
(0022, defended in E15) — is one of them. This asks whether it survives when the resampling unit is the
APPLICATION: human repos stay singleton clusters, the 40 llm repos collapse into their 10 spec clusters.

Per §16 this is asked of the committed artefact (`multiengine-grouped-260726.json` carries per-repo
counts), not of a fresh engine run: the point estimates cannot move, only the intervals can. What can
fail: H1's lower bound dropping below the preregistered +10%, which would demote the headline claim.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/pool_spec_clustered.py
"""

from __future__ import annotations

import json
import os
import random
import re
import statistics
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
SEED = 20260726
N_BOOT = 4000
H1_PREREGISTERED_FLOOR = 0.10

SPEC = re.compile(r"^vc-(?:claude-code|codex-high|codex|kimi-code)-seeded-v2-(.+)$")


def cluster_of(slug: str) -> str:
    m = SPEC.match(slug)
    return f"spec:{m.group(1)}" if m else slug


def gain(rows: list[dict]) -> tuple[float, float]:
    real = sum(r["real"] for r in rows)
    b = sum(r["bandit_tp"] for r in rows)
    u = sum(r["union_tp"] for r in rows)
    if not real or not b:
        return None, None
    return (u - b) / b, statistics.median((r["union_tp"] - r["bandit_tp"]) / r["real"]
                                          for r in rows if r["real"])


def bootstrap(clusters: dict[str, list[dict]], rng: random.Random):
    names = sorted(clusters)
    rel, med = [], []
    for _ in range(N_BOOT):
        pick = [rng.choice(names) for _ in names]
        rows = [r for c in pick for r in clusters[c]]
        g, m = gain(rows)
        if g is not None:
            rel.append(g)
            med.append(m)
    rel.sort()
    med.sort()
    ci = lambda v: (v[int(0.025 * len(v))], v[int(0.975 * len(v))])
    return ci(rel), ci(med)


def main() -> int:
    art = json.load(open(os.path.join(_HERE, "multiengine-grouped-260726.json"), encoding="utf-8"))
    per = art["per_repo"]

    by_repo = {r["repo"]: [r] for r in per}
    by_app: dict[str, list[dict]] = {}
    for r in per:
        by_app.setdefault(cluster_of(r["repo"]), []).append(r)
    spec_clusters = {k: v for k, v in by_app.items() if k.startswith("spec:")}
    print(f"repositories: {len(by_repo)}   independent applications: {len(by_app)} "
          f"({len(by_app) - len(spec_clusters)} human + {len(spec_clusters)} specs)")
    for k, v in sorted(spec_clusters.items()):
        print(f"  {k:<38} {len(v)} implementations")

    g, m = gain(per)
    print(f"\npoint estimates (unchanged by clustering): relative gain {g:+.1%}, median per-repo {m:+.4f}")
    print(f"published, repo-clustered: {art['relative_gain_ci95']}  (n=63 'independent' units)")

    rng = random.Random(SEED)
    (rlo, rhi), (mlo, mhi) = bootstrap(by_repo, rng)
    print(f"re-derived, repo-clustered: [{rlo:+.1%}, {rhi:+.1%}] — should match published")
    (alo, ahi), (amlo, amhi) = bootstrap(by_app, rng)
    print(f"APPLICATION-clustered      : [{alo:+.1%}, {ahi:+.1%}]  (n={len(by_app)} units)")
    print(f"  median-gain interval     : [{amlo:+.4f}, {amhi:+.4f}] vs published {art['median_gain_ci95']}")

    h1 = alo > H1_PREREGISTERED_FLOOR
    widened = (ahi - alo) / max(rhi - rlo, 1e-9)
    print(f"\ninterval widened {widened:.2f}x by honest clustering")
    print(f"H1 floor (+10%) under application clustering: lower bound {alo:+.1%} — "
          f"{'HOLDS' if h1 else 'FAILS — the headline claim loses its preregistered support'}")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(),
           "question": "does the flagship multi-engine gain survive clustering by independent APPLICATION "
                       "(36 units: 26 human + 10 specs x 4 generators) instead of by repository (63)?",
           "source_artefact": "multiengine-grouped-260726.json (committed per-repo counts; no engine run)",
           "independent_applications": len(by_app),
           "spec_clusters": {k: len(v) for k, v in sorted(spec_clusters.items())},
           "point_relative_gain": round(g, 4),
           "repo_clustered_ci": [round(rlo, 4), round(rhi, 4)],
           "application_clustered_ci": [round(alo, 4), round(ahi, 4)],
           "median_gain_application_ci": [round(amlo, 4), round(amhi, 4)],
           "interval_widening": round(widened, 3),
           "h1_floor": H1_PREREGISTERED_FLOOR, "h1_holds_under_application_clustering": h1,
           "seed": SEED, "n_boot": N_BOOT}
    with open(os.path.join(_HERE, "spec-clustered-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
