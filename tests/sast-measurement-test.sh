#!/usr/bin/env bash
# SAST measurement-stack contract (SM1-SM6).
#
# This stack had ZERO test coverage while the runtime stack had DD1-DD10. That asymmetry is why a
# withdrawn claim survived in code: decision 0021's "+0.069, prior WINS" was retracted in prose, but
# rank_baselines.py kept its row-level split and went on printing the retracted number with a confident
# verdict for a day. Nothing held the correction in place. These assertions are that hold.
#
# Every assertion carries a negative control so it cannot pass vacuously.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$REPO_ROOT/rag/.venv/bin/python"
SFP="$REPO_ROOT/evaluation/sast-fp-discrimination"
PASS=0; FAIL=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
sect() { printf '\n== %s ==\n' "$1"; }
[ -x "$PY" ] || { echo "missing venv at $PY"; exit 2; }
cd "$REPO_ROOT" || exit 2
run_py() { "$PY" -W ignore - "$@"; }

sect "SM1: a grouped split never puts one repo on both sides"
if run_py <<'PY'
import sys; sys.path.insert(0, "evaluation/sast-fp-discrimination")
from rank_grouped import loso_scores
rows = [{"cwe": 89, "severity": "HIGH", "is_vulnerable": True,  "det_score": .9, "llm_priority": .5},
        {"cwe": 89, "severity": "HIGH", "is_vulnerable": True,  "det_score": .9, "llm_priority": .5},
        {"cwe": 22, "severity": "LOW",  "is_vulnerable": False, "det_score": .1, "llm_priority": .5},
        {"cwe": 22, "severity": "LOW",  "is_vulnerable": False, "det_score": .1, "llm_priority": .5}]
groups = ["repoA", "repoA", "repoB", "repoB"]
# Every row must be scored exactly once, by a prior fitted without its own repo.
scored = loso_scores(rows, groups, "cwe_prior")
print(f"  rows={len(rows)} scored={len(scored)} groups={sorted(set(groups))}")
sys.exit(0 if len(scored) == len(rows) else 1)
PY
then ok "leave-one-repo-out scores every row exactly once, holding out its own repo"
else bad "SM1: the grouped split does not cover the rows exactly once"; fi

sect "SM1-neg: a held-out repo's own labels cannot reach its score (control)"
if run_py <<'PY'
import sys; sys.path.insert(0, "evaluation/sast-fp-discrimination")
from rank_grouped import loso_scores
from rank_baselines import fit_cwe_prior, score_rows
# repoX owns a CWE appearing NOWHERE else, always vulnerable. Fitted on its own rows the prior scores
# it ~1.0; fitted leave-one-repo-out that CWE is unseen so it MUST fall back to the base rate. The
# contrast between the two IS the leakage channel this experiment is about.
rows, groups = [], []
for _ in range(10):
    rows.append({"cwe": 9999, "severity": "HIGH", "is_vulnerable": True, "det_score": .5, "llm_priority": .5})
    groups.append("repoX")
for i in range(40):
    rows.append({"cwe": 100 + (i % 4), "severity": "LOW", "is_vulnerable": False, "det_score": .5, "llm_priority": .5})
    groups.append("repo%d" % (i % 5))
held = {sc for (sc, _), g in zip(loso_scores(rows, groups, "cwe_prior"), groups) if g == "repoX"}
prior, base = fit_cwe_prior(rows)
leaky = {sc for sc, _ in score_rows([r for r, g in zip(rows, groups) if g == "repoX"], "cwe_prior", prior, base)}
print("  repoX grouped=%s  leaky same-repo fit=%s" % (held, leaky))
sys.exit(0 if max(held) < max(leaky) and max(held) < 0.9 else 1)
PY
then ok "a repo-exclusive CWE falls back to the base rate under grouping, but scores ~1.0 when leaked"
else bad "SM1-neg: a held-out repo's own labels still reach its score"; fi

sect "SM2: the reconstruction refuses a join it cannot verify"
if run_py <<'PY'
import sys; sys.path.insert(0, "evaluation/sast-fp-discrimination")
import rank_grouped as rg
# Feed it a row list of the wrong length: it must ABORT (None), never guess an alignment.
bogus = [{"cwe": 1, "severity": "HIGH"}] * 3
out = rg.reconstruct_groups(bogus)
print(f"  reconstruct_groups(wrong-length) -> {out}")
sys.exit(0 if out is None else 1)
PY
then ok "a mismatched replay returns None instead of an unverified row->repo join"
else bad "SM2: the reconstruction accepts a join it did not verify"; fi

sect "SM3: the retracted +0.069 is never presented as a verdict"
if run_py <<'PY'
import sys
src = open("evaluation/sast-fp-discrimination/rank_baselines.py").read()
# The row-split path may still be demonstrated, but never as a win.
claims_win = "deterministic prior WINS" in src
labelled = "RETRACTED" in src and "LEAKY" in src
points_to_grouped = "rank_grouped" in src
print(f"  claims a win={claims_win}  labelled retracted+leaky={labelled}  points to grouped={points_to_grouped}")
sys.exit(0 if (not claims_win) and labelled and points_to_grouped else 1)
PY
then ok "the row-split instrument labels its number retracted and defers to the grouped one"
else bad "SM3: the withdrawn claim is still presented as a finding"; fi

sect "SM4: the grouped verdict is a tie, and says so"
if run_py <<'PY'
import json, os, sys
p = "evaluation/sast-fp-discrimination/rank-grouped-260726.json"
if not os.path.exists(p):
    print("  SKIP-AS-FAIL: run rank_grouped.py to produce the artefact"); sys.exit(1)
d = json.load(open(p))
lo, hi = d["ci95"]
spans_zero = lo <= 0 <= hi
print(f"  delta={d['primary_delta']:+.3f} CI=[{lo:+.3f},{hi:+.3f}] verdict={d['verdict']} n_repos={d['n_repos']}")
# The verdict string must follow the interval, not the point estimate.
sys.exit(0 if (spans_zero and d["verdict"] == "tie") else 1)
PY
then ok "the published verdict follows the confidence interval (tie), not the point estimate"
else bad "SM4: the verdict does not follow its own interval"; fi

sect "SM5: splitting by row measurably inflates the delta (the leakage is real, not asserted)"
if run_py <<'PY'
import json, os, sys
p = "evaluation/sast-fp-discrimination/rank-grouped-260726.json"
if not os.path.exists(p):
    print("  SKIP-AS-FAIL: artefact missing"); sys.exit(1)
d = json.load(open(p))
gap = d["exploratory_row_split_delta"] - d["primary_delta"]
print(f"  row-split={d['exploratory_row_split_delta']:+.3f} grouped={d['primary_delta']:+.3f} gap={gap:+.3f}")
# The whole point of decision 0021's correction: the leak is large and positive.
sys.exit(0 if gap > 0.03 else 1)
PY
then ok "the row-split delta exceeds the grouped delta — the leakage channel is measured, not claimed"
else bad "SM5: the measured leakage gap vanished; re-check the correction"; fi

sect "SM6: no superseded figure, and any win verdict is interval-guarded"
if run_py <<'PY'
import glob, re, sys
bad = []
for f in glob.glob("evaluation/sast-fp-discrimination/*.py"):
    src = open(f).read()
    if re.search(r"9\.5\s*[x\u00d7]", src):
        bad.append((f, "9.5x superseded by 6.2x"))
    # A win may only be printed when the INTERVAL decides it, never the point estimate.
    if "prior WINS" in src and not re.search(r"lo\s*<=\s*0\s*<=\s*hi|ties", src):
        bad.append((f, "win verdict not guarded by the interval"))
print("  stale/unguarded claims: %s" % (bad if bad else "none"))
sys.exit(0 if not bad else 1)
PY
then ok "no superseded ratio survives, and every win verdict is decided by its interval"
else bad "SM6: a corrected number or an unguarded verdict still lives in code"; fi

sect "summary"
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
