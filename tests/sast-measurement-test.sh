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

sect "SM4: both estimands are published, and the primary is the deployment-realistic one"
if run_py <<'PY'
import json, os, sys, time
p = "evaluation/sast-fp-discrimination/rank-grouped-260726.json"
src = "evaluation/sast-fp-discrimination/rank_grouped.py"
if not os.path.exists(p):
    print("  SKIP-AS-FAIL: run rank_grouped.py"); sys.exit(1)
# Freshness: an artefact older than the instrument that produced it is stale, and every assertion
# below would then be checking a number no current code produces.
import subprocess
def _committed_at(path):
    """Commit time of a path's last change. Filesystem mtime is useless here: git sets every file's
    mtime to CHECKOUT time, so an mtime comparison is arbitrary in a fresh clone — which is exactly
    what CI is. This was caught the moment the branch was merged and the suite re-run on main."""
    try:
        out = subprocess.run(["git", "log", "-1", "--format=%ct", "--", path],
                             capture_output=True, text=True, timeout=20).stdout.strip()
        return int(out) if out else 0
    except Exception:
        return 0
stale = _committed_at(p) < _committed_at(src)
d = json.load(open(p))
# A review found the original SM4 tautological: it recomputed lo<=0<=hi and compared it to a verdict
# the code defines as exactly that expression. These are empirical claims instead — they fail if the
# data changes, if an estimand is silently dropped, or if the primary is switched.
has_both = "macro" in d and "micro" in d
primary_ok = d.get("primary_estimand") == "macro-per-repo"
macro_wins = d["macro"]["ci95"][0] > 0
micro_ties = d["micro"]["ci95"][0] <= 0 <= d["micro"]["ci95"][1]
shape_ok = d["n_rows"] == 1764 and d["n_repos"] == 61
print("  stale=%s both=%s primary=%s macro_wins=%s micro_ties=%s shape=%s"
      % (stale, has_both, d.get("primary_estimand"), macro_wins, micro_ties, shape_ok))
sys.exit(0 if (not stale and has_both and primary_ok and macro_wins and micro_ties and shape_ok) else 1)
PY
then ok "macro (per-app) is primary and wins; micro is published, ties, and is not headlined"
else bad "SM4: an estimand was dropped, the primary changed, or the artefact is stale"; fi

sect "SM5: the leakage figure is the MATCHED one, not the confounded subtraction"
if run_py <<'PY'
import json, os, sys
p = "evaluation/sast-fp-discrimination/rank-grouped-260726.json"
if not os.path.exists(p):
    print("  SKIP-AS-FAIL: artefact missing"); sys.exit(1)
d = json.load(open(p))
g = d["matched_grouping_effect"]
# The published +0.057 confounded grouping with train size and eval set. The matched estimate is
# materially smaller; if this ever climbs back toward 0.057 the confound has returned.
print("  matched grouping effect=%+.4f (must be >0 and well below the retracted 0.057)" % g)
sys.exit(0 if 0 < g < 0.04 else 1)
PY
then ok "leakage is reported from a matched design and stays far below the confounded +0.057"
else bad "SM5: the leakage figure is missing or the confound returned"; fi

sect "SM6: no superseded figure, and any win verdict is interval-guarded"
if run_py <<'PY'
import glob, re, sys
bad = []
for f in glob.glob("evaluation/sast-fp-discrimination/*.py"):
    src = open(f).read()
    if re.search(r"9\.5\s*[x\u00d7]", src):
        bad.append((f, "9.5x superseded by 6.2x"))
    # A win may only be printed when the INTERVAL decides it, never the point estimate.
    # Line-scoped: a review found a file-wide search exempted any file whose docstring merely used
    # the word "ties". The verdict string must sit on a line that also tests the interval.
    for line in src.splitlines():
        if "prior WINS" not in line:
            continue
        guarded = "<= 0 <=" in line                      # a live verdict decided by the interval
        historical = any(w in line.lower() for w in
                         ("withdrew", "retract", "first published", "superseded"))
        if not (guarded or historical):
            bad.append((f, "win verdict neither interval-guarded nor marked as history"))
print("  stale/unguarded claims: %s" % (bad if bad else "none"))
sys.exit(0 if not bad else 1)
PY
then ok "no superseded ratio survives, and every win verdict is decided by its interval"
else bad "SM6: a corrected number or an unguarded verdict still lives in code"; fi

sect "SM7: the multi-engine gain is published with an interval and its portfolio caveat"
if run_py <<'PY'
import json, os, sys
p = "evaluation/sast-fp-discrimination/multiengine-grouped-260726.json"
if not os.path.exists(p):
    print("  SKIP-AS-FAIL: run run_multiengine_grouped.py"); sys.exit(1)
d = json.load(open(p))
# The totals must still reproduce decision 0022, or the number is a different measurement.
t = d["totals"]
# Findings counts are pinned too: precision is tp/findings, so a ruleset change adding findings that
# match no ground truth moves the precision clause while leaving every TP untouched.
expect = {"repos": 63, "real": 1790, "bandit_tp": 234, "semgrep_tp": 212, "union_tp": 336,
          "bandit_findings": 1764, "semgrep_findings": 675, "union_findings": 2439}
drift = any(t.get(k) != v for k, v in expect.items())
lo, hi = d["relative_gain_ci95"]
plo, phi = d["precision_delta_ci95"]
# `lo > 0` would be VACUOUS: a union only ever adds matches, so union_tp >= bandit_tp in every repo and
# no resample can produce a negative gain (a review measured 0 of 2000; minimum +0.234). The
# preregistration committed to +10% as the threshold that could actually fail -- assert THAT.
# `plo <= 0 <= phi` is not vacuous: a deduplicated denominator makes it fail.
import subprocess
def _committed_at(path):
    """Commit time of a path's last change. Filesystem mtime is useless here: git sets every file's
    mtime to CHECKOUT time, so an mtime comparison is arbitrary in a fresh clone — which is exactly
    what CI is. This was caught the moment the branch was merged and the suite re-run on main."""
    try:
        out = subprocess.run(["git", "log", "-1", "--format=%ct", "--", path],
                             capture_output=True, text=True, timeout=20).stdout.strip()
        return int(out) if out else 0
    except Exception:
        return 0
fresh = _committed_at(p) >= _committed_at(
    "evaluation/sast-fp-discrimination/run_multiengine_grouped.py")
zero_gain_published = d.get("repos_with_zero_gain", 0) > 0
print("  drift=%s fresh=%s gain_ci=[%.3f,%.3f] prec_ci=[%.4f,%.4f] zero_gain_repos=%s"
      % (drift, fresh, lo, hi, plo, phi, d.get("repos_with_zero_gain")))
sys.exit(0 if (not drift and fresh and lo > 0.10 and plo <= 0 <= phi and zero_gain_published) else 1)
PY
then ok "recall gain carries a CI excluding 0, precision delta spans 0, and the no-gain repo count ships"
else bad "SM7: the multi-engine claim drifted or lost its interval/caveat"; fi

sect "SM8: class attribution distinguishes finding THE vuln from flagging the file"
if run_py <<'PY'
import sys; sys.path.insert(0, "evaluation/sast-fp-discrimination")
from run_generative import names_ground_truth_class as named
# This criterion withdrew E17's mechanism claim, so it is load-bearing and must not drift.
# The decisive property: identical prose must score differently depending on the GT class.
prose = "Register 409 leaks email existence"
discriminates = named(prose, {200}) and not named(prose, {307})
# a real match and a real non-match
hit = named("IDOR: no ownership check on note_id", {639})
miss = not named("pickle.loads RCE on cookie", {639})
print("  discriminates_by_class=%s true_match=%s true_nonmatch=%s" % (discriminates, hit, miss))
sys.exit(0 if (discriminates and hit and miss) else 1)
PY
then ok "the same prose scores differently by ground-truth class — attribution is real, not a keyword hit"
else bad "SM8: class attribution collapsed into a generic keyword match"; fi

sect "SM9: the mechanism control arm is published, and mess alone does not trigger flags"
if run_py <<'PY'
import json, os, sys
p = "evaluation/sast-fp-discrimination/messy-control-260726.json"
if not os.path.exists(p):
    print("  SKIP-AS-FAIL: run run_messy_control.py"); sys.exit(1)
d = json.load(open(p))
# E18 is what lets decision 0027 claim DETECTION rather than "reacts to messy code". The claim needs
# arm B to stay well below arm A (0.167). If this ever climbs to meet it, the mechanism claim dies.
rate = d["flag_rate"]
n_ok = d["n"] >= 60
arm = d.get("arm") == "messy-no-absence"
print("  arm=%s n=%s flag_rate=%.3f (arm A was 0.167; clean was 0.025)" % (d.get("arm"), d["n"], rate))
# Must be materially below arm A. 0.10 is the midpoint between the clean rate and arm A.
sys.exit(0 if (arm and n_ok and rate < 0.10) else 1)
PY
then ok "defective-but-no-absent-control files stay near the clean rate, so mess is not the driver"
else bad "SM9: the mechanism control arm is missing or its rate rose to meet arm A"; fi

sect "SM10: the anonymisation transfer result is published with its paired interval"
if run_py <<'PY'
import json, os, sys
p = "evaluation/sast-fp-discrimination/mutation-transfer-260726.json"
if not os.path.exists(p):
    print("  SKIP-AS-FAIL: run run_mutation_transfer.py"); sys.exit(1)
d = json.load(open(p))
# This is what narrows 0027 from "capability and memorisation are inseparable" to a much smaller
# bound. If mutation ever starts collapsing detection, that narrowing is invalid and must fail here.
n = d["n_pairs"]; o = d["original_flagged"]; m = d["mutated_flagged"]
drop = (o - m) / n
paired = d["lost_by_mutation"] + d["gained_by_mutation"]
print("  n=%d original=%d mutated=%d drop=%+.3f discordant=%d p=%s"
      % (n, o, m, drop, paired, d["mcnemar_p_one_sided"]))
# A >10-point drop would mean surface memorisation was doing the work after all.
sys.exit(0 if (n >= 40 and drop < 0.10 and d["mcnemar_p_one_sided"] >= 0.05) else 1)
PY
then ok "anonymised source still detects at the same rate — surface memorisation stays excluded"
else bad "SM10: mutation now collapses detection; 0027's narrowed contamination bound is invalid"; fi

sect "SM11: the file-role control is published WITH its fragility"
if run_py <<'PY'
import json, os, sys
p = "evaluation/sast-fp-discrimination/role-control-260726.json"
if not os.path.exists(p):
    print("  SKIP-AS-FAIL: run run_role_control.py"); sys.exit(1)
d = json.load(open(p))
# This closes E18's named confound. It is a MARGINAL result (one extra flag flips it), so the guard
# checks the whole population was used and the effect size held, not the p-value alone.
a = d["arm_a_prime"]; rate_c = d["flag_rate"]
ratio = a["rate"] / rate_c if rate_c else float("inf")
whole_pop = d["n"] >= 40      # every qualifying handler file in the corpus
print("  armA=%.3f armC=%.3f ratio=%.1fx n_C=%d p=%s"
      % (a["rate"], rate_c, ratio, d["n"], d["fisher_p_one_sided"]))
sys.exit(0 if (whole_pop and ratio >= 2.0 and d["fisher_p_one_sided"] < 0.05) else 1)
PY
then ok "handlers with an absent control still flag multiples more often than handlers without"
else bad "SM11: the role control weakened; 0027 would collapse to 'recognises endpoint code'"; fi

sect "SM13: the prose classifier — single point of failure for the whole generative chain"
if run_py <<'PY'
import sys; sys.path.insert(0, "evaluation/sast-fp-discrimination")
from run_generative import classify_prose as c
# A Stage-8 review noted that NO test exercised classify_prose, though E17-E21 all score through it.
# Each case below is a failure mode that was demonstrated on real model output, not invented.
cases = [
    # reassurance must beat inherent terms (this exact prose was E17's only clean-arm flag)
    ("visible_employees_for as sole entry point - correct IDOR defense", "clean"),
    ("Access control looks properly implemented here.", "clean"),
    # presence-class defects must never count as an absent control
    ("AES-CBC unauthenticated + ephemeral KEY.", "clean"),
    ("SQL injection on line 7.", "clean"),
    # code the model QUOTES must not supply the absence word
    ("Call after login middleware or add `if not user.is_authenticated`", "clean"),
    ('flash("Not authorized", "error") is used here', "clean"),
    # real absence findings must still fire, including across a sentence break
    ("IDOR: no ownership check on note_id", "flagged"),
    ("Authz hole. No property scope.", "flagged"),
    ("Role check missing on this endpoint.", "flagged"),
    ("Login lacks rate limiting and lockout.", "flagged"),
    ("No authorization check on this endpoint.", "flagged"),
    ("What need? State task.", "non-answer"),
]
bad = [(t, c(t), e) for t, e in cases if c(t) != e]
print("  %d/%d cases correct" % (len(cases) - len(bad), len(cases)))
for t, got, exp in bad: print("    BAD got=%s exp=%s | %s" % (got, exp, t[:50]))
sys.exit(0 if not bad else 1)
PY
then ok "every demonstrated classifier failure mode stays fixed (reassurance, presence-class, quoted code)"
else bad "SM13: a classifier failure mode regressed — every generative result scores through this"; fi

sect "SM14: the instrument's measured instability is on record"
if run_py <<'PY'
import json, os, sys
p = "evaluation/sast-fp-discrimination/determinism-260726.json"
if not os.path.exists(p):
    print("  SKIP-AS-FAIL: determinism artefact missing"); sys.exit(1)
d = json.load(open(p))
# E22 measured 36% verdict flips at temperature 0. Two experiments were withdrawn because they had
# assumed determinism. This keeps the number visible so no future design quietly assumes it again.
rate = d["disagreements"] / d["n"]
print("  n=%d disagreements=%d (%.0f%%) identical_prose=%d/%d"
      % (d["n"], d["disagreements"], rate * 100, d["identical_prose"], d["n"]))
# The artefact must exist and record a NON-zero instability; if it ever reads zero, re-measure before
# trusting it, because 0/14 identical prose says the model is not deterministic.
import glob
# E29 re-measured on a larger sample spanning both arms; the pooled figure is what is cited.
v2 = "evaluation/sast-fp-discrimination/determinism-v2-260726.json"
pooled_n, pooled_d = d["n"], d["disagreements"]
if os.path.exists(v2):
    e = json.load(open(v2)); pooled_n += e["n"]; pooled_d += e["disagreements"]
    print("  pooled: %d/%d = %.3f across both determinism runs" % (pooled_d, pooled_n, pooled_d/pooled_n))
sys.exit(0 if (pooled_n >= 30 and pooled_d > 0) else 1)
PY
then ok "instrument instability is measured and published, not assumed away"
else bad "SM14: the determinism measurement is missing or claims perfect stability"; fi

sect "SM15: the rebuilt controls measure both arms fresh (no reused verdicts)"
if run_py <<'PY'
import json, os, sys
ok = True
# E19 and E20 were withdrawn for reusing one arm's verdicts under a 36%-unstable instrument. Their
# replacements must record that both arms were measured fresh, and must still show the effect.
p1 = "evaluation/sast-fp-discrimination/memorisation-v2-260726.json"
p2 = "evaluation/sast-fp-discrimination/role-control-v2-260726.json"
for p in (p1, p2):
    if not os.path.exists(p):
        print("  SKIP-AS-FAIL: missing %s" % p); sys.exit(1)
a = json.load(open(p1)); b = json.load(open(p2))
# memorisation: anonymisation must NOT collapse detection (lower bound above a 5-point drop)
mem_ok = a["ci95"][0] > -0.05
# file role: the interval on the difference must exclude zero
role_ok = b["ci95"][0] > 0 and b["fisher_p_one_sided"] < 0.05
fresh = "fresh" in (a.get("design_note", "") + b.get("design", "")).lower()
print("  memorisation CI=%s ok=%s | role CI=%s p=%s ok=%s | fresh-design recorded=%s"
      % (a["ci95"], mem_ok, b["ci95"], b["fisher_p_one_sided"], role_ok, fresh))
sys.exit(0 if (mem_ok and role_ok and fresh) else 1)
PY
then ok "both rebuilt controls hold, and both record measuring their arms fresh"
else bad "SM15: a rebuilt control weakened or reverted to reusing verdicts"; fi

sect "SM16: the file-role conclusion replicates across independent runs"
if run_py <<'PY'
import json, os, sys
a = "evaluation/sast-fp-discrimination/role-control-v2-260726.json"
b = "evaluation/sast-fp-discrimination/role-control-v3-260726.json"
for p in (a, b):
    if not os.path.exists(p):
        print("  SKIP-AS-FAIL: missing %s" % p); sys.exit(1)
A, B = json.load(open(a)), json.load(open(b))
# The instrument flips 36% of individual verdicts (E22). What must hold is that the aggregate
# DIFFERENCE is stable across runs -- that is the assumption every experiment here rests on.
dA, dB = A["difference"], B["difference"]
drift = abs(dA - dB)
both_sig = A["fisher_p_one_sided"] < 0.05 and B["fisher_p_one_sided"] < 0.05
print("  E24 diff=%+.3f (p=%s) | E28 diff=%+.3f (p=%s) | drift=%.4f"
      % (dA, A["fisher_p_one_sided"], dB, B["fisher_p_one_sided"], drift))
# Two independent runs must agree in direction, both significant, and not drift wildly.
sys.exit(0 if (both_sig and dA > 0 and dB > 0 and drift < 0.08) else 1)
PY
then ok "two independent runs agree: labels churn, the aggregate difference does not"
else bad "SM16: the file-role conclusion did not replicate across runs"; fi

sect "SM17: no guard is reading a stale artefact"
if run_py <<'PY'
import os, glob, sys
# SM5, SM9-SM11 and SM14-SM16 assert over committed artefacts. An artefact older than the instrument
# that produced it means those guards are checking a number no current code emits — the same defect a
# review found in SM7, fixed there and left everywhere else. One check covers them all.
pairs = [("generative-260726.json", "run_generative.py"),
         ("messy-control-260726.json", "run_messy_control.py"),
         ("mutation-transfer-260726.json", "run_mutation_transfer.py"),
         ("role-control-v2-260726.json", "run_role_control.py"),
         ("role-control-v3-260726.json", "run_role_control.py"),
         ("memorisation-v2-260726.json", "run_memorisation_v2.py"),
         ("multiengine-grouped-260726.json", "run_multiengine_grouped.py"),
         ("rank-grouped-260726.json", "rank_grouped.py")]
base = "evaluation/sast-fp-discrimination/"
# Artefacts whose INSTRUMENT was edited after the run (classifier corrections, storage caps). Their
# live results stand -- computed by the code as it was at run time -- but regenerating them needs fresh
# model calls. Documented here rather than hidden; regeneration is recorded as owed work.
import subprocess
def _committed_at(path):
    """Commit time of a path's last change. Filesystem mtime is useless here: git sets every file's
    mtime to CHECKOUT time, so an mtime comparison is arbitrary in a fresh clone — which is exactly
    what CI is. This was caught the moment the branch was merged and the suite re-run on main."""
    try:
        out = subprocess.run(["git", "log", "-1", "--format=%ct", "--", path],
                             capture_output=True, text=True, timeout=20).stdout.strip()
        return int(out) if out else 0
    except Exception:
        return 0
# Two entries cleared 2026-07-26 by E35 regenerating the headline artefact with the current instrument.
# Down to two, and neither carries a live conclusion: both are superseded records kept for history.
# Every artefact behind a standing claim is now re-verifiable (E35 and E36 regenerated the last two).
KNOWN_STALE = {"mutation-transfer-260726.json": "E19, withdrawn; superseded by E23",
               "role-control-v2-260726.json": "E24; superseded by E28 (role-control-v3)"}
def _still_re_derives(path):
    """True if every stored verdict in this artefact re-derives from its own prose under today's code.

    A timestamp says an artefact MIGHT be stale. Re-derivation says whether it actually is. When a change
    to the instrument leaves every stored value reproducible — adding a helper, fixing how a control is
    read, anything that does not touch the classifier — the artefact is not stale in any sense that
    matters, and failing on the timestamp would train people to add allowlist entries for non-problems.
    The weaker check defers to the stronger one; it does not override it, because an artefact that fails
    re-derivation is caught by SM19 regardless of what any timestamp says.
    """
    sys.path.insert(0, "evaluation/sast-fp-discrimination")
    try:
        import json as _json
        from rescore_artefacts import drifted, truncated, _rows
        doc = _json.load(open(path))
        if not _rows(doc) or truncated(doc):
            return False                      # nothing to verify, or unverifiable — timestamp still rules
        return not drifted(doc)
    except Exception:
        return False

stale, reproducible = [], []
for art, src in pairs:
    a, b = base + art, base + src
    if not (os.path.exists(a) and os.path.exists(b)):
        continue
    if _committed_at(a) < _committed_at(b) and art not in KNOWN_STALE:
        if _still_re_derives(a):
            reproducible.append(art)          # older than its instrument, but provably unaffected by it
        else:
            stale.append(art)
print("  checked=%d  undocumented-stale=%s  known-stale=%d (documented)  "
      "newer-instrument-but-still-re-derives=%s"
      % (len(pairs), stale or "none", sum(1 for a, _ in pairs if a in KNOWN_STALE),
         reproducible or "none"))
sys.exit(0 if not stale else 1)
PY
then ok "every committed artefact is at least as new as the instrument that produced it"
else bad "SM17: a guard is asserting over an artefact older than its own instrument"; fi

sect "SM18: the authored-unseen result keeps its class breakdown, not just a rate"
if run_py <<'PY'
import json, os, sys
p = "evaluation/sast-fp-discrimination/authored-unseen-v2-260726.json"
if not os.path.exists(p):
    print("  SKIP-AS-FAIL: run the authored-unseen v2 experiment"); sys.exit(1)
d = json.load(open(p))
# The aggregate rate averages over classes the model handles and classes it misses entirely. Decision
# 0027 was narrowed on that breakdown, so the per-class detail must survive in the artefact.
rows = d["rows"]
vuln = [r for r in rows if r["truth"] == "vulnerable"]
has_why = all(r.get("why") for r in vuln)          # the class each defect belongs to
ownership = [r for r in vuln if "639" in r.get("why", "") or "306" in r.get("why", "")]
own_hits = sum(1 for r in ownership if r["verdict"] == "flagged")
print("  n_pairs=%s sensitivity=%s p=%s | ownership+authn %d/%d"
      % (d["n_pairs"], d["sensitivity"], d["fisher_p_one_sided"], own_hits, len(ownership)))
# Guard the two things 0027 now rests on: significance, and the strong classes staying strong.
sys.exit(0 if (has_why and d["fisher_p_one_sided"] < 0.05 and own_hits >= len(ownership) - 1) else 1)
PY
then ok "authored-unseen stays significant and keeps per-defect class labels for the breakdown"
else bad "SM18: the authored-unseen result lost significance or its class detail"; fi

sect "SM19: every stored verdict re-derives from its own stored prose"
if run_py <<'PY'
import glob, json, sys
sys.path.insert(0, "evaluation/sast-fp-discrimination")
import run_generative as rg
from rescore_artefacts import drifted, truncated, _rows
# A verdict is not raw data — the prose is. The verdict is the classifier's reading of it, so every
# classifier fix silently ages every stored verdict. Eleven rows across seven artefacts had drifted
# away from their own data before this guard existed, and it had gone unnoticed because the freshness
# guard (SM17) compares COMMIT TIMES: an artefact committed alongside its instrument passes while still
# disagreeing with it. Freshness is not reproducibility, and only this check tests the latter.
bad = {}
checked = 0
unverifiable = []
for path in sorted(glob.glob("evaluation/sast-fp-discrimination/*.json")):
    doc = json.load(open(path))
    rows = _rows(doc)
    if not rows:
        continue
    if truncated(doc):
        # Reported, never silently skipped: these artefacts are not "fine", they are unverifiable,
        # and a guard that printed nothing about them would let that distinction quietly disappear.
        unverifiable.append(path.split("/")[-1])
        continue
    checked += len(rows)
    d = drifted(doc)
    if d:
        bad[path.split("/")[-1]] = [(r.get("file"), r["verdict"], now) for r, now in d]
print("  rows re-derived=%d  disagreeing=%d  unverifiable(truncated prose)=%s"
      % (checked, sum(len(v) for v in bad.values()), unverifiable or "none"))
for k, v in bad.items():
    print("    %s: %s" % (k, v))
# Negative control: the check must actually notice a planted disagreement, or it passes vacuously.
planted = {"rows": [{"file": "x.py", "verdict": "flagged",
                     "response": "Looks fine. No issues found."}]}
caught = len(drifted(planted)) == 1
print("  planted-disagreement caught=%s" % caught)
sys.exit(0 if not bad and caught and checked > 300 else 1)
PY
then ok "no stored verdict disagrees with re-reading its own prose, and a planted disagreement is caught"
else bad "SM19: an artefact's stored verdicts no longer match what the classifier reads from its prose"; fi

sect "SM20: no class-attribution vocabulary is dead, and each is specific to prose claiming a defect"
if run_py <<'PY'
import glob, json, re, sys
sys.path.insert(0, "evaluation/sast-fp-discrimination")
import run_generative as rg
# CWE-306's vocabulary demanded verbose phrasing ("no authentication", "missing authentication") that
# the model never writes — it writes "no auth", "No admin gate". It matched 0 of 440 real responses, so
# every CWE-306 file was uncreditable by construction while looking like a measured miss. A vocabulary
# that cannot fire is not a strict measure, it is a broken one.
prose = []
for path in glob.glob("evaluation/sast-fp-discrimination/*.json"):
    doc = json.load(open(path))
    for value in doc.values():
        if isinstance(value, list):
            prose += [r["response"] for r in value
                      if isinstance(r, dict) and isinstance(r.get("response"), str) and len(r["response"]) > 40]
flagged = [t for t in prose if rg.classify_prose(t) == "flagged"]
clean = [t for t in prose if rg.classify_prose(t) == "clean"]
dead, weak = [], []
for cwe, rx in sorted(rg._CLASS_VOCAB.items()):
    f = sum(1 for t in flagged if rg.names_class_absence(t, cwe))
    c = sum(1 for t in clean if rg.names_class_absence(t, cwe))
    print("  CWE-%-4s flagged %2d/%d  clean %2d/%d" % (cwe, f, len(flagged), c, len(clean)))
    if f == 0:
        dead.append(cwe)
    # Specificity floor: a class term appearing as often in prose concluding "fine" as in prose claiming
    # a defect measures the regex, not the model. CWE-200 fails this and is excluded from attribution.
    elif c / max(len(clean), 1) > 0.5 * (f / len(flagged)):
        weak.append(cwe)
print("  dead=%s  insufficiently-specific=%s" % (dead, weak))
sys.exit(0 if not dead and not weak and len(prose) > 300 else 1)
PY
then ok "every class vocabulary fires on real prose and fires far more on defect claims than on all-clear prose"
else bad "SM20: a class-attribution vocabulary is dead or fires as readily on prose claiming nothing is wrong"; fi

sect "SM21: the class-asymmetry estimate never acquires a p-value it was not powered for"
if run_py <<'PY'
import json, os, sys
p = "evaluation/sast-fp-discrimination/class-asymmetry-260726.json"
if not os.path.exists(p):
    print("  SKIP-AS-FAIL: run the class-asymmetry experiment"); sys.exit(1)
d = json.load(open(p))
# This result exists because the significance test of the same question was cancelled at 43% power. An
# estimate and a test look identical once someone quotes the point value, and the difference is the whole
# reason this run was allowed to happen. A p-value appearing here later would erase that distinction
# silently, so its ABSENCE is pinned as part of the result.
has_p = any("p_value" in k or k.endswith("_p") or "fisher" in k or "mcnemar" in k for k in d)
lo, hi = d["difference_ci95"]
# The interval must still be published whole. Reporting +0.094 without [0.000, 0.189] would turn a
# result whose lower bound touches zero into one that reads as established.
interval_ok = lo <= d["difference"] <= hi
declares = "estimation" in d.get("preregistered_as", "").lower()
# The estimate is a floor because redaction can only delete text; that framing must survive too.
floor_noted = "floor" in d.get("scoring_note", "").lower()
print("  p-value absent=%s  interval=[%s,%s] consistent=%s  declared-estimation=%s  floor-noted=%s"
      % (not has_p, lo, hi, interval_ok, declares, floor_noted))
sys.exit(0 if (not has_p and interval_ok and declares and floor_noted) else 1)
PY
then ok "the estimate keeps its interval, declares itself an estimate, and carries no p-value"
else bad "SM21: the class-asymmetry estimate has gained a p-value or lost its interval"; fi

sect "SM22: the propensity result keeps its per-file spread, not just a mean"
if run_py <<'PY'
import json, os, sys
p = "evaluation/sast-fp-discrimination/attribution-propensity-260726.json"
if not os.path.exists(p):
    print("  SKIP-AS-FAIL: run the attribution-propensity experiment"); sys.exit(1)
d = json.load(open(p))
rows = d["rows"]
# The mean alone reads as a modest detector. The spread is the actual finding: no file is reliably
# reported, which is what forces repeated reading and puts a k into every cost figure. A future edit
# that keeps `ever_mean` and drops the per-file numbers would erase the result while looking tidy.
per_file = [r["propensity"] for r in rows]
has_spread = len(set(per_file)) > 1
top = max(per_file)
groups = {r["group"] for r in rows}
# The central claim: nothing reached reliability. If a rerun ever produces a file at 1.0, this guard
# should fail and the conclusion be rewritten rather than quietly retained.
print("  n=%d groups=%s max_propensity=%.3f distinct_values=%d"
      % (len(rows), sorted(groups), top, len(set(per_file))))
sys.exit(0 if (has_spread and top < 1.0 and groups == {"ever", "never"}
               and all("hits" in r and "k" in r for r in rows)) else 1)
PY
then ok "per-file propensities are retained, both groups present, and no file reached reliability"
else bad "SM22: the propensity result lost its per-file spread, or a file now reads as reliably detected"; fi

sect "SM23: the clean-control arm has never produced a flag, in any run"
if run_py <<'PY'
import glob, json, sys
# Decision 0027's specificity claim is now stated as a FLOOR, not a low rate: across every discrimination
# run this lab has done, no file with zero ground-truth vulnerabilities has ever been flagged. That is the
# half of the primary claim carrying "it is not flagging indiscriminately", and it is asserted over every
# artefact at once rather than one number in one file, because a floor is only a floor if nothing breaches
# it anywhere.
CLEAN_ARMS = {"negative", "clean", "C_handlers_without_absence"}
total, flagged, where = 0, 0, []
for path in sorted(glob.glob("evaluation/sast-fp-discrimination/*.json")):
    doc = json.load(open(path))
    for value in doc.values():
        if not isinstance(value, list):
            continue
        for r in value:
            if not isinstance(r, dict) or r.get("arm") not in CLEAN_ARMS:
                continue
            # role-control's C arm is "handlers without an absence-class defect" — not defect-free code,
            # so it is a different control and is counted separately rather than folded in.
            if r["arm"] == "C_handlers_without_absence":
                continue
            total += 1
            if r.get("verdict") == "flagged":
                flagged += 1
                where.append((path.split("/")[-1], r.get("file")))
print("  clean-control rows across all artefacts=%d  flagged=%d" % (total, flagged))
for w in where:
    print("    BREACH: %s %s" % w)
# Negative control: the check must be looking at real rows, not an empty set it can trivially pass.
print("  guard is non-vacuous (rows found)=%s" % (total > 50))
sys.exit(0 if flagged == 0 and total > 50 else 1)
PY
then ok "no clean-control file has ever been flagged, across every committed discrimination run"
else bad "SM23: the specificity floor has been breached, or the guard found no rows to check"; fi

sect "summary"
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
