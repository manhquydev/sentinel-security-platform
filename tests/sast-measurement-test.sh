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
stale = os.path.getmtime(p) < os.path.getmtime(src)
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
fresh = os.path.getmtime(p) >= os.path.getmtime(
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
sys.exit(0 if (d["n"] >= 10 and d["disagreements"] > 0) else 1)
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

sect "summary"
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
