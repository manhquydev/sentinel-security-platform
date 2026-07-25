#!/usr/bin/env bash
# Week-10 pentest-eval oracle contract (invariants EA0-EA6, EA-LEAK, EA9-binding) from
# docs/plans/active/2026-07-25-no-issue-week10-eval-pipeline.md (decision 0018).
#
# All UNIT-level, offline, no live target/gateway: the oracle scores the COMMITTED redacted capture +
# the committed corpora. Every "must hold" claim carries a negative control (a mutated input would
# fail the same assertion) — the journal's "checks that passed because they checked nothing" lesson.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$REPO_ROOT/rag/.venv/bin/python"
EVAL="$REPO_ROOT/evaluation/pentest-eval"
MEASURE="$EVAL/measure.py"

PASS=0; FAIL=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
sect() { printf '\n== %s ==\n' "$1"; }

[ -x "$PY" ] || { echo "missing venv at $PY"; exit 2; }
cd "$REPO_ROOT" || exit 2
run_py() { "$PY" - "$@"; }

# ---------------------------------------------------------------------------
sect "EA2: SYNTHETIC oracle — measure computes the EXACT planted confusion matrix (independent truth)"
# The synthetic corpus is designed to yield TP=3, FP=1, FN=3, TN=2 with one FN per pipeline stage and
# one DEFERRED. This is ground truth by construction (not a self-written baseline), so we assert it.
if run_py <<'PY'
import importlib.util, sys, os
os.chdir(os.environ["REPO_ROOT"]) if os.environ.get("REPO_ROOT") else None
spec=importlib.util.spec_from_file_location("measure","evaluation/pentest-eval/measure.py")
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
r=m.measure()["synthetic"]
c=r["confusion"]
want={"tp":3,"fp":1,"fn":3,"tn":2}
stages=r["fn_stages"]
ok = c==want and stages=={"recon":1,"fuzz":1,"exploit":1} and len(r["deferred"])==1
ok = ok and r["per_cwe"]["89"]=={"tp":1,"fn":2} and r["per_cwe"]["22"]=={"tp":0,"fn":1}
print(f"  synthetic confusion={c} stages={stages} deferred={len(r['deferred'])} per_cwe89={r['per_cwe']['89']}")
sys.exit(0 if ok else 1)
PY
then ok "synthetic confusion matrix + per-stage attribution + per-CWE + deferred exactly match the planted design"
else bad "EA2 synthetic oracle numbers wrong"; fi

sect "EA2-neg: mutating a planted label changes the matrix (the oracle is not a rubber stamp)"
if run_py <<'PY'
import importlib.util, json, sys, tempfile, os, shutil
src="evaluation/pentest-eval"
d=tempfile.mkdtemp()
for f in ("corpus-synthetic.json","corpus-real.json","cwe_map.py","measure.py"):
    shutil.copy(os.path.join(src,f), d)
shutil.copytree(os.path.join(src,"captured"), os.path.join(d,"captured"))
cs=json.load(open(os.path.join(d,"corpus-synthetic.json")))
# flip the first TP's proposal to a non-matching class -> TP should drop to 2
cs["cases"][0]["agent"]["proposal_vuln_class"]="response-anomaly-suspected"
json.dump(cs, open(os.path.join(d,"corpus-synthetic.json"),"w"))
os.environ["PENTEST_EVAL_DIR"]=d
spec=importlib.util.spec_from_file_location("measure",os.path.join(d,"measure.py"))
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
c=m.measure()["synthetic"]["confusion"]
print(f"  mutated synthetic confusion={c}")
sys.exit(0 if c["tp"]==2 else 1)   # one TP became an FN
PY
then ok "a mutated planted label flips TP->FN (negative control holds)"
else bad "EA2-neg: mutation did not change the matrix"; fi

# ---------------------------------------------------------------------------
sect "EA3: FP=0 HARD gate on real BENIGN endpoints (decision 0006) + negative control"
if "$PY" "$MEASURE" >/dev/null 2>&1; then
  ok "measure PASSes: real FP==0 on the committed capture (benign endpoints stayed quiet)"
else
  bad "EA3 measure failed its FP=0 gate on the committed capture"
fi
# negative control: plant a proposal on a benign real endpoint -> FP>0 -> measure must FAIL
if run_py <<'PY'
import importlib.util, json, sys, tempfile, os, shutil
src="evaluation/pentest-eval"; d=tempfile.mkdtemp()
for f in ("corpus-synthetic.json","corpus-real.json","cwe_map.py","measure.py"):
    shutil.copy(os.path.join(src,f), d)
shutil.copytree(os.path.join(src,"captured"), os.path.join(d,"captured"))
# add a bogus proposal on a benign endpoint (/api/Products)
ep=json.load(open(os.path.join(d,"captured","exploit-proposals.json")))
ep["proposals"].append({"endpoint":"GET /api/Products","vuln_class":"response-anomaly-suspected","signal_kinds":["size_drift"],"verdict":"suspected-needs-hitl"})
json.dump(ep, open(os.path.join(d,"captured","exploit-proposals.json"),"w"))
os.environ["PENTEST_EVAL_DIR"]=d
spec=importlib.util.spec_from_file_location("measure",os.path.join(d,"measure.py"))
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
sys.exit(m.main())   # should return 1 (FP>0)
PY
then bad "EA3-neg: a planted benign FP did NOT fail the gate (vacuous!)"
else ok "a planted benign-endpoint proposal fails the FP=0 gate (negative control holds)"; fi

# ---------------------------------------------------------------------------
sect "EA1 + EA1b: fail-closed on absent capture AND on a vacuous (no-benign) corpus"
EMPTY="$(mktemp -d)"
if PENTEST_EVAL_DIR="$EMPTY" "$PY" "$MEASURE" >/dev/null 2>&1; then
  bad "EA1: measure PASSed over an absent corpus/capture (must exit non-zero)"
else
  ok "measure refuses (exit!=0) over an absent corpus/capture directory"
fi
if run_py <<'PY'
import importlib.util, json, sys, tempfile, os, shutil
src="evaluation/pentest-eval"; d=tempfile.mkdtemp()
for f in ("corpus-synthetic.json","corpus-real.json","cwe_map.py","measure.py"): shutil.copy(os.path.join(src,f), d)
shutil.copytree(os.path.join(src,"captured"), os.path.join(d,"captured"))
# strip every benign real endpoint -> FP denominator collapses -> vacuous -> must exit 2
cr=json.load(open(os.path.join(d,"corpus-real.json")))
cr["cases"]=[c for c in cr["cases"] if c.get("real_vuln") or not c.get("observable",True)]
json.dump(cr, open(os.path.join(d,"corpus-real.json"),"w"))
os.environ["PENTEST_EVAL_DIR"]=d
spec=importlib.util.spec_from_file_location("measure",os.path.join(d,"measure.py"))
m=importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(m); m.measure()
except SystemExit as e:
    sys.exit(0 if e.code==2 else 1)
sys.exit(1)
PY
then ok "a corpus with no benign endpoints is refused as vacuous (exit 2) — FP=0 can never be hollow"
else bad "EA1b: a no-benign corpus was NOT refused (vacuous FP risk)"; fi

# ---------------------------------------------------------------------------
sect "EA6: deferred (unobservable) endpoints are excluded from recall/FP, reported in deferred[]"
if run_py <<'PY'
import importlib.util, sys, os
spec=importlib.util.spec_from_file_location("measure","evaluation/pentest-eval/measure.py")
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
real=m.measure()["real"]
deferred_paths={x["path"] for x in real["deferred"]}
# the two deferred real cases must appear, and must NOT inflate tp/fn/fp/tn
ok = {"/rest/user/login","/api/Users"} <= deferred_paths
# real observable = 1 vuln + 4 benign = 5 scored; deferred are extra
scored = sum(real["confusion"].values())
print(f"  deferred={sorted(deferred_paths)} scored_observable={scored}")
sys.exit(0 if ok and scored==5 else 1)
PY
then ok "deferred endpoints are reported separately and never counted as a miss or a hit"
else bad "EA6: deferred handling wrong"; fi

# ---------------------------------------------------------------------------
sect "EA-LEAK: every committed captured/ + corpus byte survives a re-redaction with ZERO PII/secret"
# The capture is real live target-derived output committed to git — re-run the canonical redactors over
# it and assert nothing survives. Negative control: a planted email is caught.
if run_py <<'PY'
import sys, os, glob, json
sys.path.insert(0,".")
from agent import pii, trace
# All committed live/label data EXCEPT narrative-gold.json, whose synthetic bias-trap strings
# ("UNION SELECT", "../../etc/passwd") are INTENTIONAL and would trip redact_persisted by design.
paths = glob.glob("evaluation/pentest-eval/captured/*.json") + [
    "evaluation/pentest-eval/corpus-real.json", "evaluation/pentest-eval/corpus-synthetic.json",
    "evaluation/pentest-eval/judge-calibration.json", "evaluation/pentest-eval/baseline-260725.json"]
leaks=[]
for p in paths:
    raw=open(p,encoding="utf-8").read()
    scrubbed,findings = pii.redact(raw)
    if findings:
        leaks.append((p,[f.cls for f in findings]))
    if trace.redact_persisted(raw) != raw:
        leaks.append((p,"target-raw/secret shape changed under redact_persisted"))
print(f"  scanned {len(paths)} committed files; leaks={leaks}")
sys.exit(0 if not leaks else 1)
PY
then ok "no PII/secret shape survives in any committed captured/ or corpus file"
else bad "EA-LEAK: a committed eval file carries PII/secret shapes"; fi
if run_py <<'PY'
import sys; sys.path.insert(0,".")
from agent import pii, trace
_,f = pii.redact('contact admin@juice-sh.op for details')
# both legs of EA-LEAK must be non-blind: pii.redact fires on an email AND redact_persisted alters
# a planted target-raw/secret shape (else an idempotent no-op would pass the leg silently, M3).
tr = trace.redact_persisted("UNION SELECT password FROM users -- stack trace at com.acme.Db")
sys.exit(0 if (f and tr != "UNION SELECT password FROM users -- stack trace at com.acme.Db") else 1)
PY
then ok "both leak detectors fire (email via pii.redact AND target-raw via redact_persisted) — neither leg is blind"
else bad "EA-LEAK-neg: a leak detector did not fire on planted input"; fi

# ---------------------------------------------------------------------------
sect "EA9-binding: captured/manifest.json binds the corpus hash + the pinned image sha256"
if run_py <<'PY'
import hashlib, json, sys
man=json.load(open("evaluation/pentest-eval/captured/manifest.json"))
corpus=open("evaluation/pentest-eval/corpus-real.json","rb").read()
ok = man.get("corpus_sha256")==hashlib.sha256(corpus).hexdigest()
ok = ok and man.get("image_sha256","").startswith("sha256:e68144")
print(f"  corpus_sha256 match={man.get('corpus_sha256')==hashlib.sha256(corpus).hexdigest()} image={man.get('image_sha256','')[:20]}")
sys.exit(0 if ok else 1)
PY
then ok "manifest binds the exact corpus bytes + the pinned Juice Shop image digest (drift is detectable)"
else bad "EA9-binding: manifest does not bind corpus hash + image sha256"; fi

# ---------------------------------------------------------------------------
sect "summary"
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
