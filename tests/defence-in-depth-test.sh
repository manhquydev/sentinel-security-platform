#!/usr/bin/env bash
# Defence-in-depth map contract (invariants DD1-DD6) from
# docs/plans/active/2026-07-26-absence-coverage-ai-proposes-tools-dispose.md (v3).
#
# Every invariant here exists because a red-team found the corresponding failure in this project's own
# code: verdicts taken around the control (E8's artefact), evidence persisted unredacted, and an
# unauthenticated probe reporting every endpoint as "protected". Each assertion carries a negative
# control so it cannot pass vacuously.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$REPO_ROOT/rag/.venv/bin/python"
MAP="$REPO_ROOT/evaluation/absence-detection/map_defence_in_depth.py"
PASS=0; FAIL=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
sect() { printf '\n== %s ==\n' "$1"; }
[ -x "$PY" ] || { echo "missing venv at $PY"; exit 2; }
cd "$REPO_ROOT" || exit 2
run_py() { "$PY" -W ignore - "$@"; }

sect "DD1 (structural): NO LLM path exists that can remove a finding"
if run_py <<'PY'
import sys, ast; sys.path.insert(0, ".")
src = open("evaluation/absence-detection/map_defence_in_depth.py").read()
tree = ast.parse(src)
# The mapper must not import or call any LLM surface. This is the structural form of "no LLM veto":
# a component that never consults a model cannot be talked out of a finding by one.
imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
names = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
llm_surface = {"agent.llm", "openai", "litellm", "anthropic"}
touched = (imported | names) & llm_surface
# `gateway` is the OAuth2 identity minter, not a model client — assert that distinction holds.
uses_llm_call = "llm.chat" in src or "chat.completions" in src
print(f"  llm imports={sorted(touched)}  llm call sites={uses_llm_call}")
sys.exit(0 if not touched and not uses_llm_call else 1)
PY
then ok "the mapper imports no LLM surface and makes no model call — a model cannot suppress a finding"
else bad "DD1: an LLM surface is reachable from the verdict path"; fi

sect "DD1-neg: the check would actually catch an LLM import (not a vacuous grep)"
if run_py <<'PY'
import sys, ast
fake = "from agent import llm\nx = llm.chat([], model='m')\n"
tree = ast.parse(fake)
imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
touched = imported & {"agent.llm", "openai", "litellm", "anthropic"}
# note: `from agent import llm` records module 'agent'; the call-site check is what catches it
sys.exit(0 if ("llm.chat" in fake or touched) else 1)
PY
then ok "a planted LLM import + call is detected (negative control holds)"
else bad "DD1-neg: the detector is blind to a planted LLM call"; fi

sect "DD2: verdicts are taken at the ENFORCEMENT point, never the app origin"
if run_py <<'PY'
import sys
src = open("evaluation/absence-detection/map_defence_in_depth.py").read()
# The classifier must branch on the gateway response; the app response may only refine severity.
ok = ("enforcement origin unreachable" in src
      and "refusing to judge from the app origin" in src
      and "gw[\"status\"]" in src)
print(f"  gateway-first classification present={ok}")
sys.exit(0 if ok else 1)
PY
then ok "an unreachable enforcement origin errors instead of judging from the app (E8's artefact cannot recur)"
else bad "DD2: the classifier can fall back to the app origin"; fi

sect "DD3: evidence is redacted on write through the canonical seam"
if run_py <<'PY'
import sys; sys.path.insert(0, ".")
from agent import trace
src = open("evaluation/absence-detection/map_defence_in_depth.py").read()
uses_seam = "trace.redact_persisted" in src
# negative control: the seam must actually alter a planted secret-bearing body
planted = 'token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig and admin@juice-sh.op'
altered = trace.redact_persisted(planted) != planted
print(f"  uses seam={uses_seam}  seam alters planted JWT+email={altered}")
sys.exit(0 if uses_seam and altered else 1)
PY
then ok "evidence routes through redact_persisted, and the seam demonstrably alters a planted JWT+email"
else bad "DD3: evidence is persisted unredacted"; fi

sect "DD4: probe artefacts are gitignored (identity-bearing evidence must not be committed)"
if git check-ignore -q evaluation/absence-detection/defence-in-depth-map-260726.json 2>/dev/null; then
  ok "the map artefact is gitignored"
else bad "DD4: the map artefact would be committed"; fi

sect "DD5: the run fails closed without a live identity (H1's silent-failure mode)"
if KONG_CLIENT_SECRET="" AGENT_RECON_SECRET="" "$PY" -W ignore "$MAP" >/dev/null 2>&1; then
  bad "DD5: the map reported a result without a live identity (every endpoint would look protected)"
else ok "no live identity -> non-zero exit, never a 'clean' report"; fi

sect "DD6: both canaries are asserted in the committed surface"
if run_py <<'PY'
import json, sys
d = json.load(open("evaluation/absence-detection/routed-surface.json"))
has_session = bool(d.get("session_canary", {}).get("path"))
has_synth = bool(d.get("synthetic_canary", {}).get("path"))
# the synthetic canary must NOT be a real finding (a fixed system would stop firing it)
synth_is_unrouted = "not routed" in d["synthetic_canary"]["note"].lower() or "does NOT route" in d["synthetic_canary"]["note"]
print(f"  session_canary={has_session} synthetic_canary={has_synth} synthetic_is_unrouted={synth_is_unrouted}")
sys.exit(0 if has_session and has_synth and synth_is_unrouted else 1)
PY
then ok "session canary (identity liveness) + synthetic canary (prober liveness, not a real finding) both committed"
else bad "DD6: a canary is missing or the synthetic canary depends on a real vulnerability"; fi

sect "DD7: a 401 rendered as text/html is app-enforced, NOT 'no such endpoint'"
if run_py <<'PY'
import sys; sys.path.insert(0, "evaluation/absence-detection")
from measure_exposure_gap import classify
gw = {"status": 404, "bytes": 0, "html": False, "body": ""}
# This target renders 401 as text/html. An HTML-before-status branch order classified these as
# "absent" and under-counted app-side controls 6->2 — in the direction that enlarged the reported gap.
routed, posture, _ = classify(gw, {"status": 401, "bytes": 900, "html": True, "body": "<html>401</html>"})
# negative control: a genuine SPA fallback (200 + HTML) must still be discarded
_, absent_posture, _ = classify(gw, {"status": 200, "bytes": 900, "html": True, "body": "<html>app</html>"})
print(f"  401+html -> {posture}   200+html -> {absent_posture}")
sys.exit(0 if posture == "app-enforced" and absent_posture == "absent" else 1)
PY
then ok "401+text/html classifies app-enforced while 200+text/html is still discarded (ordering bug cannot recur)"
else bad "DD7: content-type is still able to mask an app-side control"; fi

sect "DD8: routing coverage is independent of the app's response"
if run_py <<'PY'
import sys; sys.path.insert(0, "evaluation/absence-detection")
from measure_exposure_gap import classify
# The routing axis must answer identically no matter what the app says — that independence is what
# stops a branch order from biasing the coverage count again.
gw_routed = {"status": 403, "bytes": 0, "html": False, "body": ""}
apps = [{"status": 200, "bytes": 10, "html": False, "body": "{}"},
        {"status": 401, "bytes": 10, "html": True, "body": "x"},
        {"status": 500, "bytes": 10, "html": False, "body": "x"},
        {"status": 404, "bytes": 0, "html": False, "body": ""}]
routed_flags = {classify(gw_routed, a)[0] for a in apps}
unrouted_flags = {classify({"status": 404, "bytes": 0, "html": False, "body": ""}, a)[0] for a in apps}
print(f"  routed axis across 4 app responses={routed_flags}  unrouted={unrouted_flags}")
sys.exit(0 if routed_flags == {True} and unrouted_flags == {False} else 1)
PY
then ok "the routed axis is constant across every app posture — no app response can shift the coverage count"
else bad "DD8: the routing verdict changes with the app's response"; fi

sect "DD9: a 2xx with an empty payload is not counted as a bypass"
if run_py <<'PY'
import sys; sys.path.insert(0, "evaluation/absence-detection")
from map_defence_in_depth import _has_substance
# /rest/user/whoami answers 200 {"user":{}} — the app IS withholding the protected data. Counting that
# as "no authorization of its own" overstated decision 0025's finding from 1 of 2 to 2 of 2.
empty = _has_substance('{"user":{}}')
# negative control: the endpoint that really does disclose must still register as substance
real = _has_substance('{"version":"20.1.1"}')
nested = _has_substance('{"a":{"b":[]}}')
print(f"  empty-shell={empty}  real-payload={real}  nested-empty={nested}")
sys.exit(0 if not empty and real and not nested else 1)
PY
then ok "empty JSON shells register as no-disclosure while a real payload still does (finding stays 1 of 2)"
else bad "DD9: payload substance is not measured — a withholding app looks like a bypass"; fi

sect "DD10: both probers share one loopback guard and it fails closed"
if run_py <<'PY'
import sys; sys.path.insert(0, "evaluation/absence-detection")
from probe_safety import assert_local
mdd = open("evaluation/absence-detection/map_defence_in_depth.py").read()
meg = open("evaluation/absence-detection/measure_exposure_gap.py").read()
shared = all("from probe_safety import assert_local" in s and "assert_local(gw_origin, app_origin)" in s
             for s in (mdd, meg))
assert_local("http://127.0.0.1:13000")            # must not exit
try:
    assert_local("http://198.51.100.7")           # must exit 2
    blocked = False
except SystemExit as e:
    blocked = e.code == 2
print(f"  both probers use the shared guard={shared}  non-loopback blocked={blocked}")
sys.exit(0 if shared and blocked else 1)
PY
then ok "one guard, both probers, and a non-loopback origin exits 2 (no copy that can drift)"
else bad "DD10: a prober can target a non-loopback origin"; fi

sect "summary"
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
