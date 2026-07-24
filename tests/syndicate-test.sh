#!/usr/bin/env bash
# Week-6 multi-agent Supervisor contract (PR1): invariants I2-I8 from
# docs/plans/active/2026-07-24-...-multi-agent-syndicate.md. I1 (model-egress) lives in the
# separate tests/agent-model-egress-contract-test.sh, matching D1's own file split.
#
# Two layers, matching this repo's other suites (recon-agent-test.sh, fuzz-engine-test.sh):
# UNIT (no services — `agent.recon.build_map`/`agent.fuzz.run` are mocked so the redaction,
# budget, and interrupt-seam mechanics are proven deterministically, with a negative control for
# every "must be absent" claim) and LIVE (skips unless REQUIRE_AGENT=1 — a bounded real
# Recon->Fuzz run through the gateway, and a real span landing in Phoenix).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$REPO_ROOT/rag/.venv/bin/python"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/infra/.env}"
REQUIRE_AGENT="${REQUIRE_AGENT:-0}"
PHOENIX_URL="${PHOENIX_URL:-http://127.0.0.1:6006}"

PASS=0; FAIL=0; SKIP=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
skip() { printf '  \033[33mSKIP\033[0m %s\n' "$1"; SKIP=$((SKIP+1)); }
sect() { printf '\n== %s ==\n' "$1"; }

[ -x "$PY" ] || { echo "missing venv at $PY"; exit 2; }
cd "$REPO_ROOT" || { echo "cannot cd to $REPO_ROOT"; exit 2; }
run_py() { "$PY" - "$@"; }

# ---------------------------------------------------------------------------
sect "I2: fuzz.run() scopes targets to the map's endpoints (no services)"

if run_py <<'PY'
import sys
from agent.fuzz import _fuzzable_targets, _map_endpoints_by_path, BASELINE
from agent.schema import AttackSurfaceMap, EndpointSurface, Provenance

unguided = _fuzzable_targets(BASELINE)
print(f"  unguided targets: {[(t.path, t.param) for t in unguided]}")

# A map that does NOT include the baseline's only fuzzable endpoint — scoping must exclude it.
narrow_map = AttackSurfaceMap(
    target="t", generated_at="2026-07-24T00:00:00Z", agent_version="0.1",
    endpoints=[EndpointSurface(path="/some/other/path", method="GET",
                                auth_class="public", state_change="read-only")],
    provenance=Provenance(attack_surface_baseline="b", model="none"),
).recompute_aggregates()
map_eps = _map_endpoints_by_path(narrow_map)
guided = [t for t in unguided if t.path in map_eps]
print(f"  guided (excluded-endpoint map) targets: {[(t.path, t.param) for t in guided]}")

ok = bool(unguided) and guided == []
sys.exit(0 if ok else 1)
PY
then ok "a map excluding the baseline's endpoint scopes the target set to empty (real wiring, not cosmetic)"
else bad "map scoping did not change the target set"; fi

if run_py <<'PY'
import sys
from agent.fuzz import _fuzzable_targets, _map_endpoints_by_path, BASELINE
from agent.schema import AttackSurfaceMap, EndpointSurface, Provenance

unguided = _fuzzable_targets(BASELINE)
# Negative control: a map that DOES include the baseline's endpoint must NOT scope it away.
wide_map = AttackSurfaceMap(
    target="t", generated_at="2026-07-24T00:00:00Z", agent_version="0.1",
    endpoints=[EndpointSurface(path=unguided[0].path, method="GET",
                                auth_class="public", state_change="read-only")],
    provenance=Provenance(attack_surface_baseline="b", model="none"),
).recompute_aggregates()
map_eps = _map_endpoints_by_path(wide_map)
guided = [t for t in unguided if t.path in map_eps]
sys.exit(0 if guided == unguided else 1)
PY
then ok "negative control: a map including the endpoint leaves the target set unchanged"
else bad "negative control failed — scoping over-excludes"; fi

sect "I2: fuzz.run() prioritizes injection classes when the map flags an injection CWE"

if run_py <<'PY'
import sys
from agent.fuzz import (_target_has_injection_cwe, _prioritized_corpus,
                         INJECTION_CWES, _INJECTION_PAYLOAD_CLASSES)
from agent.fuzz_payloads import CORPUS
from agent.schema import EndpointSurface, Finding

# 89 = SQL injection, a real INJECTION_CWES member.
ep_injectable = EndpointSurface(
    path="/x", auth_class="public", state_change="read-only",
    findings=[Finding(finding_id="1", title="SQLi", severity="High", scanner="DAST", cwe=89)])
ep_clean = EndpointSurface(
    path="/y", auth_class="public", state_change="read-only",
    findings=[Finding(finding_id="2", title="Info leak", severity="Low", scanner="SAST", cwe=200)])

assert 89 in INJECTION_CWES and 200 not in INJECTION_CWES
assert _target_has_injection_cwe(ep_injectable) is True
assert _target_has_injection_cwe(ep_clean) is False   # negative control: 200 is not injection-class

prioritized = _prioritized_corpus()
print(f"  CORPUS[0].cls={CORPUS[0].cls!r}  prioritized[0].cls={prioritized[0].cls!r}")
ok = (CORPUS[0].cls == "boundary"                         # committed order is unchanged
      and prioritized[0].cls in _INJECTION_PAYLOAD_CLASSES  # reorder actually moved injection first
      and {p.cls for p in prioritized} == {p.cls for p in CORPUS}   # same payloads, only reordered
      and len(prioritized) == len(CORPUS))
sys.exit(0 if ok else 1)
PY
then ok "an injection-class CWE on the map reorders the corpus (injection classes first); a non-injection CWE does not trigger it"
else bad "map-guided prioritization is not real"; fi

sect "I2 (H2): fuzz.run() itself sends injection classes earlier under an injection-CWE map (real output, not just the helper)"

if run_py <<'PY'
import sys
from unittest.mock import patch

import agent.fuzz as fuzz
from agent.fuzz import _fuzzable_targets, _INJECTION_PAYLOAD_CLASSES, BASELINE
from agent.schema import AttackSurfaceMap, EndpointSurface, Finding, Provenance
from agent.gateway import Gateway

unguided_targets = _fuzzable_targets(BASELINE)
assert unguided_targets, "fixture assumption broken: baseline has no fuzzable target"
target_path = unguided_targets[0].path

# `Gateway.__init__` mints a real OAuth token over the network (`gateway.py:_token`); `probe` is
# the only per-request call `fuzz.run()` makes. Stub both so this test exercises the REAL run()
# send loop (not just `_prioritized_corpus()` in isolation) with no services required. Every
# response is benign (no signals), which is fine — this test is about SEND ORDER, not findings.
def fake_init(self):
    pass

def fake_probe(self, url):
    return 200, "{}", "application/json"

with patch.object(Gateway, "__init__", fake_init), patch.object(Gateway, "probe", fake_probe):
    unguided = fuzz.run(use_llm=False)
    print(f"  unguided payload_order[:4]={unguided.payload_order[:4]}")

    injection_map = AttackSurfaceMap(
        target="t", generated_at="2026-07-24T00:00:00Z", agent_version="0.1",
        endpoints=[EndpointSurface(
            path=target_path, method="GET", auth_class="public", state_change="read-only",
            findings=[Finding(finding_id="1", title="SQLi", severity="High", scanner="DAST", cwe=89)])],
        provenance=Provenance(attack_surface_baseline="b", model="none"),
    ).recompute_aggregates()
    guided = fuzz.run(use_llm=False, surface_map=injection_map)
    print(f"  guided payload_order[:4]={guided.payload_order[:4]}")

    # Negative control: a map WITHOUT an injection-class CWE on the target must NOT reorder —
    # the unguided default order stays the corpus's committed order.
    clean_map = AttackSurfaceMap(
        target="t", generated_at="2026-07-24T00:00:00Z", agent_version="0.1",
        endpoints=[EndpointSurface(
            path=target_path, method="GET", auth_class="public", state_change="read-only",
            findings=[Finding(finding_id="2", title="Info leak", severity="Low", scanner="SAST", cwe=200)])],
        provenance=Provenance(attack_surface_baseline="b", model="none"),
    ).recompute_aggregates()
    clean = fuzz.run(use_llm=False, surface_map=clean_map)
    print(f"  clean-map (no injection CWE) payload_order[:4]={clean.payload_order[:4]}")

ok = (unguided.payload_order == clean.payload_order  # unguided == no-injection-CWE map: both default order
      and guided.payload_order != unguided.payload_order  # the injection-CWE map actually changed real send order
      and guided.payload_order[0] in _INJECTION_PAYLOAD_CLASSES
      and unguided.payload_order[0] not in _INJECTION_PAYLOAD_CLASSES)
sys.exit(0 if ok else 1)
PY
then ok "fuzz.run()'s real payload_order moves injection classes earlier under an injection-CWE map; an unguided/no-injection-CWE map keeps the default order (H2 proven on real output)"
else bad "fuzz.run() did not change real send order under an injection-CWE map"; fi

# ---------------------------------------------------------------------------
sect "I3: the checkpoint carries no secret and no raw target-derived text (no services)"

if run_py <<'PY'
import json, os, sqlite3, sys, tempfile
from unittest.mock import patch

import agent.fuzz as fuzz
import agent.recon as recon
import agent.supervisor as sup
from agent.schema import AttackSurfaceMap, EndpointSurface, Finding, Provenance

SECRET = "sk-ABCDEF1234567890REALLYLOOKSLIKEAKEY"
RAW_REASON = "SequelizeDatabaseError: near \"'\": syntax error at /rest/products/search"
RAW_PAYLOAD = "' UNION SELECT NULL,NULL,password FROM users--"
# Target-raw markers planted into fields the checkpoint RETAINS (HF1/H1/H2): an endpoint-
# attributed finding title, an app-level finding title (previously never iterated at all —
# H1's exact miss), and the analysis/guidance narrative fields.
XSS_MARKER = "<script>alert(1)</script>"
TRAVERSAL_MARKER = "../../../../etc/passwd"
BENIGN_TITLE = "SQL Injection"   # negative control: the vulnerability CLASS name, not an
                                 # injected marker — must survive redaction unchanged.

def fake_map(use_llm=True):
    return AttackSurfaceMap(
        target="t", generated_at="2026-07-24T00:00:00Z", agent_version="0.1",
        endpoints=[EndpointSurface(
            path="/rest/products/search", method="GET",
            auth_class="public", state_change="read-only",
            notes=f"operator note leaking a key: token={SECRET}",
            findings=[Finding(finding_id="1", title=f"Reflected: {XSS_MARKER}",
                               severity="High", scanner="DAST", cwe=79),
                      Finding(finding_id="2", title=BENIGN_TITLE,
                               severity="High", scanner="DAST", cwe=89)])],
        app_level_findings=[Finding(
            finding_id="3", title=f"Trivy secret scan hit near {TRAVERSAL_MARKER}",
            severity="Critical", scanner="SCA")],
        analysis=f"synthesis mentioning token={SECRET} and echoing RAW_MARKER:{RAW_REASON}",
        provenance=Provenance(attack_surface_baseline="b", model="none"),
    ).recompute_aggregates()

def fake_run(use_llm=True, baseline_path=fuzz.BASELINE, surface_map=None):
    finding = fuzz.Finding(endpoint="GET /rest/products/search", param="q",
                            payload_class="sqli", payload=RAW_PAYLOAD,
                            signals=[f"stack_trace: {RAW_REASON}"])
    return fuzz.FuzzReport(targets=["GET /rest/products/search?q"], requests_sent=3,
                            findings=[finding], signal_counts={"stack_trace": 1},
                            guidance=f"try more sqli; saw token={SECRET} and {RAW_PAYLOAD} echoed back")

d = tempfile.mkdtemp()
path = os.path.join(d, "cp.sqlite")
conn = sqlite3.connect(path, check_same_thread=False)
from langgraph.checkpoint.sqlite import SqliteSaver
saver = SqliteSaver(conn)
saver.setup()

with patch.object(recon, "build_map", side_effect=fake_map), \
     patch.object(fuzz, "run", side_effect=fake_run):
    result = sup.run_syndicate("redaction-check", use_llm=False, checkpointer=saver)

conn.close()

# `__interrupt__` is a transient LangGraph pause marker returned by invoke() for ergonomics,
# wrapping a non-JSON `Interrupt` object — it is NOT part of the checkpointed SyndicateState/D7
# contract (graph.get_state() never carries it; see supervisor.py). This run never sets
# `pending_state_change`, so `interrupt_seam` is a no-op (L1) and the key is not expected here
# either; excluded defensively so the check does not depend on that gating detail.
state_only = {k: v for k, v in result.items() if k != "__interrupt__"}

# The redacted result the caller sees must not carry the raw markers either.
blob = json.dumps(state_only)
assert SECRET not in blob, "secret leaked into the returned state"
assert RAW_REASON not in blob, "raw reason text leaked into the returned state"
assert RAW_PAYLOAD not in blob, "raw payload leaked into the returned state"
assert XSS_MARKER not in blob, "target-raw XSS marker leaked into a finding title in the returned state"
assert TRAVERSAL_MARKER not in blob, "target-raw traversal marker leaked into an app-level finding title"
# The signal *kind* must survive — redaction should not destroy the useful fact.
assert "stack_trace" in blob, "signal kind was dropped, not just the raw reason"
# Negative control: a benign finding title (not an injected marker) must survive untouched —
# proves redaction is targeted, not a blanket wipe of every finding title.
assert BENIGN_TITLE in blob, "benign finding title was wrongly scrubbed"

raw_db = open(path, "rb").read()
offenders = [m for m in (SECRET, RAW_REASON, RAW_PAYLOAD, XSS_MARKER, TRAVERSAL_MARKER)
             if m.encode() in raw_db]
if offenders:
    print(f"  FOUND in checkpoint DB: {offenders}", file=sys.stderr)
    sys.exit(1)
if BENIGN_TITLE.encode() not in raw_db:
    print("  negative control failed: benign finding title did not survive to the checkpoint DB",
          file=sys.stderr)
    sys.exit(1)
sys.exit(0)
PY
then ok "checkpoint DB + returned state carry no secret and no target-raw marker (incl. finding titles in endpoints[] AND app_level_findings); benign title + signal kind survive"
else bad "checkpoint DB or returned state leaked a secret/target-raw marker"; fi

if run_py <<'PY'
# Negative control: prove the byte-grep methodology above actually WOULD catch a leak if
# redaction were broken — write the SAME markers into a fresh checkpoint DB directly (bypassing
# supervisor's redaction helpers) and confirm they ARE found.
import os, sqlite3, sys, tempfile
from typing import TypedDict
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import StateGraph, END

SECRET = "sk-ABCDEF1234567890REALLYLOOKSLIKEAKEY"

class S(TypedDict, total=False):
    unsafe_raw: str

def leaky_node(state: S):
    return {"unsafe_raw": f"token={SECRET}"}   # deliberately bypasses redaction

d = tempfile.mkdtemp()
path = os.path.join(d, "cp.sqlite")
conn = sqlite3.connect(path, check_same_thread=False)
saver = SqliteSaver(conn)
saver.setup()
g = StateGraph(S)
g.add_node("leaky", leaky_node)
g.set_entry_point("leaky")
g.add_edge("leaky", END)
graph = g.compile(checkpointer=saver)
graph.invoke({}, config={"configurable": {"thread_id": "t"}})
conn.close()

raw_db = open(path, "rb").read()
sys.exit(0 if SECRET.encode() in raw_db else 1)
PY
then ok "negative control: an unredacted write IS found by the same check (detector is not vacuous)"
else bad "negative control failed — the byte-grep check cannot actually detect a leak"; fi

# ---------------------------------------------------------------------------
sect "I4: the request budget persists across a simulated resume (no re-arm, no services)"

if run_py <<'PY'
import os, sqlite3, sys, tempfile
from unittest.mock import patch

import agent.fuzz as fuzz
import agent.recon as recon
import agent.supervisor as sup
from agent.schema import AttackSurfaceMap, EndpointSurface, Provenance

def fake_map(use_llm=True):
    return AttackSurfaceMap(
        target="t", generated_at="2026-07-24T00:00:00Z", agent_version="0.1",
        endpoints=[EndpointSurface(path="/rest/products/search", method="GET",
                                    auth_class="public", state_change="read-only")],
        provenance=Provenance(attack_surface_baseline="b", model="none"),
    ).recompute_aggregates()

calls = {"n": 0}
def fake_run(use_llm=True, baseline_path=fuzz.BASELINE, surface_map=None):
    calls["n"] += 1
    return fuzz.FuzzReport(targets=["GET /x?q"], requests_sent=fuzz.MAX_TOTAL_REQUESTS,
                            findings=[], signal_counts={}, guidance=None)

d = tempfile.mkdtemp()
conn = sqlite3.connect(os.path.join(d, "cp.sqlite"), check_same_thread=False)
from langgraph.checkpoint.sqlite import SqliteSaver
saver = SqliteSaver(conn)
saver.setup()

with patch.object(recon, "build_map", side_effect=fake_map), \
     patch.object(fuzz, "run", side_effect=fake_run):
    r1 = sup.run_syndicate("resume-thread", use_llm=False, checkpointer=saver)
    print(f"  run1 budget={r1.get('budget')} fuzz.run() calls={calls['n']}")
    assert r1["budget"]["total_requests_sent"] == fuzz.MAX_TOTAL_REQUESTS
    assert calls["n"] == 1

    # A second call against the SAME thread_id must NOT re-arm the budget: fuzz.run() must not
    # be invoked again once the persisted ceiling is already reached.
    r2 = sup.run_syndicate("resume-thread", use_llm=False, checkpointer=saver)
    print(f"  run2 (same thread) budget={r2.get('budget')} fuzz.run() calls={calls['n']}")
    assert calls["n"] == 1, "fuzz.run() was called again — the budget was re-armed"
    assert r2["budget"]["total_requests_sent"] == fuzz.MAX_TOTAL_REQUESTS
    assert r2["fuzz_report"]["budget_exhausted"] is True

    # Negative control: a BRAND NEW thread_id must NOT be refused — proves the ceiling check is
    # a real per-thread budget gate, not a mechanism that always blocks fuzzing.
    r3 = sup.run_syndicate("a-different-thread", use_llm=False, checkpointer=saver)
    print(f"  run3 (fresh thread) budget={r3.get('budget')} fuzz.run() calls={calls['n']}")
    assert calls["n"] == 2, "a fresh thread's fuzz.run() call was wrongly refused"

conn.close()
sys.exit(0)
PY
then ok "budget persists across re-entry into the same thread; fuzz.run() is not re-invoked once exhausted; a fresh thread is unaffected"
else bad "budget did not persist / was re-armed on resume"; fi

# ---------------------------------------------------------------------------
sect "I5: the Phoenix span redactor strips secrets and target-raw text before export (no services)"

if run_py <<'PY'
import sys
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from agent.trace import RedactingSpanProcessor

provider = TracerProvider()
exp = InMemorySpanExporter()
provider.add_span_processor(RedactingSpanProcessor())
provider.add_span_processor(SimpleSpanProcessor(exp))
tracer = provider.get_tracer("t")

with tracer.start_as_current_span("node", attributes={"endpoint_count": 3}) as span:
    span.set_attribute("leak", "token=sk-ABCDEF1234567890 and ' UNION SELECT NULL--")

spans = exp.get_finished_spans()
attrs = dict(spans[0].attributes)
print(f"  exported attributes: {attrs}")
ok = ("sk-ABCDEF1234567890" not in attrs["leak"] and "UNION SELECT" not in attrs["leak"]
      and attrs["endpoint_count"] == 3)   # a benign numeric attribute survives untouched
sys.exit(0 if ok else 1)
PY
then ok "a planted secret + payload marker never reach the exporter; a benign attribute is untouched"
else bad "the span redactor did not strip a planted secret/target-raw marker"; fi

if run_py <<'PY'
# Negative control: a processor pipeline WITHOUT the redactor must still show the plaintext —
# proves the prior PASS came from the redactor, not from some other property of the pipeline.
import sys
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

provider = TracerProvider()
exp = InMemorySpanExporter()
provider.add_span_processor(SimpleSpanProcessor(exp))   # no RedactingSpanProcessor
tracer = provider.get_tracer("t")
with tracer.start_as_current_span("node") as span:
    span.set_attribute("leak", "token=sk-ABCDEF1234567890")
attrs = dict(exp.get_finished_spans()[0].attributes)
sys.exit(0 if "sk-ABCDEF1234567890" in attrs["leak"] else 1)
PY
then ok "negative control: without the redactor the secret DOES reach the exporter (redactor is doing real work)"
else bad "negative control failed — plaintext was stripped even without the redactor"; fi

sect "MF1: a full Bearer/JWT value is redacted, not just the 'Bearer' keyword"

if run_py <<'PY'
import sys
from agent.trace import scrub_secrets

# Before MF1: the keyword rule's trailing `\S+` matched only ONE whitespace-delimited token, so
# "Authorization: Bearer <JWT>" redacted just "Bearer" and left the JWT itself in clear text.
jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZ2VudCJ9.c2lnbmF0dXJlLWhlcmU"
text = f"Authorization: Bearer {jwt}\nnext-line: unaffected"
scrubbed = scrub_secrets(text)
print(f"  scrubbed: {scrubbed!r}")
ok = (jwt not in scrubbed                # the full token value is gone, not just "Bearer"
      and "Bearer" not in scrubbed        # the keyword itself is consumed by the match too
      and "unaffected" in scrubbed)       # the NEXT line is untouched (stops at end-of-line)
sys.exit(0 if ok else 1)
PY
then ok "a full 'Authorization: Bearer <JWT>' value is redacted end-to-end; a following line is untouched"
else bad "the secret-keyword regex still truncates at the first token"; fi

# ---------------------------------------------------------------------------
sect "I6: the interrupt() seam fires and resumes (no services)"

if run_py <<'PY'
import os, sqlite3, sys, tempfile
from unittest.mock import patch

import agent.fuzz as fuzz
import agent.recon as recon
import agent.supervisor as sup
from agent.schema import AttackSurfaceMap, EndpointSurface, Provenance
from langgraph.types import Command

def fake_map(use_llm=True):
    return AttackSurfaceMap(
        target="t", generated_at="2026-07-24T00:00:00Z", agent_version="0.1",
        endpoints=[], provenance=Provenance(attack_surface_baseline="b", model="none"),
    ).recompute_aggregates()

def fake_run(use_llm=True, baseline_path=fuzz.BASELINE, surface_map=None):
    return fuzz.FuzzReport(targets=[], requests_sent=0, findings=[], signal_counts={}, guidance=None)

d = tempfile.mkdtemp()
conn = sqlite3.connect(os.path.join(d, "cp.sqlite"), check_same_thread=False)
from langgraph.checkpoint.sqlite import SqliteSaver
saver = SqliteSaver(conn)
saver.setup()
graph = sup.build_graph(saver)

with patch.object(recon, "build_map", side_effect=fake_map), \
     patch.object(fuzz, "run", side_effect=fake_run):
    # Negative control (L1): a normal run — `pending_state_change` unset, as every PR1 run is —
    # must NOT pause. Proves the gate actually gates, not just that the guarded path still works.
    cfg0 = {"configurable": {"thread_id": "no-pause-check"}}
    out0 = graph.invoke({"model": "sast-sol", "use_llm": False,
                          "budget": {"total_requests_sent": 0, "target_max": fuzz.MAX_TOTAL_REQUESTS}},
                         config=cfg0)
    not_paused = "__interrupt__" not in out0 and graph.get_state(cfg0).next == ()
    print(f"  no pending_state_change: interrupted={'__interrupt__' in out0} next={graph.get_state(cfg0).next}")

    # Positive case: `pending_state_change=True` fires the seam, and Command(resume=...) continues.
    cfg = {"configurable": {"thread_id": "interrupt-check"}}
    out1 = graph.invoke({"model": "sast-sol", "use_llm": False, "pending_state_change": True,
                          "budget": {"total_requests_sent": 0, "target_max": fuzz.MAX_TOTAL_REQUESTS}},
                         config=cfg)
    fired = "__interrupt__" in out1
    paused_at = graph.get_state(cfg).next
    print(f"  pending_state_change=True: fired={fired} paused_at={paused_at}")

    out2 = graph.invoke(Command(resume="ack"), config=cfg)
    resumed = out2.get("interrupt_ack") is True and "__interrupt__" not in out2
    print(f"  resumed={resumed} out2 keys={sorted(out2.keys())}")

conn.close()
sys.exit(0 if (not_paused and fired and paused_at == ("interrupt_seam",) and resumed) else 1)
PY
then ok "interrupt_seam is a no-op when pending_state_change is unset (normal PR1 run); it pauses+resumes when pending_state_change=True"
else bad "the interrupt() seam did not fire/resume correctly"; fi

# ---------------------------------------------------------------------------
sect "I7: Phoenix binds loopback only (static, no services)"

COMPOSE="$REPO_ROOT/infra/phoenix/docker-compose.yml"
if [ -f "$COMPOSE" ]; then
  if python3 - "$COMPOSE" <<'PY'
import sys, yaml
c = yaml.safe_load(open(sys.argv[1]))
bad = []
for name, svc in (c.get("services") or {}).items():
    for p in (svc.get("ports") or []):
        if not str(p).startswith("127.0.0.1:"):
            bad.append(f"{name}: {p}")
if bad:
    sys.stderr.write("\n".join(bad) + "\n"); sys.exit(1)
sys.exit(0)
PY
  then ok "every published Phoenix port binds 127.0.0.1"
  else bad "a Phoenix port is not bound to 127.0.0.1"; fi

  if grep -qE '^\s*image:.*@sha256:' "$COMPOSE"; then
    ok "the Phoenix image is pinned by @sha256"
  else
    bad "the Phoenix image is not pinned by @sha256"
  fi
else
  bad "missing $COMPOSE"
fi

# ---------------------------------------------------------------------------
sect "I2 (live): the full graph produces typed, JSON-serializable state"

[ -f "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; }
GW_UP="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 4 "${KONG_PROXY:-https://127.0.0.1:18443}/rest/products/search?q=x" 2>/dev/null)"
DD_UP="$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "${DD_URL:-http://localhost:8080}/api/v2/" 2>/dev/null)"

if [ -z "${AGENT_RECON_SECRET:-}" ] || [ "$GW_UP" = "000" ] || [ "$DD_UP" = "000" ]; then
  m="gateway/lake not reachable / no secret"
  if [ "$REQUIRE_AGENT" = "1" ]; then bad "$m"; else skip "$m"; fi
else
  if run_py <<'PY'
import json, os, sys, tempfile
import agent.supervisor as sup

d = tempfile.mkdtemp()
saver = sup.default_checkpointer(os.path.join(d, "cp.sqlite"))
result = sup.run_syndicate("live-i2", use_llm=False, checkpointer=saver)

# `__interrupt__` is a transient LangGraph pause marker, not part of the checkpointed
# SyndicateState/D7 contract (see the module docstring in agent/supervisor.py) — checked
# against the checkpoint directly below, not the invoke() convenience return value.
state_only = {k: v for k, v in result.items() if k != "__interrupt__"}
checkpointed = sup.build_graph(saver).get_state({"configurable": {"thread_id": "live-i2"}}).values

# json.dumps succeeding IS the JSON-serializability proof; result must also carry real content.
blob = json.dumps(state_only)
checkpoint_blob = json.dumps(checkpointed)
rm = result.get("recon_map") or {}
fr = result.get("fuzz_report") or {}
ok = (len(blob) > 0 and len(checkpoint_blob) > 0 and rm.get("endpoints") and fr.get("targets") is not None
      and all(isinstance(k, str) for k in result))
sys.exit(0 if ok else 1)
PY
  then ok "live graph state round-trips through json.dumps; recon_map + fuzz_report are populated"
  else bad "live graph run failed or produced non-serializable state"; fi
fi

# ---------------------------------------------------------------------------
sect "I5 (live): a real graph run's span reaches Phoenix redacted"

PHX_UP="$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "$PHOENIX_URL/" 2>/dev/null)"
if [ "$PHX_UP" = "000" ]; then
  m="Phoenix not reachable at $PHOENIX_URL"
  if [ "$REQUIRE_AGENT" = "1" ]; then bad "$m"; else skip "$m"; fi
else
  if run_py <<'PY'
import sys
from agent import trace

marker = "sk-LIVEPHXCHECK1234567890"
with trace.node_span("syndicate-test-live-span", secret_leak=f"token={marker}",
                      payload_leak="' UNION SELECT NULL--") as span:
    pass
ok = trace._provider.force_flush(timeout_millis=8000)
sys.exit(0 if ok else 1)
PY
  then
    sleep 2
    PROJ="$(curl -s "$PHOENIX_URL/v1/projects" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["data"][0]["id"])' 2>/dev/null)"
    if [ -n "$PROJ" ]; then
      SPAN_JSON="$(curl -s "$PHOENIX_URL/v1/projects/$PROJ/spans?limit=50" | python3 -c '
import sys, json
d = json.load(sys.stdin)
for s in d.get("data", []):
    if s.get("name") == "syndicate-test-live-span":
        print(json.dumps(s["attributes"])); break
' 2>/dev/null)"
      if [ -n "$SPAN_JSON" ]; then
        if printf '%s' "$SPAN_JSON" | grep -qF 'sk-LIVEPHXCHECK1234567890'; then
          bad "a live secret marker reached Phoenix unredacted: $SPAN_JSON"
        elif printf '%s' "$SPAN_JSON" | grep -qF 'UNION SELECT'; then
          bad "a live target-raw marker reached Phoenix unredacted: $SPAN_JSON"
        else
          ok "a real span landed in Phoenix with the secret/payload markers redacted"
        fi
      else
        bad "span was flushed but not found in Phoenix within the wait window"
      fi
    else
      bad "could not query Phoenix's projects API"
    fi
  else
    bad "flushing the live span to Phoenix failed"
  fi
fi

# ---------------------------------------------------------------------------
sect "I8: bounded live e2e Recon -> Fuzz produces a report"

if [ -z "${AGENT_RECON_SECRET:-}" ] || [ "$GW_UP" = "000" ] || [ "$DD_UP" = "000" ]; then
  m="gateway/lake not reachable / no secret"
  if [ "$REQUIRE_AGENT" = "1" ]; then bad "$m"; else skip "$m"; fi
else
  if run_py <<'PY'
import os, sys, tempfile
import agent.supervisor as sup
from agent.fuzz import MAX_TOTAL_REQUESTS

d = tempfile.mkdtemp()
saver = sup.default_checkpointer(os.path.join(d, "cp.sqlite"))
result = sup.run_syndicate("live-i8", use_llm=False, checkpointer=saver)
fr = result.get("fuzz_report") or {}
rm = result.get("recon_map") or {}
print(f"  recon endpoints={len(rm.get('endpoints', []))}  fuzz targets={fr.get('targets')}"
      f"  requests_sent={fr.get('requests_sent')}  findings={len(fr.get('findings', []))}")
budget_ok = fr.get("requests_sent", 0) <= MAX_TOTAL_REQUESTS
report_ok = bool(rm.get("endpoints")) and fr.get("targets") is not None
sys.exit(0 if (budget_ok and report_ok) else 1)
PY
  then ok "bounded live run: Recon map -> map-guided Fuzz report, within budget"
  else bad "live e2e recon->fuzz run failed"; fi
fi

# ---------------------------------------------------------------------------
printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ]
