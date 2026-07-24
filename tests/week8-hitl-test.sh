#!/usr/bin/env bash
# Week-8 PR1 HITL approval-gate contract (invariants HA1-HA5) from
# docs/plans/active/2026-07-24-no-issue-week8-hitl-high-risk-actions.md's "Re-scoped PR1".
#
# All unit-level (no services, no REQUIRE_AGENT gate needed) — the whole point of RD1/RD5 is that
# the gate is real crypto + a local ledger, not something that depends on a live target/gateway.
# Idiom matches tests/recon-tools-test.sh (PASS/FAIL/SKIP helpers) and reuses
# tests/syndicate-test.sh's fixture-patching style (recon.build_map/fuzz.run mocked so exploit
# proposals are deterministic) for the graph-level cases.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$REPO_ROOT/rag/.venv/bin/python"

PASS=0; FAIL=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
sect() { printf '\n== %s ==\n' "$1"; }

[ -x "$PY" ] || { echo "missing venv at $PY"; exit 2; }
cd "$REPO_ROOT" || { echo "cannot cd to $REPO_ROOT"; exit 2; }
run_py() { "$PY" - "$@"; }

# ---------------------------------------------------------------------------
sect "HA1: resume without a valid token is refused; a valid token proceeds (negative control)"

if run_py <<'PY'
import os, sqlite3, sys, tempfile
from unittest.mock import patch
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import Command

import agent.approval as approval
import agent.fuzz as fuzz
import agent.recon as recon
import agent.supervisor as sup
from agent.schema import AttackSurfaceMap, Provenance

def fake_map(use_llm=True):
    return AttackSurfaceMap(target="t", generated_at="2026-07-24T00:00:00Z", agent_version="0.1",
                             endpoints=[],
                             provenance=Provenance(attack_surface_baseline="b", model="none")
                             ).recompute_aggregates()

def fake_run(use_llm=True, baseline_path=fuzz.BASELINE, surface_map=None):
    finding = fuzz.Finding(endpoint="GET /rest/products/search", param="q", payload_class="sqli",
                            payload="' UNION SELECT NULL--", signals=["stack_trace: near syntax error"])
    return fuzz.FuzzReport(targets=["GET /rest/products/search?q"], requests_sent=2,
                            findings=[finding], signal_counts={"stack_trace": 1}, guidance=None)

def new_graph(tmpdir):
    conn = sqlite3.connect(os.path.join(tmpdir, "cp.sqlite"), check_same_thread=False)
    saver = SqliteSaver(conn); saver.setup()
    return sup.build_graph(saver), conn

def pause(graph, thread, db_path):
    cfg = {"configurable": {"thread_id": thread}}
    out = graph.invoke({"model": "sast-sol", "use_llm": False, "pending_state_change": True,
                        "approval_db_path": db_path,
                        "budget": {"total_requests_sent": 0, "target_max": fuzz.MAX_TOTAL_REQUESTS}},
                       config=cfg)
    assert "__interrupt__" in out, "expected the graph to pause at interrupt_seam"
    return cfg, out["__interrupt__"][0].value["proposal"]

with patch.object(recon, "build_map", side_effect=fake_map), \
     patch.object(fuzz, "run", side_effect=fake_run):

    # --- no valid token: a malformed/empty resume value must be refused, action must never run.
    # Resumed via sup.resume_state_change (not a bare graph.invoke(Command(resume={}))): an EMPTY
    # dict is LangGraph's own "per-interrupt resume map with zero entries" sentinel, so a bare
    # invoke would just silently re-pause instead of ever reaching state_change_node — see
    # resume_state_change's docstring for why that gap can only be closed at this call site.
    d1 = tempfile.mkdtemp()
    db1 = os.path.join(d1, "approval.sqlite")
    graph1, conn1 = new_graph(d1)
    cfg1, proposal1 = pause(graph1, "ha1-no-token", db1)
    refused = False
    try:
        sup.resume_state_change(graph1, cfg1, {})
    except PermissionError as e:
        refused = True
        print(f"  no-token resume raised (expected): {e}")
    conn1.close()
    ledger1 = approval.ApprovalLedger(db1)
    entries1 = ledger1.entries()
    ledger1.close()
    no_action_ran = all(row["action"] != "simulated-execute" for row in entries1)
    refused_audited = any(row["action"] == "refused" for row in entries1)
    print(f"  refused={refused} no_action_ran={no_action_ran} refused_audited={refused_audited}")

    # --- with a valid token: the simulated action DOES run (negative control on the refusal above)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    import time, uuid

    d2 = tempfile.mkdtemp()
    db2 = os.path.join(d2, "approval.sqlite")
    pub2 = os.path.join(d2, "pub.pem")
    priv2 = Ed25519PrivateKey.generate()
    with open(pub2, "wb") as f:
        f.write(priv2.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    graph2, conn2 = new_graph(d2)
    cfg2 = {"configurable": {"thread_id": "ha1-valid-token"}}
    out2a = graph2.invoke({"model": "sast-sol", "use_llm": False, "pending_state_change": True,
                           "approval_db_path": db2, "approval_pubkey_path": pub2,
                           "budget": {"total_requests_sent": 0, "target_max": fuzz.MAX_TOTAL_REQUESTS}},
                          config=cfg2)
    proposal2 = out2a["__interrupt__"][0].value["proposal"]
    payload = {"proposal_id": approval.proposal_id(proposal2),
               "proposal_hash": approval.proposal_content_hash(proposal2),
               "issued_at": time.time(), "ttl_seconds": 300, "nonce": uuid.uuid4().hex}
    token = {**payload, "signature": priv2.sign(approval.canonical_payload(payload)).hex()}
    out2b = graph2.invoke(Command(resume=token), config=cfg2)
    conn2.close()
    result = out2b.get("state_change_result")
    print(f"  valid-token result: {result}")
    proceeded = bool(result and result.get("simulated") is True)

ok = refused and no_action_ran and refused_audited and proceeded
sys.exit(0 if ok else 1)
PY
then ok "no/invalid token is refused fail-closed (audited, action never runs); a valid token proceeds to the simulated action"
else bad "HA1 failed — see stderr"; fi

# ---------------------------------------------------------------------------
sect "HA2 (anti-self-approval, the crux): a forged token cannot pass verification with only the public key"

if run_py <<'PY'
import ast, inspect, io, sys, tokenize
import agent.approval as approval
import agent.supervisor as sup

def code_only(source: str) -> str:
    """Strip every `#` comment and every module/class/function docstring, leaving only executable
    code. Without this, a docstring that merely DESCRIBES the absence of signing (e.g. this very
    repo's own "...never calls `.sign()`...") trips a bare substring grep just as hard as a real
    `.sign(...)` CALL would — the check below wants the latter, not prose about the former."""
    lines = source.splitlines(keepends=True)
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type == tokenize.COMMENT:
            (row, col), (_, end_col) = tok.start, tok.end
            lines[row - 1] = lines[row - 1][:col] + lines[row - 1][end_col:]
    tree = ast.parse(source)
    doc_ranges = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                d = node.body[0]
                doc_ranges.append((d.lineno, d.end_lineno))
    for start, end in doc_ranges:
        for lineno in range(start, end + 1):
            lines[lineno - 1] = "\n"
    return "".join(lines)

# Structural proof: the module the graph runtime imports has NO way to mint a signature — no
# private-key loader, no Ed25519PrivateKey reference, no actual `.sign(...)` CALL anywhere in its
# CODE (a docstring/comment merely describing that absence, like this module's own, must not trip
# this — the check is precise to real code, not prose).
src = code_only(inspect.getsource(approval))
no_priv_loader = not hasattr(approval, "load_private_key")
no_priv_type = "Ed25519PrivateKey" not in src
no_sign_call = ".sign(" not in src

sup_src = code_only(inspect.getsource(sup))
sup_no_sign = ".sign(" not in sup_src and "Ed25519PrivateKey" not in sup_src

print(f"  approval.py: no_priv_loader={no_priv_loader} no_priv_type={no_priv_type} no_sign_call={no_sign_call}")
print(f"  supervisor.py: sup_no_sign={sup_no_sign}")

ok = no_priv_loader and no_priv_type and no_sign_call and sup_no_sign
sys.exit(0 if ok else 1)
PY
then ok "agent/approval.py (imported by the graph) has no private-key loader, no Ed25519PrivateKey reference, no .sign() call; supervisor.py likewise"
else bad "the graph-side module retains a code path capable of signing — self-approval boundary broken"; fi

if run_py <<'PY'
import sys, time, uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import agent.approval as approval

proposal = {"endpoint": "GET /rest/products/search", "vuln_class": "sql-injection-suspected",
           "technique": "manually verify", "justification": "fuzz flagged it"}

# The REAL approver's keypair (what agent/keys/approver.pub or an equivalent committed key
# represents) vs. an ATTACKER's own freshly-generated keypair — simulating a compromised agent
# runtime that can generate ITS OWN Ed25519 keypair (trivial, no secret needed) but does NOT hold
# the real approver's private key.
real_priv = Ed25519PrivateKey.generate()
real_pub = real_priv.public_key()
attacker_priv = Ed25519PrivateKey.generate()

def mint(priv, ttl=300, nonce=None):
    payload = {"proposal_id": approval.proposal_id(proposal),
               "proposal_hash": approval.proposal_content_hash(proposal),
               "issued_at": time.time(), "ttl_seconds": ttl, "nonce": nonce or uuid.uuid4().hex}
    return {**payload, "signature": priv.sign(approval.canonical_payload(payload)).hex()}

import tempfile, os
ledger = approval.ApprovalLedger(os.path.join(tempfile.mkdtemp(), "approval.sqlite"))

# The forged token: signed by the ATTACKER's key, verified against the REAL approver's PUBLIC key
# (the only key the agent runtime ever holds) — must be rejected.
forged = mint(attacker_priv)
forged_ok = approval.verify_approval(forged, proposal, real_pub, ledger)
print(f"  forged (attacker-signed) token verifies against the real pubkey: {forged_ok}")

# Negative control: the SAME proposal, SAME shaped token, signed by the REAL matching private key
# — must verify. Proves the rejection above is about the WRONG key, not a broken verifier.
genuine = mint(real_priv)
genuine_ok = approval.verify_approval(genuine, proposal, real_pub, ledger)
print(f"  genuine (real-key-signed) token verifies against the real pubkey: {genuine_ok}")

ledger.close()
sys.exit(0 if (forged_ok is False and genuine_ok is True) else 1)
PY
then ok "a token signed by any OTHER key (what a compromised agent runtime could self-mint) is rejected; the matching key's token verifies (negative control — the verifier isn't just always-False)"
else bad "HA2 failed — a forged token verified, or the negative control failed"; fi

# ---------------------------------------------------------------------------
sect "HA3: single-use (replay refused), proposal-bound (tamper refused), TTL-bounded (expiry refused)"

if run_py <<'PY'
import os, sys, tempfile, time, uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import agent.approval as approval

proposal = {"endpoint": "GET /rest/products/search", "vuln_class": "sql-injection-suspected",
           "technique": "manually verify", "justification": "fuzz flagged it"}
priv = Ed25519PrivateKey.generate()
pub = priv.public_key()

def mint(nonce=None, ttl=300, issued_at=None):
    payload = {"proposal_id": approval.proposal_id(proposal),
               "proposal_hash": approval.proposal_content_hash(proposal),
               "issued_at": issued_at if issued_at is not None else time.time(),
               "ttl_seconds": ttl, "nonce": nonce or uuid.uuid4().hex}
    return {**payload, "signature": priv.sign(approval.canonical_payload(payload)).hex()}

# --- single-use: the SAME token, verified twice against a SHARED ledger (same db, simulating a
# replay against a second HITL request) — second verification must fail; a fresh, unused token
# for the same proposal must still succeed (negative control: not just "always False after one use").
db = os.path.join(tempfile.mkdtemp(), "approval.sqlite")
ledger = approval.ApprovalLedger(db)
tok = mint()
first_use = approval.verify_approval(tok, proposal, pub, ledger)
replay = approval.verify_approval(tok, proposal, pub, ledger)
fresh_tok = mint()
fresh_use = approval.verify_approval(fresh_tok, proposal, pub, ledger)
print(f"  single-use: first_use={first_use} replay={replay} fresh_token_use={fresh_use}")
ledger.close()
single_use_ok = first_use is True and replay is False and fresh_use is True

# --- proposal-bound: a token minted for `proposal` must be refused against a TAMPERED proposal
# (different justification text -> different content hash); the SAME (untampered) proposal must
# still verify (negative control).
db2 = os.path.join(tempfile.mkdtemp(), "approval.sqlite")
ledger2 = approval.ApprovalLedger(db2)
tok2 = mint()
tampered = dict(proposal, justification="a rewritten justification the human never approved")
tamper_ok = approval.verify_approval(tok2, tampered, pub, ledger2)
untampered_ok = approval.verify_approval(tok2, proposal, pub, ledger2)
print(f"  proposal-bound: tampered_proposal_accepted={tamper_ok} untampered_accepted={untampered_ok}")
ledger2.close()
tamper_bound_ok = tamper_ok is False and untampered_ok is True

# --- TTL: a token issued well outside its own ttl_seconds window must be refused; a fresh one
# with the same ttl must succeed (negative control).
db3 = os.path.join(tempfile.mkdtemp(), "approval.sqlite")
ledger3 = approval.ApprovalLedger(db3)
expired = mint(issued_at=time.time() - 1000, ttl=300)
expired_ok = approval.verify_approval(expired, proposal, pub, ledger3)
fresh = mint(issued_at=time.time(), ttl=300)
fresh_ok = approval.verify_approval(fresh, proposal, pub, ledger3)
print(f"  ttl-bounded: expired_accepted={expired_ok} fresh_accepted={fresh_ok}")
ledger3.close()
ttl_ok = expired_ok is False and fresh_ok is True

ok = single_use_ok and tamper_bound_ok and ttl_ok
sys.exit(0 if ok else 1)
PY
then ok "replay/tamper/expiry are each refused; a fresh/untampered/in-window token still verifies (negative control per case)"
else bad "HA3 failed — see stderr"; fi

# ---------------------------------------------------------------------------
sect "HA4: the action is SIMULATED (no network call, no target mutation); audit precedes the action"

if run_py <<'PY'
import ast, inspect, io, sys, tokenize
import agent.supervisor as sup
import agent.approval as approval
import agent.approve as approve

def code_only(source: str) -> str:
    """Strip every `#` comment and every module/class/function docstring, leaving only executable
    code. `state_change_node`'s OWN docstring describes what it does NOT do ("no gateway/requests/
    network call") — a bare substring grep over the whole function source (docstring included)
    trips on that prose; this check wants an actual reference in CODE, not a description of its
    absence."""
    lines = source.splitlines(keepends=True)
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type == tokenize.COMMENT:
            (row, col), (_, end_col) = tok.start, tok.end
            lines[row - 1] = lines[row - 1][:col] + lines[row - 1][end_col:]
    tree = ast.parse(source)
    doc_ranges = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                d = node.body[0]
                doc_ranges.append((d.lineno, d.end_lineno))
    for start, end in doc_ranges:
        for lineno in range(start, end + 1):
            lines[lineno - 1] = "\n"
    return "".join(lines)

# Scoped to state_change_node's FUNCTION BODY only (not the whole module — fuzz_node's legitimate
# network use lives elsewhere in this file) and to CODE only (not its own descriptive docstring).
src = code_only(inspect.getsource(sup.state_change_node))
BANNED = ("gateway", "requests", "httpx", "socket", "urlopen")
offenders = [b for b in BANNED if b in src]
print(f"  state_change_node source references a network primitive: {offenders or 'none'}")

# The two Week-8 modules themselves must import none of these either (approve.py/approval.py are
# local-filesystem + crypto only — RD5's "loopback only" claim, made concrete and testable).
mod_offenders = []
for mod in (approval, approve):
    msrc = code_only(inspect.getsource(mod))
    for b in BANNED:
        if f"import {b}" in msrc or f"from {b}" in msrc or f".{b}(" in msrc:
            mod_offenders.append((mod.__name__, b))
print(f"  approval.py/approve.py import a network primitive: {mod_offenders or 'none'}")

sys.exit(0 if (not offenders and not mod_offenders) else 1)
PY
then ok "state_change_node's source, and approval.py/approve.py, reference no gateway/requests/httpx/socket primitive"
else bad "a network primitive is referenced where the simulated action lives"; fi

if run_py <<'PY'
# Dynamic proof (not just static grep): patch socket.socket.connect to raise on ANY real
# connection attempt, then run a full valid-token approve -> simulate flow. If state_change_node
# ever actually tried to reach the network, this would raise; it must complete cleanly instead.
import os, socket, sqlite3, sys, tempfile, time, uuid
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import Command

import agent.approval as approval
import agent.fuzz as fuzz
import agent.recon as recon
import agent.supervisor as sup
from agent.schema import AttackSurfaceMap, Provenance

def fake_map(use_llm=True):
    return AttackSurfaceMap(target="t", generated_at="2026-07-24T00:00:00Z", agent_version="0.1",
                             endpoints=[],
                             provenance=Provenance(attack_surface_baseline="b", model="none")
                             ).recompute_aggregates()

def fake_run(use_llm=True, baseline_path=fuzz.BASELINE, surface_map=None):
    finding = fuzz.Finding(endpoint="GET /rest/products/search", param="q", payload_class="sqli",
                            payload="' UNION SELECT NULL--", signals=["stack_trace: near syntax error"])
    return fuzz.FuzzReport(targets=["GET /rest/products/search?q"], requests_sent=2,
                            findings=[finding], signal_counts={"stack_trace": 1}, guidance=None)

def _no_network(*a, **kw):
    raise AssertionError("state_change_node attempted a real network connection")

d = tempfile.mkdtemp()
db = os.path.join(d, "approval.sqlite")
pub_path = os.path.join(d, "pub.pem")
priv = Ed25519PrivateKey.generate()
with open(pub_path, "wb") as f:
    f.write(priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

conn = sqlite3.connect(os.path.join(d, "cp.sqlite"), check_same_thread=False)
saver = SqliteSaver(conn); saver.setup()
graph = sup.build_graph(saver)

with patch.object(recon, "build_map", side_effect=fake_map), \
     patch.object(fuzz, "run", side_effect=fake_run), \
     patch.object(socket.socket, "connect", _no_network):
    cfg = {"configurable": {"thread_id": "ha4-no-network"}}
    out1 = graph.invoke({"model": "sast-sol", "use_llm": False, "pending_state_change": True,
                         "approval_db_path": db, "approval_pubkey_path": pub_path,
                         "budget": {"total_requests_sent": 0, "target_max": fuzz.MAX_TOTAL_REQUESTS}},
                        config=cfg)
    proposal = out1["__interrupt__"][0].value["proposal"]
    payload = {"proposal_id": approval.proposal_id(proposal),
               "proposal_hash": approval.proposal_content_hash(proposal),
               "issued_at": time.time(), "ttl_seconds": 300, "nonce": uuid.uuid4().hex}
    token = {**payload, "signature": priv.sign(approval.canonical_payload(payload)).hex()}
    out2 = graph.invoke(Command(resume=token), config=cfg)
conn.close()

result = out2.get("state_change_result")
print(f"  ran to completion with socket.connect patched to raise: result={result}")
sys.exit(0 if (result and result.get("simulated") is True) else 1)
PY
then ok "the simulated action completes with socket.connect() patched to raise — no real network call was ever made"
else bad "the simulated action failed to complete (or made a network call) with connect() blocked"; fi

if run_py <<'PY'
# The audit row is written BEFORE the "action" (the SIMULATED log line) — proven by crashing
# INSIDE the action step (patching builtins.print, which state_change_node calls only AFTER its
# audit write) and confirming the audit row already landed despite the crash.
import builtins, os, sqlite3, sys, tempfile, time, uuid
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import Command

import agent.approval as approval
import agent.fuzz as fuzz
import agent.recon as recon
import agent.supervisor as sup
from agent.schema import AttackSurfaceMap, Provenance

def fake_map(use_llm=True):
    return AttackSurfaceMap(target="t", generated_at="2026-07-24T00:00:00Z", agent_version="0.1",
                             endpoints=[],
                             provenance=Provenance(attack_surface_baseline="b", model="none")
                             ).recompute_aggregates()

def fake_run(use_llm=True, baseline_path=fuzz.BASELINE, surface_map=None):
    finding = fuzz.Finding(endpoint="GET /rest/products/search", param="q", payload_class="sqli",
                            payload="' UNION SELECT NULL--", signals=["stack_trace: near syntax error"])
    return fuzz.FuzzReport(targets=["GET /rest/products/search?q"], requests_sent=2,
                            findings=[finding], signal_counts={"stack_trace": 1}, guidance=None)

d = tempfile.mkdtemp()
db = os.path.join(d, "approval.sqlite")
pub_path = os.path.join(d, "pub.pem")
priv = Ed25519PrivateKey.generate()
with open(pub_path, "wb") as f:
    f.write(priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

conn = sqlite3.connect(os.path.join(d, "cp.sqlite"), check_same_thread=False)
saver = SqliteSaver(conn); saver.setup()
graph = sup.build_graph(saver)

real_print = builtins.print
def crashing_print(*a, **kw):
    text = " ".join(str(x) for x in a)
    if text.startswith("SIMULATED:"):
        raise RuntimeError("simulated crash during the action step")
    return real_print(*a, **kw)

with patch.object(recon, "build_map", side_effect=fake_map), \
     patch.object(fuzz, "run", side_effect=fake_run):
    cfg = {"configurable": {"thread_id": "ha4-audit-before-action"}}
    out1 = graph.invoke({"model": "sast-sol", "use_llm": False, "pending_state_change": True,
                         "approval_db_path": db, "approval_pubkey_path": pub_path,
                         "budget": {"total_requests_sent": 0, "target_max": fuzz.MAX_TOTAL_REQUESTS}},
                        config=cfg)
    proposal = out1["__interrupt__"][0].value["proposal"]
    payload = {"proposal_id": approval.proposal_id(proposal),
               "proposal_hash": approval.proposal_content_hash(proposal),
               "issued_at": time.time(), "ttl_seconds": 300, "nonce": uuid.uuid4().hex}
    token = {**payload, "signature": priv.sign(approval.canonical_payload(payload)).hex()}

    crashed = False
    with patch("builtins.print", crashing_print):
        try:
            graph.invoke(Command(resume=token), config=cfg)
        except RuntimeError:
            crashed = True
conn.close()

ledger = approval.ApprovalLedger(db)
entries = ledger.entries()
ledger.close()
audited = any(e["action"] == "simulated-execute" for e in entries)
print(f"  crashed_during_action={crashed} audit_row_present_despite_crash={audited}")
sys.exit(0 if (crashed and audited) else 1)
PY
then ok "the audit row for the simulated action is durably written before the action log line runs — proven by crashing during the action and finding the audit row anyway"
else bad "the audit row was not written before the action (or the crash injection did not fire)"; fi

# ---------------------------------------------------------------------------
sect "HA5: the approval surface is out-of-process + loopback; no external egress"

if run_py <<'PY'
import inspect, sys
import agent.approve as approve
import agent.approval as approval

# No agent-owned default path for a PRIVATE key anywhere in this module's source, and --key-file
# is a REQUIRED argparse argument (no `default=`) — the human must supply it explicitly every run.
src = inspect.getsource(approve)
required_key_arg = ('"--key-file"' in src and "required=True" in src.split('"--key-file"')[1].split(")")[0])
no_default_key_path = "default=" not in src.split('"--key-file"')[1].split(")")[0]
print(f"  --key-file is required (no default)={required_key_arg and no_default_key_path}")

# The audit/ledger and pubkey paths are local filesystem paths, not a URL/socket — the "surface"
# is a CLI + a file, not a listening service.
local_only = ("://" not in approval.DEFAULT_DB_PATH and "://" not in approval.DEFAULT_PUBKEY_PATH)
print(f"  DEFAULT_DB_PATH={approval.DEFAULT_DB_PATH!r} DEFAULT_PUBKEY_PATH={approval.DEFAULT_PUBKEY_PATH!r}")

sys.exit(0 if (required_key_arg and no_default_key_path and local_only) else 1)
PY
then ok "approve.py requires an explicit --key-file (no agent-readable default); the ledger/pubkey surface is local files, not a listening service"
else bad "HA5 static checks failed"; fi

if run_py <<'PY'
# Full out-of-process loop: mint a real Ed25519 keypair, write ONE ExploitProposal to a file (what
# a human reviewer would see), run `python -m agent.approve` as a SEPARATE PROCESS to approve it,
# then feed the resulting token file back into the graph's Command(resume=...) and confirm it
# proceeds. This is the actual intended workflow, not a shortcut through in-process functions.
import json, os, subprocess, sqlite3, sys, tempfile
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import Command

import agent.fuzz as fuzz
import agent.recon as recon
import agent.supervisor as sup
from agent.schema import AttackSurfaceMap, Provenance

def fake_map(use_llm=True):
    return AttackSurfaceMap(target="t", generated_at="2026-07-24T00:00:00Z", agent_version="0.1",
                             endpoints=[],
                             provenance=Provenance(attack_surface_baseline="b", model="none")
                             ).recompute_aggregates()

def fake_run(use_llm=True, baseline_path=fuzz.BASELINE, surface_map=None):
    finding = fuzz.Finding(endpoint="GET /rest/products/search", param="q", payload_class="sqli",
                            payload="' UNION SELECT NULL--", signals=["stack_trace: near syntax error"])
    return fuzz.FuzzReport(targets=["GET /rest/products/search?q"], requests_sent=2,
                            findings=[finding], signal_counts={"stack_trace": 1}, guidance=None)

d = tempfile.mkdtemp()
db = os.path.join(d, "approval.sqlite")
priv_path = os.path.join(d, "approver-private.pem")
pub_path = os.path.join(d, "approver.pub")
priv = Ed25519PrivateKey.generate()
with open(priv_path, "wb") as f:
    f.write(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption()))
with open(pub_path, "wb") as f:
    f.write(priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

conn = sqlite3.connect(os.path.join(d, "cp.sqlite"), check_same_thread=False)
saver = SqliteSaver(conn); saver.setup()
graph = sup.build_graph(saver)

with patch.object(recon, "build_map", side_effect=fake_map), \
     patch.object(fuzz, "run", side_effect=fake_run):
    cfg = {"configurable": {"thread_id": "ha5-out-of-process"}}
    out1 = graph.invoke({"model": "sast-sol", "use_llm": False, "pending_state_change": True,
                         "approval_db_path": db, "approval_pubkey_path": pub_path,
                         "budget": {"total_requests_sent": 0, "target_max": fuzz.MAX_TOTAL_REQUESTS}},
                        config=cfg)
proposal = out1["__interrupt__"][0].value["proposal"]

proposal_path = os.path.join(d, "proposal.json")
token_path = os.path.join(d, "token.json")
with open(proposal_path, "w", encoding="utf-8") as f:
    json.dump(proposal, f)

# A genuinely SEPARATE process — not an import, not a function call.
proc = subprocess.run(
    [sys.executable, "-m", "agent.approve", "--proposal-file", proposal_path,
     "--key-file", priv_path, "--approver", "test-approver", "--decision", "approve",
     "--out", token_path, "--db", db],
    cwd=os.path.dirname(os.path.dirname(os.path.abspath(sup.__file__))),
    capture_output=True, text=True, timeout=30,
)
print(f"  approve.py subprocess rc={proc.returncode} stdout={proc.stdout.strip()!r}")
if proc.returncode != 0:
    print(f"  stderr={proc.stderr}", file=sys.stderr)
    sys.exit(1)

with open(token_path, encoding="utf-8") as f:
    token = json.load(f)

with patch.object(recon, "build_map", side_effect=fake_map), \
     patch.object(fuzz, "run", side_effect=fake_run):
    out2 = graph.invoke(Command(resume=token), config=cfg)
conn.close()

result = out2.get("state_change_result")
print(f"  fed subprocess-minted token back into the graph: result={result}")
sys.exit(0 if (result and result.get("simulated") is True) else 1)
PY
then ok "a real out-of-process 'python -m agent.approve' subprocess mints the token; fed back, the graph's state_change_node accepts it"
else bad "the out-of-process approval loop failed"; fi

# ---------------------------------------------------------------------------
printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
