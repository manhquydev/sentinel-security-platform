#!/usr/bin/env bash
# Week-9 PII-redaction contract (invariants PA1-PA6) from
# docs/plans/active/2026-07-24-no-issue-week9-pii-redaction.md.
#
# All UNIT-level (no services): the redactor is pure and the capture path is driven through the
# same real Ed25519 token flow tests/week8-hitl-test.sh uses, so no live target/gateway is needed.
# Every "must be absent" claim carries a negative control (the raw fixture would fail the same
# assertion) — the journal's "checks that passed because they checked nothing" lesson.
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
sect "PA0: the dump fixture is synthetic (guard) AND actually plants PII (negative-control basis)"

if run_py <<'PY'
import json, sys
from agent import sim_dump
sim_dump.assert_synthetic()  # fails closed if a non-test PAN or non-teaching email is introduced
raw = json.dumps(sim_dump.SIMULATED_USER_DUMP)
planted = all(t in raw for t in ("admin@juice-sh.op", "4532015112830366", "eyJhbGciOiJIUzI1NiJ9",
                                 "7d3f2a1b-4c5d-6e7f-8a9b-0c1d2e3f4a5b", "0192023a7bbd73250516f069df18b500"))
print(f"  synthetic guard passed; fixture plants PII={planted}")
sys.exit(0 if planted else 1)
PY
then ok "fixture is synthetic and plants the PII the later negatives control against"
else bad "PA0 failed"; fi

# ---------------------------------------------------------------------------
sect "PA1 + PA6: end-to-end — an APPROVED simulated dump leaves every durable sink PII-free (no raw print)"

if run_py <<'PY'
import io, json, os, sqlite3, sys, tempfile, time, uuid
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import Command
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import agent.approval as approval
import agent.fuzz as fuzz
import agent.recon as recon
import agent.supervisor as sup
import agent.sim_dump as sim_dump
from agent.schema import AttackSurfaceMap, Provenance

RAW_PII = ["admin@juice-sh.op", "jim@juice-sh.op", "rsa_lord@juice-sh.op",
           "4532015112830366", "4111111111111111", "eyJhbGciOiJIUzI1NiJ9",
           "7d3f2a1b-4c5d-6e7f-8a9b-0c1d2e3f4a5b",
           "0192023a7bbd73250516f069df18b500", "e10adc3949ba59abbe56e057f20f883e"]

def fake_map(use_llm=True):
    return AttackSurfaceMap(target="t", generated_at="2026-07-24T00:00:00Z", agent_version="0.1",
                            endpoints=[], provenance=Provenance(attack_surface_baseline="b", model="none")
                            ).recompute_aggregates()

def fake_run(use_llm=True, baseline_path=fuzz.BASELINE, surface_map=None):
    f = fuzz.Finding(endpoint="GET /rest/products/search", param="q", payload_class="sqli",
                     payload="' UNION SELECT NULL--", signals=["stack_trace: near syntax error"])
    return fuzz.FuzzReport(targets=["GET /rest/products/search?q"], requests_sent=2,
                           findings=[f], signal_counts={"stack_trace": 1}, guidance=None)

with patch.object(recon, "build_map", side_effect=fake_map), \
     patch.object(fuzz, "run", side_effect=fake_run):
    d = tempfile.mkdtemp()
    db = os.path.join(d, "approval.sqlite"); pub = os.path.join(d, "pub.pem")
    priv = Ed25519PrivateKey.generate()
    with open(pub, "wb") as fh:
        fh.write(priv.public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo))
    conn = sqlite3.connect(os.path.join(d, "cp.sqlite"), check_same_thread=False)
    saver = SqliteSaver(conn); saver.setup()
    graph = sup.build_graph(saver)
    cfg = {"configurable": {"thread_id": "pa1"}}
    out_a = graph.invoke({"model": "sast-sol", "use_llm": False, "pending_state_change": True,
                          "approval_db_path": db, "approval_pubkey_path": pub,
                          "budget": {"total_requests_sent": 0, "target_max": fuzz.MAX_TOTAL_REQUESTS}},
                         config=cfg)
    proposal = out_a["__interrupt__"][0].value["proposal"]
    payload = {"proposal_id": approval.proposal_id(proposal),
               "proposal_hash": approval.proposal_content_hash(proposal),
               "issued_at": time.time(), "ttl_seconds": 300, "nonce": uuid.uuid4().hex}
    token = {**payload, "signature": priv.sign(approval.canonical_payload(payload)).hex()}

    # Capture BOTH streams during resume — PA6: the node must not print a raw dump row.
    cap_out, cap_err = io.StringIO(), io.StringIO()
    with redirect_stdout(cap_out), redirect_stderr(cap_err):
        out_b = graph.invoke(Command(resume=token), config=cfg)
    streams = cap_out.getvalue() + cap_err.getvalue()

    # Sink 1: the checkpointed state (what persists to disk).
    ckpt = graph.get_state(cfg).values
    ckpt_blob = json.dumps(ckpt, default=str)
    # Sink 2: the approval audit ledger detail.
    ledger = approval.ApprovalLedger(db); entries = ledger.entries(); ledger.close()
    audit_blob = json.dumps(entries, default=str)

    result = out_b.get("state_change_result") or {}
    proceeded = result.get("simulated") is True and "dump" in result

    leaks = {
        "checkpoint": [t for t in RAW_PII if t in ckpt_blob],
        "audit":      [t for t in RAW_PII if t in audit_blob],
        "stdout/err": [t for t in RAW_PII if t in streams],
    }
    # Negative control: the RAW fixture obviously contains these — proves the assertions are real.
    raw_has = all(t in json.dumps(sim_dump.SIMULATED_USER_DUMP) for t in RAW_PII)
    audited_classes = "pii_redacted" in result and result["pii_redacted"] != "none"
    print(f"  proceeded={proceeded} audited_classes={result.get('pii_redacted')!r} raw_control={raw_has}")
    print(f"  leaks={leaks}")
    okk = proceeded and raw_has and audited_classes and not any(leaks.values())
    sys.exit(0 if okk else 1)
PY
then ok "approved dump: checkpoint, audit ledger, and stdout/stderr all PII-free; class-counts audited (raw-fixture negative control holds)"
else bad "PA1/PA6 failed — a durable sink leaked PII or the action did not proceed"; fi

# ---------------------------------------------------------------------------
sect "PA2: the shared trace scrub removes PII on BOTH the checkpoint path and the span path"

if run_py <<'PY'
import json, sys
from agent import trace, sim_dump
raw = json.dumps(sim_dump.SIMULATED_USER_DUMP, indent=2)
rp = trace.redact_persisted(raw)         # checkpoint/audit path
sv = trace._scrub_value(raw)             # span path (must not be blind — B2)
toks = ["admin@juice-sh.op", "4532015112830366", "7d3f2a1b-4c5d-6e7f-8a9b-0c1d2e3f4a5b",
        "0192023a7bbd73250516f069df18b500"]
rp_clean = not any(t in rp for t in toks)
sv_clean = not any(t in sv for t in toks)
raw_dirty = all(t in raw for t in toks)  # negative control
print(f"  redact_persisted_clean={rp_clean} _scrub_value_clean={sv_clean} raw_control={raw_dirty}")
sys.exit(0 if rp_clean and sv_clean and raw_dirty else 1)
PY
then ok "redact_persisted AND _scrub_value both strip PII (span path is not blind); raw control holds"
else bad "PA2 failed — a trace path left PII"; fi

# ---------------------------------------------------------------------------
sect "PA3: RAG ingest scrubs PII before chunking AND preserves content-hash idempotency"

if run_py <<'PY'
import sys
from rag import ingest, sources
doc = sources.SourceDoc("attack-surface", "ref", "title",
                        "endpoint owned by admin@juice-sh.op card_number=4532015112830366", "record")
c1 = ingest._chunks_for(doc)
c2 = ingest._chunks_for(doc)  # re-ingest of identical content
text1 = " ".join(c.content for c in c1)
scrubbed = "admin@juice-sh.op" not in text1 and "4532015112830366" not in text1
placeheld = "[redacted:pii:" in text1
# Idempotency (M2): the same doc yields byte-identical chunk content => identical sha256 => 0 churn.
from rag import store
idempotent = [store.sha256(c.content) for c in c1] == [store.sha256(c.content) for c in c2]
raw_dirty = "admin@juice-sh.op" in doc.text  # negative control
print(f"  scrubbed={scrubbed} placeheld={placeheld} idempotent={idempotent} raw_control={raw_dirty}")
sys.exit(0 if scrubbed and placeheld and idempotent and raw_dirty else 1)
PY
then ok "RAG boundary scrubs PII before chunking; re-ingest is byte-idempotent (content-hash intact)"
else bad "PA3 failed — RAG leg leaked PII or broke idempotency"; fi

# ---------------------------------------------------------------------------
sect "PA4 (load-bearing): the security workload passes through UNCHANGED (0% FP)"

if run_py <<'PY'
import sys
from agent import pii
# Legitimate security content + non-card numeric identifiers that MUST NOT be touched.
neg = [
    "' OR 1=1-- UNION SELECT username,password FROM Users",
    "<script>alert(document.cookie)</script>",
    "../../../../etc/passwd",
    "Traceback (most recent call last): SequelizeDatabaseError near syntax error",
    "sha256=" + "a"*64,                       # file-hash territory (64-hex)
    "0192023a7bbd73250516f069df18b500",       # bare 32-hex MD5 (UUID-hex territory)
    "session_id=4408041234567893",            # 16 digits, no card label (Luhn may pass)
    "user_id=4532015112830366",               # Luhn-valid PAN but NON-card label
    "offset 4111111111111111 in buffer",      # bare 16-digit, no label at all
]
changed = [(s, pii.redact(s)[0]) for s in neg if pii.redact(s)[0] != s]
print(f"  false-positives={len(changed)}")
for s, out in changed:
    print(f"    FP: {s!r} -> {out!r}")
sys.exit(0 if not changed else 1)
PY
then ok "SQLi/XSS/traversal/stack-trace/hashes/non-card numeric IDs all pass unchanged (0% FP)"
else bad "PA4 failed — the redactor mangled legitimate security content (decision 0006 violation)"; fi

# ---------------------------------------------------------------------------
printf '\n== summary ==\n'
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
