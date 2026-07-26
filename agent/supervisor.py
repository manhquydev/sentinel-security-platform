"""The Supervisor graph: Recon -> (map-consuming) Fuzz -> Exploit(sim), hand-rolled `StateGraph`
(Week 6, decision D2). Durable, redacted, budget-bounded, and reserving an `interrupt()` seam for
the Week-8 HITL state-changing branch.

Design load-bearing points (see docs/plans/active/2026-07-24-...):

- **D7 — state is explicitly JSON-serializable.** `SyndicateState` carries only typed, JSON-
  native fields; `recon.build_map()`'s `AttackSurfaceMap` and `fuzz.run()`'s `FuzzReport` are
  stored as plain dicts (`.model_dump()` / hand-mapped), never as the dataclass/pydantic
  objects themselves. Model config is threaded through STATE (`state["model"]`), not left to
  the ambient `os.environ` the reused `recon.py`/`fuzz.py` read internally — `_threaded_model`
  bridges state -> env only for the duration of the reused call.
- **D5 — checkpoint redaction is a hard gate.** Nothing this module hands to the checkpointer
  carries a raw target-derived string or a secret: fuzz findings are stored as
  `{endpoint, param, payload_class, signal_kinds, counts}` (the raw truncated payload and the
  raw per-signal "reason" text are DROPPED, only the signal *kind* survives). Every free-text
  field that DOES persist (recon `analysis`, endpoint `notes`, every `Finding.title` in both
  `endpoints[].findings` and `app_level_findings`, fuzz `guidance`, exploit `technique` /
  `justification` / `expected_impact`) is LLM narrative synthesized over target-derived input,
  not operator-authored (0006/MF2) — so each one runs through `trace.redact_persisted()`, the
  same secret-AND-target-raw scrub the span path uses. The exploit narrative fields ALSO pass
  through `agent/exploit.py`'s own runnable-payload scrub (E3, a DISTINCT, best-effort concern —
  see that module's docstring for exactly what it does and does not cover) before this redaction
  ever runs. The two layers cover different, non-overlapping vocabularies (this pass: secrets +
  target-raw markers; E3: runnable state-changing/script/shell syntax) — neither is a substitute
  for the other, and NEITHER is the safety control: the exploit agent never executing anything
  (D3/D4) is. This pass runs regardless so a persisted narrative is never worse-redacted just
  because it came from the exploit node instead of recon/fuzz.
- **D3/D4 — Exploit(sim) is contained by import, not by promise.** `exploit_node` calls
  `agent.exploit.propose()`, which imports only `agent.llm` and `agent.schema` — no
  `agent.gateway`, no `requests`/`httpx`/socket (`tests/syndicate-test.sh` E1 asserts this
  statically) — so it is structurally incapable of reaching the target itself; it only reads the
  fuzz findings this module already redacted and makes one narrative LLM call. `verdict` is
  fixed `suspected-needs-hitl` in the schema itself (E2): this agent proposes, Week-8 HITL
  decides.
- **D11 — the request budget lives IN the checkpointed state**, and `run_syndicate()` only
  seeds it on a brand-new thread. LangGraph merges an `invoke()`'s input dict over whatever a
  thread already has checkpointed, so re-supplying `budget` on a second call against the SAME
  thread_id would silently reset it back to zero — the exact re-arm bug this module's tests
  (I4) assert against. `fuzz_node` also refuses to call `fuzz.run()` again once the persisted
  counter has already reached the ceiling, as a second, independent line of defense.
- **D2 — the `interrupt()` seam.** `interrupt_seam_node` is inert unless BOTH
  `pending_state_change` is set AND `exploit_proposals` is non-empty — `tests/syndicate-test.sh`
  (I6) exercises the pause/resume mechanics with `pending_state_change=True` but no proposals
  (its fixtures yield none), so it still reaches END afterward exactly as before; that is not a
  special case for the test, it is the real rule — there is nothing to gate approval over when no
  proposal exists.
- **Week-8 PR1 — the HITL approval gate (RD1-RD5, `agent/approval.py`/`agent/approve.py`).** When
  a run DOES have both `pending_state_change=True` and a non-empty `exploit_proposals`,
  `interrupt_seam_node` pauses `interrupt()` with the first proposal attached, and a
  `Command(resume=<token>)` routes into `state_change_node` (see `_route_after_interrupt`) instead
  of straight to END. That node verifies the resume value as a signed `ApprovalToken` using ONLY
  the Ed25519 PUBLIC verify key (`agent/approval.py::load_public_key`) — it has no code path that
  can mint a valid token itself (self-approval is structurally impossible, not policy-forbidden).
  On success it performs a SIMULATED dry-run (`SIMULATED: would execute ...`, no gateway/requests/
  network call, no target mutation) and appends to the audit ledger BEFORE logging that line; on
  any failure (missing/forged/expired/replayed/proposal-mismatched token) it raises rather than
  silently no-op, so the action never runs and a bug that reaches this node without a real
  approval is loud. The real token-minting CLI (`agent/approve.py`) is a SEPARATE, human-run
  process this module never imports — see that module's docstring for the out-of-process
  boundary and the honest single-shared-user-host residual.
- **`resume_state_change` — the sanctioned way to resume a paused seam.** LangGraph's
  `Command(resume=...)` treats a dict whose keys all look like interrupt ids as a per-interrupt
  resume MAP rather than a literal value — and an EMPTY dict satisfies that check vacuously, so a
  bare `graph.invoke(Command(resume={}), config=cfg)` (the natural way to express "resume with no
  token") delivers no value to `interrupt_seam_node`'s `interrupt()` call at all: it silently
  re-pauses at the SAME seam instead of ever reaching `state_change_node`, so nothing is raised or
  audited — a LangGraph resume-routing quirk `state_change_node` cannot see or guard against from
  inside a node. `resume_state_change` closes that gap: if the graph is STILL interrupted right
  after a resume attempt, it itself records a `refused` audit row against the pending proposal and
  raises, so this one remaining "quiet nothing happened" path can't be mistaken for success.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from contextlib import contextmanager
from typing import Any, Iterator, TypedDict

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, StateGraph
from langgraph.types import Command, interrupt

from . import approval, exploit, fuzz, pii, recon, sim_dump, trace
from .schema import AttackSurfaceMap

CHECKPOINT_PATH = os.path.join(os.path.dirname(__file__), "out", "syndicate.sqlite")


class SyndicateState(TypedDict, total=False):
    """D7: every field here is JSON-native. `graph.invoke()`'s return value additionally carries
    a transient `__interrupt__` key while paused at `interrupt_seam` — that key is LangGraph's
    own pause marker (wrapping a non-JSON `Interrupt` object), not a `SyndicateState` field, and
    it is never part of the checkpointed state itself (`graph.get_state(cfg).values` never
    carries it). Callers that need to serialize the result should drop that key first."""

    model: str
    use_llm: bool
    recon_map: dict[str, Any] | None
    fuzz_report: dict[str, Any] | None
    exploit_proposals: list[dict[str, Any]] | None
    budget: dict[str, int]
    interrupt_ack: bool
    # L1: gates `interrupt_seam_node`. A normal run never sets this (always False/absent), so it
    # flows straight through to END without pausing. Week-8's HITL branch sets it True before
    # this node runs; I6 sets it explicitly (with no proposals) to keep the seam exercised
    # without engaging the real approval gate below.
    pending_state_change: bool
    # Week-8 PR1 (RD1/RD3): the value LangGraph's `Command(resume=...)` delivered at the
    # `interrupt_seam` pause point — expected to be a signed `ApprovalToken.to_dict()` when a real
    # state-change is being approved, but this field accepts whatever a caller resumes with (D7:
    # JSON-native only) and `state_change_node` is what actually validates its shape/signature.
    approval_token: dict[str, Any] | None
    # Set by `state_change_node` on a valid approval; absent/None on every other run.
    state_change_result: dict[str, Any] | None
    # Optional overrides threaded through state (D7: no ambient env for this), so tests can point
    # `state_change_node` at an isolated keypair/ledger without touching agent/keys or agent/out.
    approval_pubkey_path: str
    approval_db_path: str


# --- state <-> reused-module bridging ---------------------------------------------------------


@contextmanager
def _threaded_model(model: str) -> Iterator[None]:
    """`recon.py`/`fuzz.py` (reused as-is) resolve their model via `os.environ["RECON_MODEL"]`.
    The graph threads the model through STATE instead (D7); this sets the env var only for the
    duration of the reused call and restores whatever was there before."""
    prior = os.environ.get("RECON_MODEL")
    os.environ["RECON_MODEL"] = model
    try:
        yield
    finally:
        if prior is None:
            os.environ.pop("RECON_MODEL", None)
        else:
            os.environ["RECON_MODEL"] = prior


def _redact_finding(f: dict[str, Any]) -> None:
    """`Finding.title` (`schema.py`) is copied straight from a lake finding — Trivy/Nuclei/etc.
    scanner output ABOUT the target, so it is target-influenced by construction (HF1). Redact
    in place through the full secret+target-raw scrub; benign titles like "SQL Injection" (the
    vulnerability CLASS name) are untouched since neither pattern matches that shape — only an
    actually-injected marker (`UNION SELECT`, a stack-trace signature, a traversal string) is."""
    if f.get("title"):
        f["title"] = trace.redact_persisted(f["title"])


def _redact_map(m: AttackSurfaceMap) -> dict[str, Any]:
    """D5/HF1/MF2: every free-text field the map carries is LLM narrative over target-derived
    input, not operator-authored fact — `analysis` is the recon LLM's synthesis over finding
    titles, `notes` is the same per-endpoint, and every `Finding.title` (endpoint-attributed AND
    app-level — `app_level_findings` is where MOST findings land by design, per `recon.py`, and
    is iterated here so it is not silently left unredacted) is scanner output about the target.
    All go through `trace.redact_persisted()` (secrets AND target-raw), matching the span path."""
    d = m.model_dump()
    if d.get("analysis"):
        d["analysis"] = trace.redact_persisted(d["analysis"])
    for ep in d.get("endpoints", []):
        if ep.get("notes"):
            ep["notes"] = trace.redact_persisted(ep["notes"])
        for f in ep.get("findings", []):
            _redact_finding(f)
    for f in d.get("app_level_findings", []):
        _redact_finding(f)
    return d


def _redact_fuzz_report(report: fuzz.FuzzReport) -> dict[str, Any]:
    """D5: drop the raw truncated payload and the raw per-signal reason text; keep only the
    signal *kind* (e.g. "stack_trace") and how many times it fired for that finding. `guidance`
    is the fuzz LLM's synthesis over target-derived response signals (HF1/MF2), so it gets the
    full secret+target-raw scrub, not just the secret pass."""
    findings = []
    for f in report.findings:
        kinds = [s.split(":", 1)[0].strip() for s in f.signals]
        counts: dict[str, int] = {}
        for k in kinds:
            counts[k] = counts.get(k, 0) + 1
        findings.append({
            "endpoint": f.endpoint,
            "param": f.param,
            "payload_class": f.payload_class,
            "signal_kinds": sorted(set(kinds)),
            "counts": counts,
        })
    return {
        "targets": list(report.targets),
        "requests_sent": report.requests_sent,
        "findings": findings,
        "signal_counts": dict(report.signal_counts),
        "guidance": trace.redact_persisted(report.guidance) if report.guidance else None,
    }


def _redact_proposal(p: dict[str, Any]) -> None:
    """D5, same rule as every other persisted narrative field: `technique`/`justification`/
    `expected_impact` are LLM narrative synthesized over the (already-redacted) fuzz findings
    (D3), so they get the full secret+target-raw scrub before the checkpoint sees them — on top
    of, not instead of, `agent/exploit.py`'s own runnable-payload scrub (E3), which already ran
    before this function is called. `endpoint`/`vuln_class`/`signal_kinds`/`verdict` are code-
    derived facts (D3), not model output, so they are left as-is."""
    for field in ("technique", "justification", "expected_impact"):
        if p.get(field):
            p[field] = trace.redact_persisted(p[field])


# --- graph nodes --------------------------------------------------------------------------


def recon_node(state: SyndicateState) -> dict[str, Any]:
    use_llm = bool(state.get("use_llm", True))
    with trace.node_span("recon", use_llm=use_llm):
        with _threaded_model(state.get("model", "sast-grok45")):
            m = recon.build_map(use_llm=use_llm)
    return {"recon_map": _redact_map(m)}


def fuzz_node(state: SyndicateState) -> dict[str, Any]:
    budget = dict(state.get("budget") or {"total_requests_sent": 0, "target_max": fuzz.MAX_TOTAL_REQUESTS})

    if budget["total_requests_sent"] >= budget["target_max"]:
        # D11: this thread's checkpointed budget already reached the ceiling in a prior
        # invocation — a resume must not re-arm it by calling fuzz.run() again.
        with trace.node_span("fuzz", budget_exhausted=True):
            pass
        empty: dict[str, Any] = {
            "targets": [], "requests_sent": 0, "findings": [], "signal_counts": {},
            "guidance": None, "budget_exhausted": True,
        }
        return {"fuzz_report": empty, "budget": budget}

    surface_map: AttackSurfaceMap | None = None
    if state.get("recon_map"):
        try:
            surface_map = AttackSurfaceMap.model_validate(state["recon_map"])
        except Exception as e:  # noqa: BLE001 - a malformed persisted map must not crash the run
            print(f"  fuzz_node: recon_map failed to validate, fuzzing unguided: {e}", file=sys.stderr)

    use_llm = bool(state.get("use_llm", True))
    with trace.node_span("fuzz", use_llm=use_llm, map_guided=surface_map is not None):
        with _threaded_model(state.get("model", "sast-grok45")):
            report = fuzz.run(use_llm=use_llm, surface_map=surface_map)

    budget["total_requests_sent"] += report.requests_sent
    return {"fuzz_report": _redact_fuzz_report(report), "budget": budget}


def exploit_node(state: SyndicateState) -> dict[str, Any]:
    """D3/D4: `exploit.propose()` only reads the fuzz findings this graph already redacted
    (`fuzz_node` ran before this node) and makes one narrative LLM call — it never touches the
    target. `model` is passed directly as a function argument (D7) rather than threaded through
    `os.environ` the way `recon.py`/`fuzz.py` are, since `exploit.py` is Week-6-native code, not
    a reused module that only knows how to read the ambient env."""
    fuzz_report = state.get("fuzz_report") or {}
    use_llm = bool(state.get("use_llm", True))
    with trace.node_span("exploit", use_llm=use_llm,
                          findings=len(fuzz_report.get("findings") or [])):
        proposals = exploit.propose(fuzz_report, use_llm=use_llm,
                                    model=state.get("model", "sast-grok45"))

    dumped = [p.model_dump() for p in proposals]
    for p in dumped:
        _redact_proposal(p)
    return {"exploit_proposals": dumped}


def interrupt_seam_node(state: SyndicateState) -> dict[str, Any]:
    """Gated on `pending_state_change` (L1): a normal run never sets it, so this is a no-op and
    the graph reaches END directly. When it IS set, this pauses `interrupt()` with the first
    exploit proposal attached (PR1: one proposal per HITL round — selecting among several is a
    future extension, not needed for this gate to be real) so a human/out-of-process approver can
    see exactly what they are approving, and waits for `Command(resume=<value>)`. The resume value
    is threaded into `approval_token` verbatim; `_route_after_interrupt` below decides whether
    that value gets a chance to mean anything (only when there was a real proposal to approve)."""
    if not state.get("pending_state_change"):
        return {}
    proposals = state.get("exploit_proposals") or []
    proposal = proposals[0] if proposals else None
    resume_value = interrupt({
        "seam": "pre-state-change",
        "note": "Week-8 HITL: resume with a signed ApprovalToken (agent/approve.py) to proceed",
        "proposal": proposal,
    })
    return {"interrupt_ack": True, "approval_token": resume_value}


def _route_after_interrupt(state: SyndicateState) -> str:
    """Only route into `state_change_node` when there is BOTH an active HITL request
    (`pending_state_change`) AND an actual proposal to gate (`exploit_proposals` non-empty) — a
    `pending_state_change=True` run with no proposal (e.g. `tests/syndicate-test.sh` I6's
    fixtures, which yield zero findings) has nothing to approve, so it reaches END exactly as
    every pre-Week-8 run did; this is the correct rule, not a carve-out to keep I6 passing."""
    if state.get("pending_state_change") and state.get("exploit_proposals"):
        return "state_change"
    return END


def state_change_node(state: SyndicateState) -> dict[str, Any]:
    """Week-8 PR1's HITL gate consumer (RD1-RD4). Only reachable via `_route_after_interrupt`,
    i.e. only when a proposal actually exists to gate. SIMULATED, not real (RD2): on a valid
    token this logs "SIMULATED: would execute ..." and appends one audit row — it makes no
    gateway/requests/network call and mutates no target. Fail-closed (RD3): without a token that
    verifies (real Ed25519 signature over THIS exact proposal, not expired, not already
    consumed), it RAISES rather than silently no-op, so a bug that reaches this node without a
    genuine approval is loud, not swallowed. Idempotent under a LangGraph re-run of this node
    (RD4): `approval.verify_approval` consumes the token's nonce atomically and ONLY on full
    success, so a second execution with the SAME resume value finds the nonce already consumed
    and refuses — the simulated action can only ever "happen" (and be audited) once per token."""
    proposals = state.get("exploit_proposals") or []
    proposal = proposals[0] if proposals else None
    token = state.get("approval_token")
    pid = approval.proposal_id(proposal) if proposal else "<no-proposal>"

    pubkey_path = state.get("approval_pubkey_path") or approval.DEFAULT_PUBKEY_PATH
    db_path = state.get("approval_db_path") or approval.DEFAULT_DB_PATH
    ledger = approval.ApprovalLedger(db_path)
    try:
        if proposal is None or not isinstance(token, dict):
            ledger.record(proposal_id=pid, action="refused",
                          detail="state_change_node reached with no proposal or no token")
            raise PermissionError(
                "state_change_node: no proposal/token present — refusing (fail-closed)")

        try:
            pubkey = approval.load_public_key(pubkey_path)
            verified = approval.verify_approval(token, proposal, pubkey, ledger)
        except Exception as e:  # noqa: BLE001 - an approval-infra failure (missing/corrupt pubkey
            # file, a non-IntegrityError sqlite error) must be a LOUD, AUDITED, fail-closed refusal,
            # never an un-audited raw raise that could read as "something else broke" (code-review
            # M1/M2). The action still never runs.
            try:
                ledger.record(proposal_id=pid, action="refused",
                              detail=f"approval infrastructure error — refusing (fail-closed): {type(e).__name__}")
            except Exception:  # noqa: BLE001 - if the ledger itself is the failure, still fail closed
                pass
            raise PermissionError(
                f"state_change_node: approval check errored for {pid!r} — refusing (fail-closed)") from e
        if not verified:
            ledger.record(proposal_id=pid, action="refused",
                          detail="approval token failed verification (bad signature, expired, "
                                 "already consumed, or bound to a different proposal)")
            raise PermissionError(
                f"state_change_node: invalid approval token for {pid!r} — refusing (fail-closed)")

        endpoint = proposal.get("endpoint")

        # Week-9 (decision 0017): the simulated (dry-run) action "returns" a synthetic mock user
        # dump — the ONLY place target-shaped data enters this runtime. Scrub it AT CAPTURE, before
        # the value is placed in state, audited, or printed, so the checkpoint, the audit `detail`,
        # and stderr below all carry redacted text or class-counts only — never a raw email, PAN, or
        # crackable password hash. `state_change_result` is never routed through `redact_persisted`
        # elsewhere, so THIS is its only protection: apply the full persist-scrub (secrets +
        # target-raw + PII, PII last) that every other checkpointed field already gets, and record
        # the PII class-counts separately for the audit. The dump is serialized multi-line so the
        # line-bounded credential rule scrubs one field at a time (the `password` MD5 value goes;
        # the weak-hashing finding survives via class label + endpoint, W9-D2a).
        _pretty_dump = json.dumps(sim_dump.SIMULATED_USER_DUMP, indent=2)
        scrubbed_dump = trace.redact_persisted(_pretty_dump)
        pii_findings = pii.redact(_pretty_dump)[1]
        pii_classes = ",".join(f"{f.cls}={f.count}" for f in sorted(pii_findings, key=lambda f: f.cls)) or "none"

        # Audit BEFORE the simulated action (RD4/HA4) — the token is already consumed above, so
        # this row is the durable record of the one and only time this token will ever authorize
        # anything. Only the redacted class-counts are recorded, never the dumped values.
        ledger.record(proposal_id=pid, action="simulated-execute",
                      detail=f"SIMULATED: would execute proposal against {endpoint}; "
                             f"dump PII redacted at capture [{pii_classes}]")
        print(f"SIMULATED: would execute proposal {pid} vs {endpoint} "
              f"(vuln_class={proposal.get('vuln_class')}) — no network call, no target mutation; "
              f"dump PII redacted at capture [{pii_classes}]",
              file=sys.stderr)
        return {"state_change_result": {"proposal_id": pid, "endpoint": endpoint, "simulated": True,
                                        "dump": scrubbed_dump, "pii_redacted": pii_classes}}
    finally:
        ledger.close()


# --- graph assembly / entry point -----------------------------------------------------------


def build_graph(checkpointer: SqliteSaver):
    g = StateGraph(SyndicateState)
    g.add_node("recon", recon_node)
    g.add_node("fuzz", fuzz_node)
    g.add_node("exploit", exploit_node)
    g.add_node("interrupt_seam", interrupt_seam_node)
    g.add_node("state_change", state_change_node)
    g.set_entry_point("recon")
    g.add_edge("recon", "fuzz")
    g.add_edge("fuzz", "exploit")
    g.add_edge("exploit", "interrupt_seam")
    g.add_conditional_edges("interrupt_seam", _route_after_interrupt,
                            {"state_change": "state_change", END: END})
    g.add_edge("state_change", END)
    return g.compile(checkpointer=checkpointer)


def resume_state_change(graph: Any, cfg: dict[str, Any], resume_value: Any) -> dict[str, Any]:
    """The sanctioned way to resume a paused `interrupt_seam` for Week-8 HITL (RD3/RD4) — prefer
    this over a bare `graph.invoke(Command(resume=...), config=cfg)`. See the module docstring's
    `resume_state_change` bullet for why the bare call alone is not sufficient: an EMPTY dict
    resume value (the natural way to express "no token") is swallowed by LangGraph's own
    per-interrupt resume-map heuristic before `state_change_node` ever runs, so no code inside the
    graph gets a chance to raise or audit it.

    This wrapper invokes the resume and, if the graph is STILL paused at an interrupt immediately
    afterward, treats that as a refused resume: it records one audit row against the pending
    proposal and raises `PermissionError`, so a caller can never observe "nothing happened" as if
    it were a quiet success. When the resume DOES reach `state_change_node` (every other
    missing/forged/expired/replayed/proposal-mismatched token shape), that node's own fail-closed
    raise+audit already applies and this wrapper simply returns/re-raises whatever it produced."""
    result = graph.invoke(Command(resume=resume_value), config=cfg)
    if "__interrupt__" not in result:
        return result

    proposal = result["__interrupt__"][0].value.get("proposal")
    pid = approval.proposal_id(proposal) if proposal else "<no-proposal>"
    db_path = result.get("approval_db_path") or approval.DEFAULT_DB_PATH
    ledger = approval.ApprovalLedger(db_path)
    try:
        ledger.record(
            proposal_id=pid, action="refused",
            detail="resume attempt did not deliver a usable value (e.g. an empty resume value, "
                   "which LangGraph treats as an empty per-interrupt resume map rather than a "
                   "literal token) — state_change_node was never reached; refusing (fail-closed)")
    finally:
        ledger.close()
    raise PermissionError(
        f"resume_state_change: resume for {pid!r} did not advance past interrupt_seam — "
        "refusing (fail-closed)")


def default_checkpointer(path: str = CHECKPOINT_PATH) -> SqliteSaver:
    """A durable, gitignored (`agent/out/`) SQLite checkpoint. The returned `SqliteSaver.conn` is
    this function's caller's to close — `run_syndicate` closes it itself when IT is the one that
    opened it (see below, L1); a caller that keeps a `SqliteSaver` alive across multiple
    `run_syndicate` calls (tests, a long-lived process) owns closing `saver.conn` when done."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    saver = SqliteSaver(conn)
    saver.setup()
    return saver


def run_syndicate(thread_id: str, *, model: str = "sast-grok45", use_llm: bool = True,
                   checkpointer: SqliteSaver | None = None) -> dict[str, Any]:
    """Run (or continue) the Supervisor graph for one thread. A brand-new `thread_id` seeds the
    budget at zero; an EXISTING thread_id must not resupply `budget` in the input (D11) — see
    the module docstring. This convenience wrapper never sets `pending_state_change` itself, so a
    call through it always reaches END; the Week-8 HITL gate is exercised by callers that build
    the graph directly (`build_graph`) and invoke with `pending_state_change=True` (see
    `tests/week8-hitl-test.sh` / `tests/syndicate-test.sh` I6).

    L1: when `checkpointer` is omitted, this function opens its OWN connection via
    `default_checkpointer()` for the duration of this call and closes it before returning — the
    SQLite state is durable on disk, so a later call against the same `thread_id` simply reopens
    the same file; nothing about resume depends on holding the connection open between calls.
    Leaving it open per call would leak a connection/fd on every invocation with no explicit
    checkpointer (e.g. the CLI or a library caller that never passes one). A caller that DOES
    pass its own `checkpointer` keeps ownership of its lifecycle; this function never closes it."""
    from . import finops  # Week-11: per-run cost/token/latency metering (decision 0019)

    owns_checkpointer = checkpointer is None
    checkpointer = checkpointer or default_checkpointer()
    try:
        graph = build_graph(checkpointer)
        cfg = {"configurable": {"thread_id": thread_id}}
        existing = graph.get_state(cfg)
        init: SyndicateState = {"model": model, "use_llm": use_llm}
        if not (existing.values or {}).get("budget"):
            init["budget"] = {"total_requests_sent": 0, "target_max": fuzz.MAX_TOTAL_REQUESTS}
        with finops.run_meter(thread_id) as meter:
            result = graph.invoke(init, config=cfg)
        # Attach the run's FinOps accounting to the return value (not persisted state). Costs are
        # zero when use_llm=False (no gateway calls) — the accounting still records that honestly.
        return {**result, "finops": meter.report()}
    finally:
        if owns_checkpointer:
            checkpointer.conn.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Run the Week-6 Supervisor graph (Recon -> Fuzz -> Exploit(sim)).")
    ap.add_argument("--thread", default="cli", help="checkpoint thread id (reuse to resume)")
    ap.add_argument("--no-llm", action="store_true", help="deterministic run only")
    ap.add_argument("--model", default=os.environ.get("RECON_MODEL", "sast-grok45"))
    args = ap.parse_args(argv)

    result = run_syndicate(args.thread, model=args.model, use_llm=not args.no_llm)
    fr = result.get("fuzz_report") or {}
    rm = result.get("recon_map") or {}
    proposals = result.get("exploit_proposals") or []
    print(f"Syndicate run (thread={args.thread!r}) — endpoints: {len(rm.get('endpoints', []))}"
          f"  fuzz targets: {fr.get('targets')}  requests: {fr.get('requests_sent')}"
          f"  findings: {len(fr.get('findings', []))}  exploit proposals: {len(proposals)}")
    for p in proposals:
        print(f"    {p.get('endpoint')} [{p.get('vuln_class')}] verdict={p.get('verdict')}")
    if "__interrupt__" in result:
        print("  paused at interrupt_seam (reserved for Week-8 HITL)")
    # Week-11 FinOps: per-run cost/token/latency + cost-spike/drift alerting (decision 0019)
    from . import finops
    fin = result.get("finops") or {}
    if fin:
        lat = fin.get("latency_s", {})
        print(f"  FinOps: calls={fin['calls']} tokens={fin['total_tokens']} "
              f"cost~=${fin['cost_estimate_usd']:.4f} (estimate) latency={lat.get('total')}s "
              f"errors={fin['errors']}")
        for a in finops.check_thresholds(fin):
            print(f"  \033[33mALERT\033[0m FinOps budget breach: {a['metric']} "
                  f"{a['actual']} > {a['ceiling']} (over by {a['over_by']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
