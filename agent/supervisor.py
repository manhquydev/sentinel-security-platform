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
- **D2 — the `interrupt()` seam.** `interrupt_seam_node` is inert this week: it takes no
  action and exists only so a future state-changing branch (Week-8 HITL) has a proven pause
  point to attach to. `tests/syndicate-test.sh` (I6) fires and resumes it so it cannot rot.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from contextlib import contextmanager
from typing import Any, Iterator, TypedDict

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, StateGraph
from langgraph.types import interrupt

from . import exploit, fuzz, recon, trace
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
    # L1: gates `interrupt_seam_node`. PR1 never sets this (always False/absent), so a normal
    # run flows straight through to END without pausing. Week-8's HITL state-changing branch
    # will set it True before this node runs; I6 sets it explicitly to keep the seam exercised.
    pending_state_change: bool


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
        with _threaded_model(state.get("model", "sast-sol")):
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
        with _threaded_model(state.get("model", "sast-sol")):
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
                                    model=state.get("model", "sast-sol"))

    dumped = [p.model_dump() for p in proposals]
    for p in dumped:
        _redact_proposal(p)
    return {"exploit_proposals": dumped}


def interrupt_seam_node(state: SyndicateState) -> dict[str, Any]:
    """Reserved for the Week-8 HITL state-changing branch (decision D2/0013). Gated on
    `pending_state_change` (L1): PR1 never sets it, so this is a no-op and the graph reaches
    END normally on every run this week — it no longer pauses unconditionally. Only when a
    future branch sets `pending_state_change=True` before this node runs does it actually call
    `interrupt()` and wait for a `Command(resume=...)`."""
    if not state.get("pending_state_change"):
        return {}
    interrupt({"seam": "pre-state-change", "note": "reserved for Week-8 HITL; no action taken"})
    return {"interrupt_ack": True}


# --- graph assembly / entry point -----------------------------------------------------------


def build_graph(checkpointer: SqliteSaver):
    g = StateGraph(SyndicateState)
    g.add_node("recon", recon_node)
    g.add_node("fuzz", fuzz_node)
    g.add_node("exploit", exploit_node)
    g.add_node("interrupt_seam", interrupt_seam_node)
    g.set_entry_point("recon")
    g.add_edge("recon", "fuzz")
    g.add_edge("fuzz", "exploit")
    g.add_edge("exploit", "interrupt_seam")
    g.add_edge("interrupt_seam", END)
    return g.compile(checkpointer=checkpointer)


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


def run_syndicate(thread_id: str, *, model: str = "sast-sol", use_llm: bool = True,
                   checkpointer: SqliteSaver | None = None) -> dict[str, Any]:
    """Run (or continue) the Supervisor graph for one thread. A brand-new `thread_id` seeds the
    budget at zero; an EXISTING thread_id must not resupply `budget` in the input (D11) — see
    the module docstring. The first call against a thread pauses at `interrupt_seam` only once a
    future branch sets `pending_state_change=True` (PR1: it never does, so this reaches END).

    L1: when `checkpointer` is omitted, this function opens its OWN connection via
    `default_checkpointer()` for the duration of this call and closes it before returning — the
    SQLite state is durable on disk, so a later call against the same `thread_id` simply reopens
    the same file; nothing about resume depends on holding the connection open between calls.
    Leaving it open per call would leak a connection/fd on every invocation with no explicit
    checkpointer (e.g. the CLI or a library caller that never passes one). A caller that DOES
    pass its own `checkpointer` keeps ownership of its lifecycle; this function never closes it."""
    owns_checkpointer = checkpointer is None
    checkpointer = checkpointer or default_checkpointer()
    try:
        graph = build_graph(checkpointer)
        cfg = {"configurable": {"thread_id": thread_id}}
        existing = graph.get_state(cfg)
        init: SyndicateState = {"model": model, "use_llm": use_llm}
        if not (existing.values or {}).get("budget"):
            init["budget"] = {"total_requests_sent": 0, "target_max": fuzz.MAX_TOTAL_REQUESTS}
        return graph.invoke(init, config=cfg)
    finally:
        if owns_checkpointer:
            checkpointer.conn.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Run the Week-6 Supervisor graph (Recon -> Fuzz -> Exploit(sim)).")
    ap.add_argument("--thread", default="cli", help="checkpoint thread id (reuse to resume)")
    ap.add_argument("--no-llm", action="store_true", help="deterministic run only")
    ap.add_argument("--model", default=os.environ.get("RECON_MODEL", "sast-sol"))
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
