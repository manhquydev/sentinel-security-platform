# 2026-07-24 — Week-9: the PII surface that had to be built, then measured

Shipped Week-9 (real-time PII redaction) through the full gated pipeline
(scout → research → advise → plan-TDD → 4-lens red-team → validate → implement → review/audit → fix).
Decision 0017.

## What shipped

`agent/pii.py` — narrow deterministic PII detectors (email, Luhn-checked card under a label anchor,
JWT, UUID), its own module because `egress_redaction` is imported nowhere in `agent/` and the
agent-side secret scrub has no JWT/UUID. Scrub-AT-CAPTURE in the existing Week-8 `state_change_node`
over a synthetic fixture dump, covering the one real sink set (checkpoint, approval-audit `detail`,
stdout). PII composed into the SHARED trace scrub so both the checkpoint and span paths are covered.
RAG-boundary scrub before chunking. A measured residual (recall vs FP) with a fail-closed corpus gate.

## Lessons worth keeping

- **For the THIRD week running, the red-team's job was to correct the scope, not the code.** The
  literal charter surface ("the pentest dumps a DB → redact the PII") does not exist: the Exploit
  agent never executes, the fuzzer reduces bodies to signal-kinds + a bounded error-signature slice
  before anything persists, and RAG ingests only static records. So Week-9 had to *build* a
  simulated dump to have any PII to redact — and the honest version of that is a fixture-backed
  dry-run on the Week-8 seam, not a new node or a reversal of the 0016 containment.
- **The plan's "obvious" sink inventory was two-thirds wrong, and only reading the code found it.**
  The first draft claimed the dump reached three gateway-bypassing sinks (checkpoint, Phoenix spans,
  RAG). Against the code: only the checkpoint receives it; `state_change_node` creates no span, and
  no path routes graph state into `rag.ingest`. The real sinks the draft *missed* were the approval
  audit row and stdout. "Where does this value actually go?" is a code question, not a design one.
- **A measurement over an absent corpus is the same lie as no measurement.** The Week-7 FP corpus is
  untracked/gitignored and its harness measures the *old* detectors — so a reused "0% FP" would have
  passed over nothing (this repo has journaled that exact failure before). Week-9 commits a synthetic
  corpus and makes the guard fail closed when it's missing, with a negative control that proves it.
- **Structure over detection, again.** Scrubbing at capture closes the prompt-injection smuggling
  channel by construction — the LLM never sees raw PII, so it has nothing to reformat. The MD5
  password *value* goes via the existing credential pass; the weak-hashing *finding* survives via the
  class label — no bare-32-hex detector, because that would false-positive on UUID-hex and break the
  decision-0006 workload-integrity gate that PA4 enforces at 0 FP.
- **Verify, don't trust — including your own subagents' silence.** Both the code-review and
  security-audit subagents completed their analysis but died on a transient API error at the
  report-writing step, persisting nothing. Re-running risked the same failure, so the review/audit
  were finished directly with empirical probes — which found one real evasion (a dot/underscore-
  separated PAN under a label) the earlier lenses hadn't, now fixed and re-verified.

## Deferred (named, not forgotten)

- Bare-PAN recall in positional multi-row SQL results (bound to real execution, decision 0016).
- Name/location PII via a local NER (revisit only if recall on covered shapes drops).
- A gateway-egress PII leg (ship only once its FP on security content is measured at 0).
- Scanner→lake import-path PII (a separate surface). Streaming-response egress remains the
  pre-existing documented gap.
