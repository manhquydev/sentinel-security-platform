# 0017 Week-9 PII redaction is structural at capture, measured not trusted; real dumps are simulated

Date: 2026-07-24

## Status

Accepted (Week-9 shipped — the redactor, the capture control, the RAG boundary, and the measurement;
real state-changing dumps remain deferred with Week-8/decision 0016).

## Context

Week 9 is "Data Privacy & PII Redaction": if the pentest dumps a DB of mock users, the PII must be
redacted from the agent's memory and logs before it reaches central logging or the RAG store. A
four-lens red-team of the first plan (assumption-destroyer + failure-mode NOT-CLEAN,
scope-complexity TRIM, security-adversary CLEAN) proved, in code, that the charter's literal surface
does not exist as built and that the naive "four legs over three gateway-bypassing sinks" framing was
mostly false:

- **No live dump surface.** The Exploit agent never executes (structural containment, `agent/exploit.py`);
  the fuzzer reduces response bodies to signal-kinds + a bounded error-signature slice before anything
  persists (`agent/fuzz_signals.py`, `agent/supervisor.py`); the RAG ingests only static
  owasp/nvd/attack-surface records — no path routes agent runtime output into it.
- **The sink inventory was wrong.** The simulated dump reaches ONE real durable sink set — the
  checkpoint, the approval-audit `detail` row, and stdout/stderr — not a Phoenix span (that node has
  no span) and not `rag.ingest`. `egress_redaction` is imported nowhere in `agent/`, and the
  agent-side secret scrub has no JWT/UUID, so "reuse the gateway detectors" was not real.
- **A vacuous measurement risk.** The Week-7 FP corpus is untracked/gitignored and the existing FP
  harness measures the old egress detectors, so a "0% FP" could pass over an absent corpus — the
  project's own journaled failure mode.

## Decision

**Redaction is a narrow, structural detector applied AT CAPTURE, over a simulated dump, and its
residual is measured — never trusted.**

- **Detection is narrow deterministic regex (`agent/pii.py`), not ML/NER.** Presidio was rejected
  (a 460 MB transformer, a first-use model download that breaks air-gapped operation, and NER false
  positives on security vocabulary with no published FP baseline); a hybrid/NER path is deferred
  (names are absent from the target's mock data). `agent/pii.py` carries its own detectors — email,
  Luhn-checked credit-card PAN under a card-ish label anchor, JWT, UUID — each a structural shape
  match, never "suspicious-looking" content, so the legitimate SQLi/XSS/traversal/stack-trace/file-hash
  workload passes untouched (the decision-0006 constraint, measured).
- **The control is scrub-at-capture in the existing `state_change_node`.** The simulated (dry-run)
  action returns a synthetic mock-users dump — the only place target-shaped data enters the runtime.
  It is run through the full persist-scrub (secrets → target-raw → PII, PII last) and its PII classes
  are counted for the audit, BEFORE the value enters graph state, the audit ledger, or any print. This
  one structural point covers the checkpoint, the audit `detail`, and stdout/stderr; `state_change_result`
  is never routed through `redact_persisted` elsewhere, so capture is its only protection.
- **Defense-in-depth backstops, honestly labelled.** The PII pass is composed into the SHARED scalar
  scrub that both `redact_persisted` (checkpoint/audit) and `_scrub_value` (spans) call — so any
  narrative field that does reach a span/checkpoint is covered, not only the checkpoint. `rag/ingest.py`
  scrubs `doc.text` before chunking (preserving the content-hash idempotency) so any future PII-bearing
  source is scrubbed at the RAG boundary. Neither is the dump's live sink; both are stated as backstops.
- **W9-D2a — the unsalted MD5 password VALUE is redacted, the finding preserved.** The value is a
  crackable credential, removed by the existing `password`-assignment credential pass; the "weak
  unsalted hashing" finding survives via the class label + column + endpoint, which never needed the
  literal digest. No bare-32-hex detector is added — a hyphenless 32-hex is UUID-hex territory and a
  bare-hex rule would false-positive on legitimate hashes and fail the workload-integrity gate.
- **Measurement, not assertion.** Two independent numbers over a committed SYNTHETIC corpus
  (`evaluation/pii-redaction/`): recall on the shapes policy says must be redacted (1.0 on covered
  shapes) and false-positive/alteration on legitimate security content (0). Documented gap shapes
  (bare positional PAN, phone) are tracked, never counted against recall. The guard FAILS CLOSED if
  the corpus is absent — no vacuous 0% FP.

- The **gateway-egress PII leg is cut** this increment (defense-in-depth off the dump's path; the card
  detector is the highest FP risk on security content — not worth the decision-0006 risk now).

## Consequences

- The checkpoint, the approval ledger, the console, the spans, and the RAG boundary never carry a raw
  target email, PAN, JWT, UUID, or crackable password hash; the redactor's residual is a committed,
  regression-guarded number, not a claim.
- **Deferred (each an explicit decision first):** bare-PAN recall in positional multi-row SQL results
  (bound to real execution, decision 0016); name/location PII via a local NER (revisit if recall on
  covered shapes drops); a gateway-egress PII leg (only once its FP on security content is measured at
  0); scanner→lake import-path PII (a separate surface). Streaming-response egress redaction remains
  the pre-existing documented gap.
