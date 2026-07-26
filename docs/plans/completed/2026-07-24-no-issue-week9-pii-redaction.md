# Execution Plan: Week-9 Data Privacy & PII Redaction (TDD)

Date: 2026-07-24

## Status

**Complete (2026-07-24)** — shipped and validated: `agent/pii.py` + scrub-at-capture in
`state_change_node` + PII-aware shared trace scrub + RAG boundary + `evaluation/pii-redaction/`
measurement. Tests green: `tests/week9-pii-redaction-test.sh` 5/0 (incl. real end-to-end
approved-dump run), `tests/week9-pii-eval-test.sh` 2/0 (recall 9/9, FP 0/10, fail-closed corpus
gate); zero regressions across W1–W8 suites. Review/audit: SHIP (one LOW evasion found + fixed).
Decision 0017. History below (red-team-reconciled v2).

---

Four-lens red-team ran
2026-07-24 (reports `plans/reports/redteam-260724-2158-week9-{assumption-destroyer,failure-mode,
scope-complexity,security-adversary}.md`): assumption-destroyer NOT-CLEAN, failure-mode NOT-CLEAN,
scope-complexity TRIM, security-adversary CLEAN. Every blocking finding is resolved below; the
scope is trimmed to the honest control. Research base:
`plans/reports/researcher-260724-2145-week9-pii-redaction.md`.

Accepted user scope (2026-07-24) is unchanged in intent — *build a real simulated PII-dump surface,
redact in real time, and MEASURE* — but the red-team corrected HOW: the "four co-equal legs over
three gateway-bypassing sinks" framing was false against the code, so v2 is **one primary control
(scrub-at-capture) + honestly-labelled backstops**, which delivers the same accepted outcome without
the theater.

### What the red-team changed (all blocking items resolved)
1. **The dump reaches ONE real durable sink set, via the existing node — not three.** `state_change_node`
   already exists behind the tested Week-8 seam (`agent/supervisor.py:303-361`) and returns a result
   dict → checkpoint. It does NOT reach a Phoenix span (that node has no `node_span`) and there is NO
   path from graph state to `rag.ingest` (`rag/ingest.py` reads only static owasp/nvd/attack-surface
   sources). → **Reuse `state_change_node`; do not add a node. Drop the "three bypassing sinks" claim.**
2. **Real sink inventory (corrected & complete):** checkpoint state; the **approval-audit `detail`**
   row (`agent/approval.py:174`, already routed through `redact_persisted`); and **stdout/stderr**
   `print()` (covered by NO existing redactor). Phoenix span *names* are passed raw
   (`agent/trace.py:175`) — keep dump text out of names, attributes only.
3. **`agent/pii.py` carries its OWN detectors.** `egress_redaction` is imported nowhere in `agent/`
   or `rag/`; the agent-side scrub `trace.py::_SECRET_PATTERNS` (trace.py:43-59) has **no JWT and no
   UUID**. So "reuse JWT/UUID from egress" was false — `agent/pii.py` implements email, Luhn-card,
   JWT, UUID itself and is the single module used at capture, composed into trace, and at the RAG
   boundary.
4. **Egress leg (old W9-D6) CUT.** Off the dump's path, self-labelled defense-in-depth, duplicates
   existing gateway integration, and the card detector is the highest-FP-risk shape — not worth the
   decision-0006 risk this increment. Deferred with reason.
5. **The FP measurement must not be vacuous.** The Week-7 FP corpus (`benchmark/targets/webgoat-src`,
   `scanners/out/`) is untracked/gitignored, and the existing `measure-false-positives.py` measures
   the OLD egress detectors, never `agent.pii`. → Week-9 ships its OWN measurement over `agent.pii`
   with a **committed synthetic FP corpus** + a `REQUIRE_CORPUS`-style presence gate, so "0% FP"
   cannot pass over an absent corpus (the journal's documented failure mode).
6. **W9-D2a (MD5) resolved — redact the value, context-anchored; NO bare-hex detector** (see W9-D2a).

## Why this scope (the honest surface finding — unchanged, confirmed by the red-team)

The charter's literal Week-9 scenario ("pentest dumps a DB of mock users → redact PII before memory/
logs/RAG") has **no live surface** in the system as built: the Exploit agent never executes
(structural containment, `agent/exploit.py`); the fuzzer reduces bodies to signal-kinds + a bounded
error-signature slice before anything persists (`agent/fuzz_signals.py`, `agent/supervisor.py` D5);
RAG ingests only static records. So Week-9 **creates** the surface — a fixture-backed simulated dump
on the existing HITL seam — and builds + measures the redaction control over the one real sink set
that dump reaches. Real target mutation stays deferred (decision 0016).

## Outcome

When the syndicate's HITL-approved simulated action yields mock PII (emails, Luhn-valid card PANs,
JWT/UUID session tokens, and unsalted MD5 password hashes present in Juice-Shop-shaped mock data),
that PII is **scrubbed at the moment of capture in `state_change_node`, before the result enters
graph state, the return value, the approval-audit row, or any print** — so it can never reach the
checkpoint, the audit ledger, or the console. The redactor's residual is **measured** — recall on a
planted-PII set and false-positive/alteration on a committed security corpus — not asserted.
Observable when:

- a simulated dump carrying planted PII leaves every durable sink PII-free (checkpoint, audit
  `detail`, stdout), each with a negative control (the raw fixture fails the same assertion);
- the redactor does NOT mangle the security workload — SQLi/XSS/traversal payloads, stack traces,
  32-char and 64-char hex hashes, and long numeric IDs pass through unchanged (measured FP 0%);
- a committed measurement reports recall AND FP with a CI regression guard that fails closed when the
  corpus is absent.

## Scope

### In scope
1. **`agent/pii.py`** — a pure detector/redactor module (no litellm/network import, mirroring
   `egress_redaction.py`/`trace.py` testability). Own detectors: **email**, **credit-card PAN**
   (13–19 digits, Luhn-valid, redacted only under a card-ish label anchor — see H3), **JWT**
   (`eyJ…` three-segment), **UUID** (RFC 4122). Returns `(scrubbed_text, findings)` so callers can
   audit *what class* was removed (never the value/hash). Runs **last**, after any secret/target-raw
   pass (ordering — see M1).
2. **Primary control — scrub-at-capture in the existing `state_change_node`** (`agent/supervisor.py`):
   the fixture dump is serialized and run whole through `agent.pii` BEFORE the value is placed in
   state, returned, logged, or written to the audit — one structural point covering checkpoint +
   audit + stdout. Handles int-typed fields (H1) by scrubbing the serialized row, and free-text
   columns (H2) by scrubbing the whole row, not named columns.
3. **Backstops (defense-in-depth, honestly labelled — NOT the dump's live sinks):**
   - `agent/trace.py` — compose the `agent.pii` pass into the **shared scalar scrub** that BOTH
     `redact_persisted` (checkpoint/audit) AND `_scrub_value` (spans) call, so any narrative field
     that *does* reach a span/checkpoint gains PII coverage (fixes B2 — not `redact_persisted` alone).
   - `rag/ingest.py` — scrub `doc.text` through `agent.pii` **before `_chunks_for`** (so the keep-hash
     matches the stored content — M2, preserves ON CONFLICT idempotency). Guards the charter's "before
     the RAG database" boundary for any future PII-bearing source; labelled DiD, not a live dump sink.
4. **Measurement (`evaluation/pii-redaction/`):** a committed **synthetic** planted-PII corpus
   (documented Luhn-valid *test* PANs, `@juice-sh.op` addresses, synthetic JWTs) with an in-file
   provenance assertion (A3); a recall runner over `agent.pii`; and a **PII-FP** runner over a
   committed synthetic security corpus (numeric-heavy: long IDs, 32/64-hex hashes, SQLi/XSS payloads)
   with structural oracles ("this token cannot be an email/card"). Corpus-presence gate; committed
   baseline; CI regression guard.
5. One decision record (`docs/decisions/0017-…`), README status + journal updates.

### Non-goals / deferred (named)
- **Gateway-egress PII leg** (old W9-D6) — deferred; the card detector's FP risk on security content
  isn't worth shipping off the dump path this increment.
- Real state-changing execution / real DB dump (deferred, decision 0016). **Bare-card recall** (PANs
  in positional multi-row SQL results with no per-row label) is bound as a 0016 precondition (H5) —
  the fixture uses labelled rows, which is what a real dump-to-LLM prompt carries.
- **Name/location PII via NER** (hybrid) — deferred; names absent from Juice Shop data, NER adds
  FP risk on security vocabulary (research §1.3). Gate: revisit if recall on covered shapes drops.
- Streaming-response egress redaction (pre-existing documented gap; unchanged).
- Scanner→lake import-path PII (separate surface; note, don't build).

## TDD invariants (tests-first; PA-series)

- **PA1 (capture → all real sinks)** a dump carrying planted email/card/JWT/UUID/MD5-password →
  checkpoint state, the approval-audit `detail` row, AND captured stdout/stderr are all PII-free;
  negative control: the raw fixture fails each assertion. (Covers B-findings on the true sink set.)
- **PA2 (span/checkpoint backstop)** a narrative field routed through the shared trace scrub is
  PII-free at BOTH `redact_persisted` and `_scrub_value` (span) exporters; negative control on the
  raw field. (Fixes B2 — proves the span path isn't blind.)
- **PA3 (RAG boundary DiD)** a source doc with planted PII is PII-free in the chunk text reaching
  embed+insert, AND re-ingesting the same doc prunes/inserts **zero** chunks (idempotency intact —
  M2); negative control on the raw doc.
- **PA4 (workload integrity — load-bearing, decision 0006)** SQLi/XSS/traversal payloads, stack
  traces, 32-char MD5 and 64-char SHA hashes, hyphenless-UUID-shaped 32-hex, and long numeric IDs
  (e.g. `session_id=4408041234567893`) pass through `agent.pii` UNCHANGED. Measured FP 0% (H3).
- **PA5 (measurement honesty, non-vacuous)** recall reported over a corpus that INCLUDES the
  admitted-gap shapes (so misses show — H4), FP reported over the committed security corpus; the
  guard **fails closed if the corpus is absent** (B3) and on any recall drop / alteration rise.
- **PA6 (fail-closed, no bypass)** the capture scrub is structural in `state_change_node` — no code
  path (exception, partial result, int/free-text field, a `print(rows)` before the scrub) returns or
  emits an un-scrubbed value; **stdout negative control** included (A6). Existing W1–W8 suites green.

## Design decisions (W9-D#)

- **W9-D1 — fixture-backed dry-run on the EXISTING HITL seam.** Reuse `state_change_node` (Week-8);
  no new node, no real execution/target-client/network (decision 0016). Fixture = a small committed
  **synthetic** mock-users table (Luhn-valid test PANs + `@juice-sh.op` + synthetic hashes), with an
  in-file provenance note asserting it is not scraped real data (A3).
- **W9-D2 — detection = narrow deterministic regex in `agent/pii.py` (own detectors).** Presidio
  rejected (460 MB transformer, first-use download breaks air-gapped, NER FP on security vocab, no
  FP baseline — research §1.1); hybrid deferred. `agent/pii.py` implements email, Luhn-card
  (label-anchored), JWT, UUID; MD5 password value handled via the existing password-assignment path
  (W9-D2a). Structural shape match only — never "suspicious-looking" — the discipline the Week-7
  harness measures at zero FP.
- **W9-D2a — MD5 password-hash value: REDACT (context-anchored); NO bare-32-hex detector.**
  Evidence (`egress_redaction.py`): `password=<md5>` is ALREADY `[redacted:password]` today because
  `password` is in the assignment-key list; a bare hyphenless 32-hex (UUID-shaped) is left unchanged
  — proving a bare-hex detector would false-positive. So the crackable value is removed via the
  existing context-anchored machinery, the weak-hashing **finding survives** via class label + column
  + endpoint, and PA4 stays green. This overrides the earlier tentative "lean preserve."
- **W9-D3 — one detector module, three enforcement points, honestly ranked.** `agent/pii.py` is the
  single source; capture is the PRIMARY control; trace + RAG are labelled backstops. No duplication.
- **W9-D4 — placeholder + per-class audit, never the value.** Redacted PII → `[redacted:pii:<class>]`;
  `agent.pii` returns findings so the node records *which class/count* was removed. No value, no
  length that reconstructs it, no hash (short-PII hashes are brute-forceable — egress_redaction's own
  reasoning). Count-only hints match existing safe precedent (security-adversary A2).
- **W9-D5 — measurement: own harness, committed corpora, presence-gated.** Recall ≥ threshold on the
  planted set (incl. gap shapes); FP 0% unambiguous / <5% alteration on the committed security corpus
  via structural oracles; thresholds pinned from the first real run; guard fails closed on absent
  corpus. Does NOT reuse the Week-7 harness verbatim (it measures the wrong detectors — B4).
- **W9-D6 — CUT** (was: gateway-egress leg). Deferred; reason recorded above.
- **M1 (ordering) — PII pass runs LAST**, after secret/target-raw, so the greedy secret-assignment
  rule (`[^\r\n]+`, trace.py:57) cannot swallow a PII placeholder + the rest of the line.

## Files

Create:
- `agent/pii.py` — pure PII detector/redactor (own email/card/JWT/UUID; returns `(text, findings)`).
- `tests/fixtures/mock_users_dump.json` (or `.py`) — synthetic labelled mock-users fixture + provenance note.
- `evaluation/pii-redaction/` — committed synthetic recall corpus + security FP corpus + recall &
  FP runners + committed baseline.
- `tests/week9-pii-redaction-test.sh` — UNIT PA1–PA4, PA6 (negative controls incl. stdout) + LIVE
  (REQUIRE_AGENT) end-to-end dump→sinks.
- `tests/week9-pii-eval-test.sh` — PA5 measurement + corpus-presence gate + regression guard.
- `docs/decisions/0017-week9-pii-redaction-is-structural-at-capture-measured-not-trusted.md`.

Modify:
- `agent/supervisor.py` — scrub-at-capture in the existing `state_change_node` (W9-D1/PA1/PA6);
  ensure no pre-scrub print.
- `agent/trace.py` — compose the PII pass into the SHARED scalar scrub both `redact_persisted` and
  `_scrub_value` use (B2/PA2), PII-last (M1).
- `rag/ingest.py` — scrub `doc.text` before `_chunks_for` (PA3/M2).
- `README.md` status + `docs/journal/` entry + `docs/decisions/README.md`.

NOT modified (was in v1): `infra/litellm/guardrails/` — egress leg cut.

## Validation

- `bash tests/week9-pii-redaction-test.sh` (UNIT green offline; LIVE under REQUIRE_AGENT=1).
- `bash tests/week9-pii-eval-test.sh` (recall + FP within committed thresholds; **fails closed if
  corpus absent**).
- Regression green: `tests/redaction-guarantee-test.sh`, `tests/syndicate-test.sh`,
  `tests/week8-hitl-test.sh`, `tests/week7-*-test.sh`, `tests/agent-model-egress-contract-test.sh`.
- Interpreter: `rag/.venv/bin/python` for all agent/rag tests (repo convention).

## Risks & rollback

- **R1 — FP on the security workload** (decision 0006's thesis; the central risk). Mitigated by PA4
  as a hard gate over a numeric-heavy corpus, the label-anchored card detector (H3), and cutting the
  egress leg. A detector that can't clear FP is dropped, not shipped mangling.
- **R2 — vacuous measurement over an absent corpus** (the journal's documented failure). Mitigated by
  committing synthetic corpora in-repo + the corpus-presence gate (PA5/B3).
- **R3 — tautological recall.** Mitigated by including admitted-gap shapes in the recall corpus (H4).
- **R4 — Luhn false-positive on non-card 16-digit IDs** (H3). Mitigated by requiring a card-ish label
  anchor AND Luhn, and by PA4's `session_id=<16-digit>` negative case.
- **R5 — int/free-text field bypass** (H1/H2). Mitigated by scrubbing the serialized whole row.
- **R6 — RAG idempotency break** (M2). Mitigated by scrubbing `doc.text` before hashing/chunking.
- Rollback: additive placeholders; revert the capture scrub + `trace.py`/`rag.ingest` compose points
  to restore prior behavior. No schema/store migration.

## Cook pipeline (per user directive)

implement (tests-first) → code-review → STRIDE/security audit → brainstorm any residual → fix →
loop until green + reviewed. Suggested PR boundary if splitting (scope-complexity): PR1 =
`agent/pii.py` + capture-at-capture + PA1/PA4/PA6 + FP measurement; PR2 = recall-eval + RAG boundary
+ decision/journal. Single PR acceptable (≈ Week-5 size after trims).
