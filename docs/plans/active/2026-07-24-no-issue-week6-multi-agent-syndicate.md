# Execution Plan: Week-6 Multi-Agent Pentest Syndicate (TDD)

Date: 2026-07-24

## Status

Active — plan CLEAN (red-team + validate resolved); **PR1 implemented, reviewed, audited, fixed,
verified GREEN**. Remaining: PR1 docs + PR, then PR2 (Exploit-sim).

## Outcome

A LangGraph-orchestrated multi-agent syndicate — **Supervisor + Recon + Fuzz + Exploit(sim)** —
that runs end-to-end against the loopback Juice Shop target, wires the Week-4 Recon and Week-5 Fuzz
pipelines into a real producer→consumer flow, adds a read-only/simulated Exploit agent, and traces
the agent-to-agent flow to a self-hosted Phoenix plane with **redacted payloads only**, preserving
every existing safety control. Delivered as two reviewable PRs. Observable when:

- the Supervisor graph runs Recon → **Fuzz consuming the Recon map** → Exploit(sim), each node's
  every model call traversing the LiteLLM gateway (server-side provenance + redaction), **sending
  nothing state-changing to the target**;
- durable state is checkpointed with **redacted / ID-only** content (no raw target text or secrets
  on disk), and the graph reserves a **tested** `interrupt()` seam for Week-8 HITL;
- the agent-to-agent flow is traced to Phoenix (loopback-bound, manual OTel graph spans) with a
  **working** span redactor that strips secrets AND target-raw text;
- the suite proves every invariant with a negative control, and existing suites stay green.

## Context

- Charter: `docs/Project_Sentinel_VinUni_x_VinSOC_12-week.md` (Week 6; skills S2 multi-agent + S6
  observability).
- Trigger decision: `docs/decisions/0012-...-langgraph-deferred.md` (Week 6 = LangGraph trigger).
- Reused nodes: `agent/recon.py::build_map()->AttackSurfaceMap`, `agent/fuzz.py::run()->FuzzReport`,
  `agent/schema.py`, `agent/gateway.py`, `agent/llm.py`.
- Safety baseline (must not regress): decisions 0006 (provenance enforced **server-side at the
  gateway**), 0009 (Agent IAM), 0013 (read-only fuzzing; state-change reserved for Week-8 HITL).
- Existing observability: Langfuse (traces+redacts every LLM call via the gateway); egress redaction
  `infra/litellm/.../egress_redaction.py` **preserves** attack/target payloads by design — so the
  Phoenix target-raw redactor is a DISTINCT concern, not a reuse.
- Reports: research `plans/reports/researcher-260724-1118-week6-...md`; red-team
  `plans/reports/redteam-260724-1118-week6-*.md`; state `plans/reports/scout-260724-1118-...md`.

## User decisions (advise + post-red-team re-confirmation, 2026-07-24)

1. Framework = **LangGraph now, done right** (accept: checkpoint redaction, JSON-serializable state,
   langchain-core/venv compat, a test that fires `interrupt()`).
2. Exploit Agent = **read-only / simulated**; real exploitation gated to Week-8 HITL (0013).
3. Observability = **Phoenix, done right** (manual OTel graph spans, loopback+auth, working
   secret+target-raw span redactor, redacted checkpoint) — a NEW plane alongside Langfuse.
4. Increment = **incremental PRs** (PR1 supervisor + wired Recon→Fuzz + observability; PR2 Exploit-sim).

## Design decisions (research + brainstorm + red-team, 2026-07-24)

- **D1 — The gateway is the provenance chokepoint; nodes use `agent/llm.py`, and a NEW model-egress
  contract test enforces it.** Provenance+redaction are enforced SERVER-SIDE at the LiteLLM gateway
  (`sentinel_guardrail.py:119-141`), so the real invariant is "no `agent/` code reaches a model
  except through the gateway." A new test `tests/agent-model-egress-contract-test.sh` (distinct from
  the existing lake `tests/import-contract-test.sh`, which guards `import-report.sh` — do not
  conflate) fails if any `agent/` module imports a direct LLM SDK or references the router API base.
  `llm.py` remains the labelled door.
- **D2 — Hand-rolled `StateGraph`** (explicit linear flow, less magic to audit).
- **D3 — Exploit(sim) = facts-by-code + one narrative LLM call**; proposals are technique
  descriptions (no runnable state-changing payload strings in git); `verdict` fixed
  `suspected-needs-hitl`; the narrative is scrubbed/validated so an injected runnable payload cannot
  land verbatim.
- **D4 — Structural containment:** `agent/exploit.py` imports no network/gateway client (test-asserted).
- **D5 — Trace + checkpoint redaction is a hard gate, DISTINCT from egress redaction.** A working OTel
  span processor strips secrets AND target-raw text before export; the SqliteSaver checkpoint stores
  only IDs / already-redacted content (raw `FuzzReport` payloads never hit disk; every retained
  free-text field — recon `analysis`, endpoint `notes`, every `Finding.title` in both
  `endpoints[].findings` and `app_level_findings`, fuzz `guidance` — runs through the same
  secret-AND-target-raw scrub as the span path via `trace.redact_persisted()`). Tests assert no
  secret AND no target-raw pattern in spans or the checkpoint DB (corrected after code review/
  STRIDE audit HF1/H1/H2: the initial implementation only secret-scrubbed these fields and never
  iterated `app_level_findings` at all — fixed, with a non-vacuous I3 negative control).
- **D6 — Versions pinned by a live spike.** Real current `langgraph` (≈1.2.9, hard-requires
  `langchain-core`) + Phoenix/OTel resolved in Phase 0; direct deps version-pinned in
  `agent/requirements.txt`, full transitive resolution captured as a `pip freeze` lock in
  `agent/requirements.lock`. The Phoenix container image IS digest-pinned (`@sha256`,
  `infra/phoenix/docker-compose.yml`). Full `--require-hashes` integrity pinning for the Python
  lock is a tracked FOLLOW-UP (needs `pip-compile --generate-hashes` / `uv pip compile
  --generate-hashes`), corrected from an earlier overstated claim after code review (MF4/M1).
- **D7 — State is explicitly JSON-serializable.** The graph state carries typed, JSON-native fields;
  the fuzz `Finding` dataclass is renamed to avoid collision with `schema.Finding`; model config is
  threaded through state, not ambient `os.environ`.
- **D8 — Real dependency-compat analysis in the SHARED `rag/.venv` (hard gate).** `recon.py` does
  `from rag import ...` (`recon.py:71`), and `agent/requirements.txt` is `-r ../rag/requirements.txt`
  — so the agent MUST share `rag/.venv`; a dedicated agent env would break RAG imports. langgraph +
  langchain-core + Phoenix/OTel must therefore coexist with rag's heavy pins (numpy 2.5.1 /
  onnxruntime / fastembed / pydantic 2.13.4). Phase 0 verifies this **before any code**; on an
  irreconcilable conflict, STOP and resolve (pin negotiation or a subprocess/service boundary) —
  do not force-install.
- **D9 — Map→Fuzz is really wired AND adds signal.** The map's `EndpointSurface` has no `parameters`
  field (`schema.py:42-50`) and recon/fuzz currently apply the same `public`+`read-only` baseline
  filter — so scoping alone is cosmetic. Real wiring (no frozen-schema change): `fuzz.run()` consumes
  the map to (a) scope targets to the map's endpoints, resolving query params from the baseline the
  map cites (`provenance.attack_surface_baseline`), and (b) **prioritize** payload-classes by
  the map's per-endpoint findings/CWEs (e.g. an injection-class CWE steers injection payloads first).
  Backward-compatible: `run()` keeps its `baseline_path` default so the standalone Week-5 path still
  works. Honest scope of "prioritize" (corrected after code review, H2): at the current
  `MAX_REQUESTS_PER_TARGET=40` vs `len(CORPUS)==18`, per-target truncation never bites, so
  reordering the corpus cannot change WHICH payloads run, `requests_sent`, or the finding set —
  it changes real SEND ORDER, which is what a kill-switch or a tighter future budget actually
  consumes. `FuzzReport.payload_order` makes that order observable; an invariant calls
  `fuzz.run(surface_map=...)` directly (not just the reordering helper in isolation) and asserts
  the injection classes land earlier in `payload_order` under an injection-CWE map than under an
  unguided/non-injection-CWE map.
- **D10 — Phoenix binds loopback only, behind the repo's loopback bar**; a gate asserts the binding.
- **D11 — Budget/kill-switch persists across checkpoint resume** so a resumed run cannot re-arm the
  full request budget (0013 bound holds under resume). Plus a graph-level token/iteration budget.
- **D12 — LangSmith telemetry stays hard-off (air-gap).** `langchain-core` pulls `langsmith`
  transitively; the agent must never set `LANGCHAIN_TRACING_V2`/`LANGCHAIN_API_KEY`. A test asserts
  the syndicate makes no outbound connection to a `langchain`/`langsmith` host; tracing goes only to
  the loopback Phoenix + the existing Langfuse path.

### Phase 0 result (verified 2026-07-24) — GATE PASSED

Non-destructive resolver check (`pip download -c rag/requirements.txt`, never touched `rag/.venv`):
`langgraph==1.2.9` (real current — the research's `0.0.37` was stale) requires `langchain-core 1.5.1`
which resolves `pydantic` to **2.13.4** and `requests` to **2.34.2** — rag's EXACT pins, no conflict;
`numpy`/`onnxruntime`/`fastembed` untouched (Phoenix server is Docker; only OTel client libs pulled:
`opentelemetry-sdk==1.44.0`, `opentelemetry-exporter-otlp-proto-grpc==1.44.0`,
`langgraph-checkpoint-sqlite==3.1.0`, `openinference-semantic-conventions==0.1.30`). Direct deps pinned
in `agent/requirements.txt`; the full resolution is captured as a version-pinned (not hash-pinned)
`pip freeze` lock in `agent/requirements.lock` — a `--require-hashes` integrity lock is a tracked
follow-up, not generated yet (corrected per MF4/M1; the lock file header now says so honestly).

## Scope

**PR1 — Supervisor + wired Recon→Fuzz + observability:** `agent/supervisor.py` (StateGraph,
SqliteSaver with redacted state, tested inert `interrupt()` seam, graph budget), map→fuzz wiring
(`agent/fuzz.py` gains map consumption), Phoenix wiring (compose/systemd unit loopback-bound + OTel
graph spans + working redaction processor), import-contract test, `tests/syndicate-test.sh`
invariants, docs.
**PR2 — Exploit(sim):** `agent/exploit.py`, `ExploitProposal` contract, its invariants, docs.
Out of scope: real state-changing exploitation (Week-8 HITL), broadening `agent-recon` ACL, PII
redaction engine (Week 9), guardrail/IPI hardening beyond the existing contract (Week 7), vLLM/FinOps.

## TDD Approach (tests-first; red → green per phase)

**Phase 0 — Spike: pin reality (shared).** In a decided venv (D8): resolve+install actual current
`langgraph` + `langgraph-checkpoint-sqlite` + Phoenix/OTel; run a real compat check against
`rag/.venv` pins; confirm imports; stand up Phoenix loopback-bound and confirm a manual OTLP span
lands. Gate: versions pinned+hash-pinned in `agent/requirements.txt`; compat verdict recorded.

**PR1 phases:**
- **P1.1 RED — contracts + failing invariants.** Write: I1 model-egress contract
  (`tests/agent-model-egress-contract-test.sh`: no direct LLM SDK / router-base reference in
  `agent/`); I2 supervisor runs recon→(map-consuming)fuzz yielding typed JSON-serializable state;
  I3 checkpoint DB contains no secret AND no target-raw pattern; I4 budget persists across a simulated
  resume (no re-arm); I5 Phoenix spans contain no secret AND no target-raw pattern; I6 `interrupt()`
  seam fires and resumes in a test; I7 Phoenix bound to loopback; I8 bounded live e2e recon→fuzz.
  Each with a negative control. All failing.
- **P1.2 GREEN — map→fuzz wiring** (D9): `fuzz.run()` consumes the map; pass the map-consumption
  invariant.
- **P1.3 GREEN — supervisor graph** (D2/D7/D11): StateGraph, redacted SqliteSaver state, threaded
  model config, graph budget, tested `interrupt()` seam; pass I2/I4/I6.
- **P1.4 GREEN — Phoenix observability** (D5/D10): loopback unit, manual OTel graph spans, working
  secret+target-raw redaction processor; pass I3/I5/I7.
- **P1.5 — model-egress contract + live e2e + no-regression:** pass I1/I8; existing suites green.
- **P1.6 — cook loop:** implement → code-review → STRIDE audit → brainstorm findings → fix → re-verify.
- **P1.7 — docs + PR1:** README Status (W4–6, clears drift), decision record (multi-agent + Phoenix +
  D1 gateway-chokepoint); small PR.

**PR2 phases:**
- **P2.1 RED — Exploit contracts + invariants.** `ExploitProposal` (`extra=forbid`, verdict Literal);
  E1 exploit module imports no network client; E2 verdict always HITL-gated; E3 narrative scrubbed of
  runnable payloads; E4 exploit consumes FuzzReport → ≥1 proposal from a real signal. Failing.
- **P2.2 GREEN — `agent/exploit.py`** to pass E1–E4; wire as a graph node.
- **P2.3 — cook loop + docs + PR2.**

## Risks And Recovery

- **Framework/transitive client bypasses the gateway.** Mitigation: D1 import-contract test (I1).
- **Checkpoint/trace leaks target text or secrets to disk.** Mitigation: D5 redacted state + working
  redactor; I3/I5 assert no secret AND no target-raw.
- **Resume re-arms the request budget.** Mitigation: D11; I4.
- **Dependency incompatibility in the shared venv.** Mitigation: D8 Phase-0 compat gate before code.
- **Phoenix exposed off-loopback.** Mitigation: D10; I7.
- **Inert seam rots.** Mitigation: I6 fires it now.
- **Additive**: new `agent/supervisor.py`, `agent/exploit.py`, tests, Phoenix config, docs; Weeks 1–5
  code changes limited to the `fuzz.run()` map-consumption seam (backward-compatible default).

## Progress

- [x] Scout state vs charter; W1–5 verified green live.
- [x] Advise (4) + research + design decisions (D1–D11).
- [x] Plan `--tdd` written.
- [x] Red-team pass (4 reviewers): 2 Crit / 8 High / 5 Med adjudicated; escalations re-confirmed by user.
- [x] Validate pass (3 findings resolved) + whole-plan consistency sweep (no contradictions).
- [x] Plan CLEAN → cleared to cook.
- [x] Phase 0 spike — dependency-compat HARD GATE **PASSED**; deps pinned in `agent/requirements.txt`.
- [x] PR1 — implemented + independently verified GREEN (model-egress 10/0, syndicate 14/0 incl.
  live e2e recon→map-guided-fuzz, fuzz-engine 4/0, gateway-authz 29/0, no regression). Files:
  `agent/supervisor.py`, `agent/trace.py`, `agent/fuzz.py` (map consumption), `infra/phoenix/`,
  `tests/{syndicate,agent-model-egress-contract}-test.sh`. Report:
  `plans/reports/fullstack-260724-1159-week6-pr1-syndicate.md`.
- [x] PR1 cook loop closed — code-review (2 High/2 Med/2 Low) + STRIDE audit (2 High/4 Med/2 Low)
  findings fixed: HF1/H1/H2 (target-raw scrub extended to every persisted narrative field incl.
  `app_level_findings`, previously unredacted entirely), MF1 (secret-keyword regex no longer
  truncates at the first token), MF2/M1 (provenance labels corrected), MF3/M4 (LangSmith air-gap
  covers `LANGSMITH_TRACING`/`LANGSMITH_API_KEY`), MF4/M1 (D6 lock claim corrected to
  version-pinned only), HF2/H2 (`payload_order` makes prioritization's real send-order effect
  observable and I2 proves it against `fuzz.run()` output, not just the reorder helper), L1
  (`interrupt_seam` gated on `pending_state_change`, no longer fires on every run; `run_syndicate`
  closes the connection it opens itself). syndicate 16/0, egress 12/0, fuzz-engine 4/0,
  recon-agent 9/0, recon-tools 3/0, gateway-authz 29/0 — all green. Report:
  `plans/reports/fullstack-260724-1239-week6-pr1-fixes.md`.
- [ ] PR1 docs + PR.
- [ ] PR2 (P2.1–P2.3) — Exploit(sim).

## Decisions

- 2026-07-24: User decisions 1–4 (above), re-confirmed after red-team added new evidence. Design
  decisions D1–D11 fold in every accepted red-team fix.

## Validation

- Focused: `tests/syndicate-test.sh` invariants I1–I8 (PR1), E1–E4 (PR2), each with a negative control.
- Integration/e2e: bounded live Recon→(map-consuming)Fuzz[→Exploit-sim] via Kong; Phoenix trace
  loopback-bound + redacted.
- Repo-required: existing suites stay green.

## Red Team Review

### Session — 2026-07-24
**Findings:** 15 after dedup (4 reviewers). **Severity:** 2 Critical, 8 High, 5 Medium.
**Verdict at review time: NOT CLEAN.** Reports: `plans/reports/redteam-260724-1118-week6-*.md`.
Root causes: **R1** observability plane didn't compose with the raw-`requests` client + duplicated
audited Langfuse redaction; **R2** Recon→Fuzz "guided by map" was unwired.

| # | Finding | Sev | Disposition → resolution |
|---|---------|-----|--------------------------|
| 1 | Recon→Fuzz "guided by map" unwired (`fuzz.py:82`, `recon.py:90`) | Crit | Accept → D9 (P1.2) + map-consumption invariant |
| 2 | SqliteSaver checkpoint writes unredacted target text to disk | Crit | Accept → D5 redacted/ID-only state; I3 |
| 3 | Phoenix can't see raw-`requests` calls → I5 vacuous | Crit | Accept → D5 manual OTel graph spans (not auto-instr) |
| 4 | Phoenix redundant with Langfuse for LLM-call tracing | High | Accept (scoped) → Phoenix traces GRAPH flow (new capability); LLM-call tracing stays Langfuse |
| 5 | D1 door is discipline not a control (gateway is server-side) | High | Accept → D1 import-contract test; I1 |
| 6 | langgraph hard-requires langchain-core; venv compat unknown | High | Accept → D6/D8 Phase-0 compat gate |
| 7 | Serialization impedance + colliding `Finding` types | High | Accept → D7 JSON-native state + rename fuzz Finding |
| 8 | Resume re-arms fuzz budget → breaches 0013 | High | Accept → D11; I4 |
| 9 | Research redaction processor mutates immutable attrs | High | Accept → D5 working processor; I5 |
| 10 | egress redaction preserves target text → can't meet claim | High | Accept → D5 DISTINCT target-raw redactor |
| 11 | Phoenix binds 0.0.0.0 no auth | High | Accept → D10; I7 |
| 12 | LangGraph over-applies to linear flow (0012 YAGNI) | High | Escalated → **user kept LangGraph, done right** |
| 13 | Four-agent one-pass violates git-workflow.md | High | Escalated → **user chose incremental PRs** |
| 14 | Inert `interrupt()` dead code | Med | Accept → I6 fires it |
| 15 | Graph budget / narrative scrub / integrity pins / flaky I6 / ambient env | Med | Accept → D3/D6/D7/D11 + deterministic fixtures |

Escalations 3,4,9,10,11 (observability) resolved by user Decision A = **Phoenix done right**.
Escalation 12 by Decision B = **LangGraph done right**. Escalation 13 by Decision C = **incremental**.

## Validation Log

### Session — 2026-07-24
Guard: `## Red Team Review` already carries `file:line` evidence, so the heavy re-verification was
skipped; this pass verified the NEW resolution claims (D1–D11) against the codebase. No user
interview needed — the genuine decision points were settled at advise + post-red-team. Three
feasibility findings, all resolved into the plan (none reverses a decision):

| # | Claim checked | Result | Resolution |
|---|---------------|--------|------------|
| VF1 | D1 reuses `tests/import-contract-test.sh` | FAILED — that file guards the lake `import-report.sh`, not model egress | D1 now specs a DISTINCT `tests/agent-model-egress-contract-test.sh` |
| VF2 | D9 fuzz derives targets "from the map" | PARTIAL — map `EndpointSurface` has no `parameters` (`schema.py:42-50`); recon+fuzz share the same baseline filter, so scoping alone is cosmetic | D9 refined: fuzz scopes to map endpoints, resolves params from the cited baseline, and **prioritizes by the map's findings/CWEs**; invariant asserts order changed |
| VF3 | D8 "decided venv" | VERIFIED constraint — `recon.py:71` `from rag import`, `agent/requirements.txt` `-r ../rag/requirements.txt` force the SHARED `rag/.venv` | D8 now a hard Phase-0 gate: langgraph/langchain-core/Phoenix must coexist with rag's pins; conflict → STOP, don't force |

**Verification Results:** Claims checked: 3 · Verified/Resolved: 3 · Failed-unresolved: 0 · Tier: Full.

### Whole-Plan Consistency Sweep
Re-read the full plan after the red-team + validate edits. Reconciled: the D1 test rename propagated
to I1 + P1.5; D9's "guided by map" is now consistent between Outcome, D9, and P1.2; the "drops
langchain-openai" phantom is removed (D6 states langgraph requires langchain-core); Phoenix's role is
consistently scoped to GRAPH-flow spans (LLM-call tracing stays Langfuse) across Outcome, Context,
D5, and Red-Team row 4. **No unresolved contradictions.**

## Result

Plan hardening: Scout → research → advise → brainstorm → plan(--tdd) → red-team (2 Crit/8 High/5 Med,
resolved into D1–D12) → validate (3 findings resolved) → consistency sweep. Phase 0 dependency-compat
gate **PASSED**.

**PR1 COMPLETE (verified).** Supervisor + wired Recon→Fuzz + Phoenix observability implemented,
then run through the full cook loop: code-review (2 High/2 Med/2 Low) + STRIDE audit (2 High/4 Med/2
Low) → all findings fixed (the target-raw checkpoint leak, the secret-regex truncation, the vacuous
invariants, the provenance-label errors, the LangSmith air-gap gap) with non-vacuous tests. Suites:
syndicate 16/0, model-egress 12/0, fuzz-engine 4/0, recon-agent 9/0, recon-tools 3/0,
gateway-authz 29/0 — no regression. Live e2e: recon map → map-guided fuzz surfaces the real Juice
Shop SQLi read-only, within budget, checkpoint+spans redacted.

Remaining: PR1 docs (README Status W4–6, decision record) + PR; then PR2 (Exploit-sim).
