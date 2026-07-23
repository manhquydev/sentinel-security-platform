# Execution Plan: Promote LiteLLM to the shared Sentinel LLM gateway

Date: 2026-07-23

## Status

Active

## Outcome

Every LLM call in Sentinel goes through one gateway that **measures what it costs, records
what happened, marks what it cannot trust, and controls what leaves the host**. None of those
four is true today: the proxy exists but is scoped to the benchmark stream, its spend is
`null` on the only tier that matters, nothing traces it, nothing labels target-derived
content, and the outbound prompt has no redaction at all.

Completion is observable when:

- the gateway runs as a shared service from `infra/litellm/`, brought up like the DefectDojo
  stack, and the benchmark stream reaches it as a client without its frozen DeepSeek arm
  losing reproducibility;
- a request produces a **non-null spend figure** whose per-token rates trace to a recorded
  source, or an explicit unavailable-with-reason marker — never a fabricated number, never a
  misleading `0`;
- the **guardrail hook signature and provenance label schema are frozen** as the D ↔ E
  interface contract, with a reference implementation that carries a taint label from request
  to audit record to trace;
- spotlighting is applied always-on to untrusted spans, as a transformation, and a negative
  control proves an unmarked untrusted span fails the request;
- secret redaction on the egress path is proven by negative controls observed failing first,
  and the redacted request is still one the upstream accepts;
- Langfuse holds traces of real calls, the bodies it holds are post-redaction, and a planted
  secret is provably absent from the **stored trace**;
- an evaluation harness can produce a static-baseline ASR figure, so Week 7 has a
  before/after rather than an assertion; and
- `benchmark/README.md`'s egress note matches what the system actually does.

## Context

### Where this sits

Project Sentinel is a 12-week autonomous web-security platform. This plan is **Stream E**, the
LLMOps platform, which [the architecture proposal](../../project-sentinel-architecture-proposal.md)
§4 names the dependency root: *"E phải xong trước tiên — mọi stream khác gọi qua nó."*

Two constraints from that document shape this plan more than any technical consideration:

- §4 gives **Stream D** ownership of "toàn bộ input/output boundary" (guardrails, HITL, PII
  redaction — T7 to T9) and states that **Stream E** owns shared infrastructure but *"không sở
  hữu logic domain"*. §2's gateway box lists E's share precisely: *"PII mask · guardrail
  **hook** · key mgmt · audit log"* — the mechanism, not the policy.
- §4 lists four interface contracts that must be frozen *before* any stream writes code.
  Contract #3 is **"Guardrail hook signature (D ↔ E)"**. That contract is this plan's headline
  deliverable, and an earlier draft of this plan omitted it while building D's policy instead.

Repository truth places implementation at Phase 1, Week 1: the DefectDojo lake is live and
verified (Week-1 close-out at `e7cd0c6`, attack-surface baseline at `bb45ed2`), and the
AI-SAST benchmark stream is complete with `cx/gpt-5.6-sol` at P 0.7503 ± 0.0044 / R 0.9329 —
*at* the 0.75 line, not above it.

[P5 AI-SAST source wiring](../../../plans/260721-2216-week1-sast-dast-data-lake-defectdojo/phase-05-ai-sast-source-wiring-HOLD.md)
is on HOLD behind six unblock conditions. This plan satisfies **two** of them — a distinct
prompt-payload redaction, and an egress-audit log. The third guardrail-related condition,
prompt-injection handling, is **deliberately not satisfied here**; see
[decision 0006](../../decisions/0006-the-gateway-labels-provenance-it-does-not-detect-injection.md).
P5 therefore remains on HOLD after this work.

### Why there is no injection detector in this plan

Settled in [decision 0006](../../decisions/0006-the-gateway-labels-provenance-it-does-not-detect-injection.md)
against three independent published results. In short: adaptive attack recovers 64% ASR on
action-open tasks against a filter measured at 0% statically, and Sentinel's agents are
action-open by definition; domain-camouflaged payloads achieve zero detection by production
classifiers, and Sentinel's legitimate traffic is *made of* security vocabulary and attack
strings; and the only defense family with a 0% result requires the agent loop and tool-call
mediation, which a gateway hook does not have.

So the gateway labels provenance and E freezes the signature; Stream D enforces on that label
in Week 7 when the agent loop exists.

### What already exists, verified by reading it

`benchmark/litellm-config.yaml` is better than a starting point. Verified present: six aliases
(`sast-sol` / `sast-terra` / `sast-gpt55` on the `cx/*` router, `cheap-sast` pinned to the
frozen DeepSeek arm, plus `judge` and `embed` placeholders); `master_key`, `database_url` for
virtual-key persistence, and `fail_closed_budget_enforcement: true`; `request_timeout: 120`
chosen from measurement rather than taste, after sol run 1 lost 49.6 minutes to a router-side
hang against a ~12 s healthy call; `turn_off_message_logging` and `redact_user_api_key_info`;
`drop_params: true` from the Step-0 spike; and four operational scripts including
`preflight.sh` and `scan-for-secrets.sh`.

Its comments are load-bearing history and must survive the move: why `stream: false` is pinned
at deployment level (the router defaults to SSE, which Metis cannot parse), why only `cx/*`
works (Metis calls `/v1/responses`; `ag/gemini-3.5-flash-*` answer it with a `chat.completion`
object and empty usage, `glm/glm-5.2` returns 429), and why `cheap-sast` must not be renamed
(the frozen scorecard is reproducible only through that alias).

### The gaps, each verified

1. **Spend is unmeasurable on the winning tier.** The router returns `usage.cost: null` and
   LiteLLM carries no pricing for `cx/*`, so manifests record `spend_usd: null` with a reason.
   `model_info.input_cost_per_token` would make LiteLLM compute spend from reported tokens,
   and the `cx/*` tiers do return populated usage — **but the rates are not known**, and
   inventing them yields a confident wrong number, worse than the honest `null`.
2. **Nothing traces the gateway.** Token volume is currently recovered by counting per-scan
   usage files on disk, a method that already lost ~19% of run 1 and run 2's records to
   filename collisions before anything read them.
3. **No provenance labelling exists**, so nothing downstream can distinguish operator-authored
   instructions from target-derived data.
4. **The outbound prompt has no guardrail.** `turn_off_message_logging` stops LiteLLM
   persisting bodies to callbacks; it does nothing about what the gateway forwards upstream.
   `benchmark/README.md:110` states this as a hard boundary and warns against citing those
   settings as satisfying it, while `benchmark/.env.example` records that the router publishes
   no retention or training terms, so only public corpora may be sent through it.

### Correction carried from the first draft

The first draft proposed gating Phase 1 on "the benchmark's 95 tests green against the shared
gateway". That gate is empty: `benchmark/tests/test_litellm_routing.py:1` states *"Config-only
tests… No API key or network needed."* All 95 parse YAML and fixtures. They will pass whether
or not the relocation works. Parity proof must therefore be constructed, not borrowed.

### Opening brainstorm contract

- **Outcome:** one shared gateway that measures spend, traces calls, labels untrusted data and
  enforces an egress boundary — the dependency root every later stream calls through.
- **Constraints:** the frozen DeepSeek arm stays reproducible; no repository secret is
  committed; redaction is proven before any body is trusted to a callback; Stream D's policy
  domain is not entered; existing Week-1 surfaces are not modified; YAGNI, then KISS, then DRY.
- **Non-goals:** injection detection or policy, Presidio PII recognition (Stream D, Week 9),
  Week-2 API Gateway and Agent IAM, RAG, any agent, vLLM, and repointing the target to WebGoat.
- **Acceptance:** as listed under Outcome, each paired with a negative control observed
  failing before it passed.

## Scope

In scope:

- a shared gateway stack at `infra/litellm/`: compose file, pinned image digest, env contract,
  bring-up documented beside the DefectDojo stack;
- the config moved from `benchmark/` with its comment history intact, `benchmark/` repointed,
  and `cheap-sast` preserved verbatim;
- resolution of the `cx/*` pricing question, then real rates recorded with their source, or an
  explicit unavailable marker — decided by evidence;
- **the guardrail hook signature and provenance label schema, frozen as the D ↔ E contract**,
  with a reference `CustomGuardrail` implementation;
- spotlighting/datamarking applied to spans labelled untrusted;
- egress secret redaction plus an egress-audit record;
- a self-hosted Langfuse v3 stack, callback wiring, and body logging enabled only after
  redaction passes;
- an evaluation harness able to produce a static-baseline ASR figure;
- test suites in the repository's existing style: assertions with negative controls proven
  able to fail;
- correcting `benchmark/README.md`'s egress note.

Out of scope:

- any injection classifier, detector or policy, and Presidio PII recognition — Stream D,
  Weeks 7 and 9, per decision 0006;
- the adaptive-attack evaluation round; this plan builds the harness and runs the static
  baseline only, because the adaptive round costs on the order of weeks and thousands of
  dollars and its subject (D's enforcement) does not exist yet;
- Kong/Tyk API Gateway and Agent IAM — Week 2, separate plan;
- RAG, any agent, fuzzing, exploitation, vLLM and GPU FinOps;
- executing P5 AI-SAST ingestion;
- repointing scanners or the lake to WebGoat — real work, separate plan (see Open questions);
- re-running or re-scoring any benchmark arm.

### Exclusive file ownership

May create: `infra/litellm/{docker-compose.yml,config.yaml,README.md}`,
`infra/litellm/guardrails/`, `infra/langfuse/{docker-compose.yml,README.md}`,
`tests/litellm-gateway-test.sh`, `tests/test_gateway_guardrails.py`, and further
`docs/decisions/` entries.

May modify, narrowly: `infra/.env.example` (new variables only);
`benchmark/litellm-config.yaml` (becomes a pointer, or is removed once `benchmark/` reads the
shared config); `benchmark/README.md` (egress note and endpoint); `benchmark/scripts/preflight.sh`
(its `turn_off_message_logging` assertion changes meaning and must be **rewritten, not deleted**).

Must not touch: `scanners/**`, `scripts/**`, `.github/**`, `infra/systemd/**`,
`infra/defectdojo*/**`, `infra/harness/**`, `attack-surface/**`, and every existing test.

## Approach

Ordering is not negotiable, and it repeats the argument Week-1 made about repairing the lake
before automating it: **redaction is a precondition for body logging, not a parallel task.**
The accepted decision routes bodies into Langfuse after redaction, which makes the redaction
hook load-bearing. Wire it second and every trace written in between is an unredacted store of
source code and attacker-controlled strings; deleting a ClickHouse row later does not unwrite
it.

### Phase 1 — Move the gateway, lose nothing

Relocate to `infra/litellm/` following the DefectDojo stack's conventions: discrete env vars
rather than a DSN (a DSN carries the password into tracebacks and `docker inspect`), image
pinned by digest, bring-up in the compose header.

Parity must be proven mechanically, because the existing tests cannot prove it. Assert every
alias name and its `litellm_params`, every `general_settings` and `litellm_settings` key, and
the survival of the explanatory comments, by comparing the old and new files structurally.
`cheap-sast` is the sharpest case: the frozen DeepSeek scorecard is reproducible only through
that alias, so a rename is silent data loss.

Then add the integration proof the config-only tests never gave: one real call through the
relocated gateway that returns a completion.

Gate: structural parity asserted; one live call succeeds; no secret in any committed file.

### Phase 2 — Make spend real or make it honestly absent

Answer the pricing question first; the two branches produce different artifacts.

Try, in order: ask the router operator for published per-token rates; check whether the router
returns a rate on any endpoint; derive from a known-price upstream if the tier maps to one. If
a rate is obtained, record it in `model_info` **with its source and observation date in a
comment**, so a later reader can distinguish a real rate from a guess.

If none is obtainable, do not fabricate. Record token volume as the measured quantity and
spend as unavailable-with-reason, matching what the scorecards already do. Assert that the
gateway never reports spend `0` for a call that consumed tokens — that failure mode is
indistinguishable from success in a dashboard.

Virtual-key attribution stays the accounting backbone: per-tier, per-run keys exist because
two tiers sharing one key destroys per-arm attribution, which is the only accounting left when
pricing goes inert.

Gate: a real call yields a non-null spend traceable to a recorded rate, or an unavailable
marker carrying a reason; a token-consuming call never reports `0`; per-key attribution
verified across two keys.

### Phase 3 — The contract, then the hygiene

This phase delivers the interface contract §4 demands, and nothing from Stream D's domain.

*The signature.* Define and freeze the guardrail hook signature and the provenance label
schema: how a caller marks a span as target-derived, what the label carries (source, target
identity, confidence), and how it propagates into the audit record and the trace. Design it as
the input a capability-gating enforcer will need in Week 7 — the labelling is E's, the
enforcement is D's. Document it as a contract, not an implementation detail, because changing
it later costs both streams.

*Spotlighting.* Apply datamarking to labelled untrusted spans at `pre_call`. It is a
transformation, not a classification, so it adds no false-positive surface on a workload made
of attack strings. Claim nothing more for it than hygiene; it is bypassable and decision 0006
says so.

*Egress secret redaction.* Strip secrets from the prompt before it leaves the host. Reuse what
the repository already knows how to detect rather than importing a new stack:
`attack-surface/export-baseline.py` carries a working detector for opaque tokens, UUIDs and
`secret=`-style assignments, and `scanners/redact-report.sh` carries the whitelist discipline.
Presidio is explicitly not adopted here — it is a two-server dependency and it belongs to
Stream D's Week-9 PII work.

Every redaction writes an audit record: which class, which call, which virtual key — never the
value.

The lesson Week-1 paid for transfers directly. Its redaction suite originally only grepped for
planted strings, so it could not observe a sanitized report the parser rejected; the fix that
mattered was a round-trip assertion. The analogue: assert not only that a planted secret is
absent from the outbound body, but that the redacted body is **still a request the upstream
accepts**. A guardrail that mangles prompts into a 400 is broken in a quieter, worse way.

Negative controls, each observed failing before its fix:

- a planted API key in a prompt reaches the upstream ⇒ fail;
- a redacted prompt the upstream rejects as malformed ⇒ fail;
- an untrusted span with no provenance label passes through ⇒ fail;
- a labelled untrusted span reaches the model without spotlighting applied ⇒ fail;
- a redaction event produces no audit record ⇒ fail;
- an audit record containing the secret value itself ⇒ fail.

Gate: all six observed red, then green. **No body logging is enabled until this gate passes.**

### Phase 4 — Langfuse, then bodies

Stand up Langfuse v3 at `infra/langfuse/`: Postgres, ClickHouse, Redis, MinIO, `langfuse-web`
and `langfuse-worker` — six containers, accepted knowingly as the second-largest operational
stack in the repository. Loopback-only binding, as every other service here. Pin by digest.

Wire the callback with `turn_off_message_logging` still `true` and confirm traces arrive
carrying metadata: model, latency, token counts, virtual key, provenance labels. Only then
flip body logging on, and immediately re-run Phase 3's planted-secret controls end-to-end,
this time asserting the secret is absent **from the stored trace** rather than merely from the
outbound request. That is the assertion the accepted body-logging decision actually rests on.

Assert that a Langfuse outage cannot fail an LLM call. Tracing is best-effort; the guardrail
is not.

Update `benchmark/README.md`'s egress note, and rewrite `preflight.sh`'s
`turn_off_message_logging` assertion, which now checks for a setting the system deliberately
no longer has. Deleting it removes a check; it must instead assert the new boundary — body
logging on *and* the redaction guardrail loaded.

Gate: traces present for real calls; a planted secret absent from the stored trace; Langfuse
reachable only on loopback; a Langfuse outage does not fail a call; `preflight.sh` asserts the
new boundary and fails when the guardrail is unloaded.

### Phase 5 — Make the number possible, then write it down

Stand up the evaluation harness and run the **static baseline only**: AgentDojo, or Promptfoo
if it proves cheaper to wire. The point is not the number — with no enforcement built, the
baseline measures an undefended system — it is that Week 7 inherits a working harness and a
recorded starting point instead of an argument about methodology.

Record honestly what a static figure proves. Per decision 0006's evidence, static results
overstate robustness badly, and the adaptive round is deliberately out of scope here.

Then the durable artifacts: `tests/litellm-gateway-test.sh` in the contract-suite style,
`tests/test_gateway_guardrails.py` for the redaction and labelling logic (pure enough to test
without a live gateway), and `infra/litellm/README.md` covering bring-up, env contract, key
scoping, the provenance contract and the egress boundary — following `scripts/README.md`'s
precedent.

## Risks And Recovery

- **Sentinel has no injection defense until Week 7.** Stated, not mitigated. It also has no
  agents until then, so there is nothing yet to hijack; the exposure begins exactly when
  Stream C ships, which is when D's enforcement is due. If C lands before D, that is a
  schedule risk to raise, not a reason to build a detector decision 0006 rejected on evidence.
- **A provenance label is only as good as the caller's discipline.** A mislabelled untrusted
  span is worse than no label, because Week-7 enforcement will trust it. Mitigate by failing
  closed: an unlabelled span from a known-untrusted source fails the request rather than
  defaulting to trusted.
- **Body logging into traces reverses a documented hard boundary**, accepted knowingly by the
  user after the trade-off was presented. Mitigation is structural: redaction ships and passes
  negative controls before bodies are trusted anywhere, and the assertion is made against the
  *stored trace*. The residual is unavoidable and must be stated — every trace's safety now
  depends on redaction being complete, and no redactor is provably complete.
- **A ClickHouse-backed store of prompt bodies is a new asset worth attacking.** Loopback-only,
  never leaves this host.
- **Fabricated pricing is worse than no pricing.** A wrong rate looks authoritative and
  silently corrupts every downstream FinOps figure. Phase 2 prefers the unavailable marker.
- **Six new containers on a host already running twenty.** 19 GB RAM and 57 GB disk free at
  plan time; ClickHouse is the heavy component. Recovery is `docker compose down` on the
  Langfuse stack alone, which is why the no-fail-on-outage assertion matters.
- **Moving the config can silently break the frozen benchmark arm.** Parity is asserted
  structurally in Phase 1, since the existing tests cannot detect it.
- **A guardrail that mangles prompts degrades every downstream result invisibly**, because a
  slightly-worse LLM answer looks like a slightly-worse LLM. The round-trip assertion is the
  defence, borrowed from the Week-1 redaction suite that learned this expensively.
- **Recovery:** this plan adds services and files; it changes no lake state and no scanner.
  Removing `infra/litellm/` and `infra/langfuse/` and reverting `benchmark/` returns the
  repository to `bb45ed2`.

## Progress

Sequencing changed on 2026-07-23: Phase 3 ran first. The interface contract is the only
item in this plan that blocks another stream, §4 requires contracts frozen before code, and
it needs no service running — whereas Phase 1 is a refactor that adds no capability. An
earlier draft placed the relocation first out of habit rather than argument.

Phase 3 — the contract and the hygiene — **complete 2026-07-23**

- [x] `provenance-label.schema.json` frozen as the D ↔ E contract, with the declaration
      pinned to `metadata.sentinel_provenance` — the channel LiteLLM keeps proxy-side rather
      than forwarding upstream. A top-level key would have depended on `drop_params` to avoid
      reaching the provider, which is too fragile to rest a boundary on.
- [x] `provenance.py`: fail-closed validation with exact coverage, and spotlighting that
      delimits whitespace-significant content rather than datamarking it, so scanner output
      and source survive byte-for-byte. No injection detector, per decision 0006.
- [x] `egress_redaction.py`: credentials matched on structure — known prefixes, assignment
      syntax, PEM framing, JWT layout — never on entropy. A bare 64-hex run is flagged for an
      operator without being rewritten, because in this workload it is a file hash inside a
      real finding.
- [x] `sentinel_guardrail.py`: the LiteLLM adapter, holding no policy of its own. Provenance
      runs before redaction; the audit summary goes to the proxy log, never back to the
      caller, so the guardrail cannot serve as an oracle for what a caller smuggled past it.
- [x] `docs/product/guardrail-hook-contract.md` published, then corrected against the code —
      it had claimed audit logging that did not yet exist and had left the declaration's
      location unspecified.
- [x] **Adversarial review found a real defect the implementation's own tests missed**: three
      dotted segments of ten-plus characters is a JWT *and* a Java package path, so the
      length-only pattern rewrote `organization.applications.configuration` into a redaction
      placeholder — silently corrupting the Java source the SAST arm sends through. Anchoring
      the header segment on `eyJ` removes the collision. Regression tests added for Java
      packages, Semgrep check_ids and Maven coordinates.
- [x] `tests/test_gateway_guardrails.py` — **34 assertions**, runnable without litellm
      installed. Six mutations each turned the suite red at the assertion that owns them:
      accepting a missing declaration, skipping spotlighting, not redacting, leaking the value
      into the audit entry, and reverting the JWT anchor. Restoration returned green each time.
- [x] No regression: `tests/` 45, `benchmark/` 95, workflow-safety 17, wrapper-status 15,
      target-allowlist 9, `bash -n` and `git diff --check` clean.

- [ ] Phase 1: shared gateway at `infra/litellm/`, structural parity asserted, one live call.
- [ ] Phase 2: pricing resolved; spend real-with-source or absent-with-reason.
- [ ] Phase 4: Langfuse standing, metadata traces, then bodies after the stored-trace control.
- [ ] Phase 5: static ASR baseline, test suites, gateway README.

## Decisions

- 2026-07-23: The gateway labels provenance and does not detect injection. Recorded in full,
  with its evidence and rejected alternatives, as
  [decision 0006](../../decisions/0006-the-gateway-labels-provenance-it-does-not-detect-injection.md).
- 2026-07-23: The guardrail hook signature and provenance label schema are this plan's
  headline deliverable, because §4 requires interface contracts frozen before code and names
  this one explicitly. An earlier draft omitted it while building Stream D's policy instead.
- 2026-07-23: The gateway moves to `infra/litellm/` as shared infrastructure; `benchmark/`
  becomes a client. A directory named `benchmark/` misdescribes the dependency root once
  agents call through it.
- 2026-07-23: Langfuse v3 self-hosted, accepted with its six-container footprint, after Arize
  Phoenix (one container) was presented as the lighter alternative.
- 2026-07-23: Bodies are logged into traces **after** the redaction hook, reversing the
  boundary at `benchmark/README.md:110`. Accepted after the trade-off was presented.
  Consequence: redaction becomes a precondition, and `preflight.sh`'s assertion is rewritten
  rather than deleted.
- 2026-07-23: Presidio is not adopted. It is a two-server dependency and belongs to Stream D's
  Week-9 PII work; egress redaction reuses detectors this repository already has.
- 2026-07-23: Spend is never fabricated. A rate is recorded only with its source; otherwise
  the gateway reports unavailable-with-reason.
- 2026-07-23: Only the static ASR baseline is in scope. The adaptive round costs weeks and
  thousands of dollars, and its subject — D's enforcement — does not exist yet.
- 2026-07-23: A Langfuse outage must never fail an LLM call. Tracing is best-effort; the
  guardrail is not.

## Validation

- Focused proof: `tests/test_gateway_guardrails.py` for redaction and provenance labelling,
  runnable without a live gateway; `tests/litellm-gateway-test.sh` for the config contract,
  structural alias parity and the egress boundary.
- Integration proof: one real call through the shared gateway producing a trace in Langfuse
  and a spend figure or reasoned absence; `preflight.sh` all `[ok]`; the static ASR baseline
  runs end to end.
- Negative controls, each observed failing first:
  - planted API key in a prompt reaches the upstream ⇒ fail;
  - planted secret present in the **stored trace** ⇒ fail;
  - redacted prompt rejected as malformed by the upstream ⇒ fail;
  - untrusted span with no provenance label passes through ⇒ fail;
  - labelled untrusted span reaches the model unspotlighted ⇒ fail;
  - redaction event with no audit record, or an audit record containing the value ⇒ fail;
  - token-consuming call reporting spend `0` ⇒ fail;
  - `cheap-sast` alias renamed or absent ⇒ fail;
  - Langfuse unreachable causes an LLM call to fail ⇒ fail;
  - guardrail unloaded while body logging is on ⇒ `preflight.sh` fails.
- Repository-required checks: existing Week-1 suites unchanged and green (`core-gate`,
  `import-contract`, `redaction-guarantee`, `target-allowlist`, `wrapper-status`,
  `workflow-safety`), `SKIP_REIMPORT=1 tests/verify-lake-test.sh`,
  `tests/test_attack_surface_baseline.py`, `git diff --check`.

## Result

Pending.

## Open questions

- **Are the `cx/*` per-token rates obtainable at all?** Phase 2 branches on this and it cannot
  be settled by reading the repository. If not, spend stays honestly unavailable and token
  volume carries the FinOps story.
- **WebGoat as the standing target is decided but not implemented.** The Semgrep unit already
  points at `benchmark/targets/webgoat-src` (v2025.3, `c3ed45a`), but the lake's 221 Semgrep
  findings were measured against OWASP Benchmark — `scanners/out/semgrep.san.json` resolves to
  `benchmark/targets/owasp-benchmark/.../BenchmarkTest00023.java`. Nuclei and Trivy still point
  at Juice Shop and no WebGoat runtime is deployed, so `infra/defectdojo/lake-baseline.json`
  records a Semgrep count from a tree the scheduler no longer scans and the first timer firing
  will fail `verify-lake.sh`'s exact-match drift check. Not yet live: the timer is staged but
  not installed (`systemctl --user` reports no such unit). Needs its own plan before that timer
  is enabled.
- **If Stream C ships before Stream D**, the system gains agents before it gains enforcement.
  That is a sequencing question for the roadmap, not something this plan can resolve.
- **Should Sentinel produce the missing false-positive dataset for security-testing
  workloads?** No published study covers it, the project is unusually well placed to build it,
  and it would serve the Phase 3 thesis. Out of scope here; worth a decision of its own.
