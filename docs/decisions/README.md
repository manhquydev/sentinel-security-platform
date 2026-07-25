# Decisions

Decision records preserve lasting product, architecture, data ownership,
security, compatibility, and validation choices that future work must inherit.

Use `docs/templates/decision.md`. Task-local implementation choices remain in
the active execution plan and do not require a separate decision.

An installed consumer begins with no fabricated decisions. Add local decision
documents here as real choices are accepted, then index them in this file.

## Index

- [0001 Benchmark LLM provider and model family](0001-benchmark-llm-provider-and-model-family.md)
  — DeepSeek → clawcmc router `cx/*`; public-corpora-only boundary; no cost data,
  backing model not observable.
- [0002 CWE category map accepts semantic equivalents](0002-cwe-category-map-accepts-semantic-equivalents.md)
  — the map was an identity map contradicting its own contract; correcting it changed
  every published precision/recall figure.
- [0003 DefectDojo broker is Redis, not the upstream valkey pin](0003-defectdojo-broker-is-redis-not-valkey.md)
  — under valkey 9.1.0 the Celery worker reported healthy while never polling the task
  queue, disabling every asynchronous path with no error surfaced.
- [0004 DefectDojo OSS has no role-based authorization](0004-defectdojo-oss-has-no-role-based-authorization.md)
  — roles moved to `dojo-pro`; CI scoping uses `Product.authorized_users`, and delete
  requires `is_staff`, so the residual is smaller than the Week-1 plan assumed.
- [0005 Scanner wrappers accept a local-binary fallback](0005-scanner-wrappers-accept-a-local-binary-fallback.md)
  — registry blob throughput made large images unpullable on this host; the digest-pinned
  path stays the default, with a documented fallback rather than a blocked scanner.
- [0007 A Product is one application, and benchmark corpora leave the lake](0007-a-product-is-one-application-and-benchmarks-leave-the-lake.md)
  — 221 of 246 findings describe OWASP Benchmark inside a Product named for Juice Shop;
  dedup is product-wide and endpoint hashing ignores port, so two loopback targets in one
  Product would silently collapse each other's DAST findings.
- [0006 The gateway labels provenance; it does not detect injection](0006-the-gateway-labels-provenance-it-does-not-detect-injection.md)
  — adaptive attack recovers 64% ASR on action-open tasks and domain-camouflaged payloads
  evade production classifiers entirely, so Stream E freezes the hook signature and taint
  labels while Stream D enforces at the agent layer.
- [0008 Kong fronts the app; LiteLLM fronts the model](0008-kong-fronts-the-app-litellm-fronts-the-model.md)
  — two orthogonal gateway planes with disjoint data and failure modes; Kong OSS is the
  app-ingress plane (Week 2), LiteLLM stays the LLM-egress plane.
- [0009 Agent IAM is OAuth2 identity with ACL authorization](0009-agent-iam-is-oauth2-identity-with-acl-authorization.md)
  — MCP/A2A defer authorization to the gateway, and Kong OSS does not bind scopes to a
  consumer, so identity is a short-TTL OAuth2 token and enforcement is fail-closed ACL groups
  named after the attack-surface auth taxonomy.
- [0010 Authorization enforcement is Kong ACL; OPA deferred](0010-authorization-enforcement-is-acl-opa-deferred.md)
  — the Week-2 boundary is a static per-consumer/per-route allow that ACL enforces natively;
  OPA is adopted only when a decision becomes conditional (Week 5 fuzzing scope, Week 8 HITL).
- [0011 RAG uses local embeddings + pgvector hybrid; GraphRAG deferred](0011-rag-is-local-embeddings-pgvector-hybrid-graphrag-deferred.md)
  — the chat gateway cannot embed (proven), so Week-3 RAG is self-hosted fastembed BGE + pgvector
  with RRF hybrid and a measured, regression-guarded accuracy baseline; GraphRAG and a re-ranker
  wait behind explicit triggers.
- [0012 The Recon agent is a thin, provenance-bound pipeline; LangGraph deferred](0012-recon-agent-is-a-thin-provenance-bound-pipeline-langgraph-deferred.md)
  — the Week-4 pipeline is linear and the gateway is fail-closed on the provenance contract, so
  the agent is a thin provenance-bound loop with a frozen, code-checked Attack Surface Map schema;
  LangGraph is adopted at Week 6 when the supervisor and HITL interrupt arrive.
- [0013 Fuzzing is hybrid, read-only, with deterministic signal detection](0013-fuzzing-is-hybrid-read-only-with-deterministic-signals.md)
  — a committed payload corpus ranked/mutated by the LLM; 5xx/stack-trace/reflection signals are
  code-detected facts, not LLM opinions; the engine stays in agent-recon's read-only scope and
  defers state-changing payloads to the Week-8 HITL gate.
- [0014 The syndicate is a LangGraph supervisor over the existing agents; observability is a redaction-gated Phoenix plane](0014-the-syndicate-is-a-langgraph-supervisor-over-existing-agents-observability-is-a-redaction-gated-phoenix-plane.md)
  — hand-rolled `StateGraph` over Recon+Fuzz with model access still at the gateway (a model-egress
  contract test enforces it); durable checkpoint + spans run through a secret-AND-target-raw scrub
  distinct from egress redaction; Arize Phoenix (loopback, digest-pinned) traces the graph flow,
  Langfuse keeps per-call bodies; the `interrupt()` seam is inert-but-tested for Week-8 HITL.
- [0015 IPI defense is structural output-integrity; the real surface is recon-analysis; detection is measured](0015-ipi-defense-is-structural-output-integrity-the-real-surface-is-recon-analysis-detection-is-measured.md)
  — a red-team showed there is no rogue-execution surface to gate (already read-only/contained), so
  Week-7 defends the one real IPI surface (a scanner `title` → recon `_analyze` → analyst narrative):
  the code-computed facts a hijacked narrative can't alter are the control, a contradicted analysis is
  quarantined, and detectors (in-repo heuristic; LlamaFirewall air-gapped sidecar) are MEASURED
  defense-in-depth with the false-positive rate on security content as the differentiator.
- [0016 Week-8 HITL is a fail-closed gate over a simulated action with out-of-process Ed25519 approval; real execution deferred](0016-week8-hitl-is-a-failclosed-gate-over-a-simulated-action-with-out-of-process-ed25519-approval-real-execution-deferred.md)
  — a red-team proved "approve+execute the real payload" rested on 5 broken axes (no runnable payload,
  approvable≠write endpoints, self-forgeable approval, no OPA on Kong OSS, illusory reversibility), so
  Week-8 ships a genuine fail-closed HITL gate over a SIMULATED action: approval is Ed25519-signed and
  the agent holds only the verify key (can't self-approve), the single-use token binds the exact
  reviewed proposal + is audited before the dry-run action; real execution + its prerequisites are
  deferred to an explicit future cycle.
- [0017 Week-9 PII redaction is structural at capture, measured not trusted; real dumps are simulated](0017-week9-pii-redaction-is-structural-at-capture-measured-not-trusted.md)
  — a red-team showed the charter's literal DB-dump surface doesn't exist (Exploit never executes,
  the fuzzer reduces bodies to signal-kinds, RAG ingests only static records), so Week-9 creates a
  fixture-backed simulated dump on the Week-8 seam and scrubs it AT CAPTURE (before the checkpoint,
  the approval-audit ledger, and stdout). Detection is narrow deterministic regex (email, Luhn card
  under a label anchor, JWT, UUID) — Presidio/NER rejected (heavy model, air-gapped break, FP on
  security vocabulary) — so the SQLi/XSS/hash workload passes untouched; the unsalted-MD5 password
  value is removed via the credential pass while the finding survives; residual is MEASURED (recall
  vs FP) with a guard that fails closed on an absent corpus. Egress PII leg + bare-PAN + NER deferred.
- [0018 Week-10 eval is a deterministic oracle over an observable subset; the LLM judge is measured, not trusted](0018-week10-eval-is-a-deterministic-oracle-over-an-observable-subset-judge-measured-not-trusted.md)
  — a red-team showed the read-only fuzzer's observable surface is exactly one endpoint, so a naive
  recall/FP over "the observable subset" is vacuous. Week-10 is a deterministic code oracle over two
  labelled corpora: a `synthetic:true` corpus with a KNOWN confusion matrix (asserted as independent
  ground truth) that exercises the matcher exhaustively, and an enriched real corpus (the known SQLi
  search + four benign read paths, labelled from public sources) scored over a committed, redacted
  live capture. Recall is honest COVERAGE (the syndicate does identify the observable SQLi, 1/1);
  FP=0 on benign endpoints is the load-bearing gate (the syndicate false-positives on none);
  unobservable auth/state-change vulns are deferred (0016), never faked. The guard fails closed +
  non-vacuous by construction; a re-redaction leak guard protects the first committed live capture.
  The LLM narrative judge is built only to be MEASURED — under the security-correct target-derived
  provenance the hardened models refuse the grading role (0/12), and only a forbidden trust downgrade
  gets them to respond — so it is demonstrated unfit to be load-bearing; the oracle stays the verdict.
- [0019 Week-11 production is a containerised syndicate + per-run FinOps + an on-prem serving path](0019-week11-production-is-a-containerised-syndicate-per-run-finops-and-an-on-prem-serving-path.md)
  — scouting corrected the literal charter (4 GB laptop GPU, no docker NVIDIA runtime). Week-11 ships
  the three real things: per-run FinOps (`agent/finops.py`) that MEASURES exact tokens+latency and
  labels cost an estimate (on-prem = $0), with a deterministic cost/token/latency/error budget guard
  for spike alerting, opt-in and non-invasive; a slim digest-pinned syndicate container
  (`infra/agent/`, RAG degrades gracefully so no ML stack) verified running the full pipeline against
  the live planes; and an on-prem serving path as a gateway alias (`local-onprem`) verified LIVE via
  Ollama (`qwen2.5:0.5b` on the GPU, agent call + FinOps $0), with vLLM (`infra/vllm/`) committed as
  the datacenter path. Honestly deferred + named: vLLM production throughput/autoscaling; the
  gateway-container→host-model hop (sandbox forbids non-loopback binds); output/version drift beyond
  the budget guard.
- [0020 The inherited LLM-SAST-triage verifier is measured unsafe; the deterministic ethos holds; default model → grok-4.5](0020-ai-sast-llm-triage-verifier-is-measured-unsafe-deterministic-ethos-holds-default-model-grok.md)
  — the AI-SAST inherit-and-upgrade spike (clean-room guided-question verifier, inheriting VulnHunterX's
  method) ran on real RealVuln FP-traps (Bandit → match → verify → score) and DISPROVED the thesis
  across two models × two provenance conditions: under the security-correct target-derived provenance
  BOTH sast-sol and grok-4.5 refuse the grading role (FP-reduction 0, reproducing the Week-10 judge on
  the SAST surface); under the forbidden operator downgrade both grade but breach the hard recall floor
  (silently drop real SQLi/cmd-injection/hardcoded-cred). So no verifier module ships (measure-first,
  fail-allowed) — the honest path is a broader deterministic SAST foundation + a NON-load-bearing LLM
  annotator that can never drop a finding. Also: the default agent model moved to grok-4.5
  (`sast-grok45`, gpt-5.6-sol low on quota); frozen benchmark arms untouched.
- [0021 The non-load-bearing LLM SAST annotator is a confirmed safe upgrade (ranks, never drops)](0021-non-load-bearing-sast-annotator-is-a-confirmed-safe-upgrade.md)
  — the safe replacement for the disproven drop-verifier (0020): the LLM assigns a review-priority over
  code-derived facts (operator-safe, no refusal) and NEVER drops a finding, so recall stays 1.0. Measured
  over the full RealVuln corpus (n=1764, 37 memoized LLM calls): LLM annotator AUC 0.814 [0.780,0.848] vs
  deterministic severity 0.732 [0.694,0.770] — significantly better (non-overlapping CIs), real-vuln
  priority 0.44 vs FP-trap 0.26. The LLM assists the human's order-of-work, never the keep/drop call.
  **AMENDED**: a self-red-team found a free supervised deterministic CWE-class prior scores AUC 0.886
  vs the LLM's 0.818 (paired bootstrap +0.069 [+0.045,+0.095], significant) — so where labels exist the
  deterministic prior wins and no LLM is needed; the zero-shot LLM annotator is only the cold-start
  fallback. Measured-not-trusted holds a third time on this surface.
- [0022 Multi-engine deterministic detection is the real recall lever; the SAST ceiling is structural](0022-multi-engine-deterministic-detection-is-the-real-recall-lever-sast-ceiling-needs-dast.md)
  — ranking can't recover an undetected vuln, so detection was measured: Bandit recall 0.131, Semgrep
  0.118 (but 2.4x the precision), **union 0.188 = +44% relative at no precision cost**, engines strongly
  complementary (~37%/30% unique). **81% still missed by both** — CWE-200/284/862/639/20 (info exposure,
  access control, missing authz, IDOR, input validation) need app semantics + runtime, which pattern SAST
  structurally cannot see; that residual is the DAST/syndicate layer's job. Adding further engines
  (OpenGrep/gosec/Brakeman/js-x-ray) is now an evidence-backed, per-language decision with a committed
  harness. The founding thesis — AI stands on a broad deterministic tool foundation — measured, not assumed.
- [0023 SAST detects PRESENCE not ABSENCE (9.5x); the residual belongs to runtime/DAST](0023-sast-detects-presence-not-absence-the-residual-belongs-to-runtime.md)
  — per-CWE breakdown of 0022's missed 81%: SAST recall is **43.6% on "presence of a bad pattern"**
  (SQLi 70%, cmd-injection 89%, weak crypto 94%) but **4.6% on "absence of a required control"**
  (CWE-284 access control 0%/187 vulns, CWE-307 no auth-attempt limit 0%/134, CWE-200 info exposure
  0.8%/237) — a **9.5x** gap, and the absence bucket is the LARGER half (847 vs 569 real vulns). An
  absent control has no token to match; it is observable only in behaviour, i.e. at RUNTIME. So more
  SAST rules cannot close it — this is the measured justification for the SAST ∪ DAST architecture and
  for the agentic syndicate. Instruments: analyze_cwe_gap.py, classify_gap.py (offline, no LLM).
- [0024 The standard SAST benchmark contains 0% absence-of-control cases](0024-the-standard-sast-benchmark-cannot-measure-half-of-real-vulnerabilities.md)
  — self-verified from OWASP Benchmark's own expectedresults CSV: all 2740 cases fall in 11 presence-type
  categories (sqli/xss/weakrand/crypto/cmdi/pathtraver/...), with **zero** CWE-284/639/862/863/306/307.
  Against 47% absence-class in RealVuln and 26-53% in Juice Shop, the benchmark that drives SAST tool
  development cannot measure the larger half of real vulnerabilities — what is not measured is not built.
  Explains strong AI-SAST leaderboard scores alongside low real-world recall, and makes benchmark choice
  a load-bearing decision. Also: Juice Shop's /api/Challenges carries no CWE/endpoint, so the E8/E9
  runtime probers still lack a recall denominator (hand-labelling deferred).
- [0025 Authorization is measured at the enforcement point; the finding is the defence-in-depth posture](0025-authorization-is-measured-at-the-enforcement-point-and-the-finding-is-defence-in-depth.md)
  — two red-team lenses found the planned "detect missing authz" outcome unachievable here (the gateway
  routes 8 endpoints, only 2 non-public, both correctly protected) and found E8's earlier finding was an
  artefact of probing AROUND Kong. Reframed: judge at the enforcement point with a LIVE authenticated
  identity; the finding is WHERE authorization is enforced. Measured on Juice Shop as agent-recon:
  **2/2 non-public routed endpoints return 403 at the gateway but 200 at the app** — 100% rely solely on
  Kong, a single point of failure any direct-to-app path defeats. Guarded by two fail-closed canaries
  (session = identity liveness, synthetic = prober liveness) so a vacuous "clean" run is impossible, and
  by a structural test that no LLM surface is reachable from the verdict path. Coverage bound stated:
  8 routed endpoints, gateway-fronted slice only.
