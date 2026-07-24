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
