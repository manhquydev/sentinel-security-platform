# 0006 The gateway labels provenance; it does not detect injection

Date: 2026-07-23

## Status

Accepted

## Context

Sentinel's agents read content from deliberately vulnerable targets (OWASP WebGoat, OWASP
Juice Shop). Target-derived text is attacker-controlled by construction, so indirect prompt
injection is not a hypothetical for this system — it is the expected condition of every input.

All LLM traffic passes through a LiteLLM proxy, which exposes guardrail hooks
(`async_pre_call_hook`, `async_moderation_hook`, `async_post_call_success_hook`). The obvious
move is to put an injection detector there. The question was whether that is the *best* move
or merely the fastest, so the defense landscape and its measurement methodology were
researched before any code was designed.

The [architecture proposal](../project-sentinel-architecture-proposal.md) constrains the
answer in two ways that turned out to matter more than expected. §4 assigns Stream D
ownership of "toàn bộ input/output boundary" and states that Stream E owns shared
infrastructure but "không sở hữu logic domain". Separately, §4 lists four interface contracts
that must be frozen before any stream writes code; contract #3 is literally "Guardrail hook
signature (D ↔ E)".

## Decision

**The gateway does not detect prompt injection. It labels data provenance, applies
transformation-only hygiene, and records an audit trail.**

Stream E ships:

- the guardrail hook signature, frozen as the D ↔ E interface contract;
- provenance/taint labelling in the request contract, marking which spans are target-derived
  and therefore untrusted;
- spotlighting/datamarking as an always-on transformation;
- secret redaction on the egress path, which is E's own hygiene concern — protecting this host
  from what it sends to a third-party router that publishes no retention terms;
- an egress audit log; and
- the evaluation harness that makes attack success rate measurable, since §4 assigns eval
  to E.

Stream E ships **no classifier and no detector**, now or later.

Stream D implements capability gating and information-flow enforcement at the agent layer in
Week 7, plugging into the frozen signature. That work requires the agent loop, which does not
yet exist.

## Alternatives Considered

1. **A classifier at the pre-call hook (PromptGuard 2, Llama Guard, or equivalent).** Rejected
   on three independent published results, each of which alone would be sufficient:
   - Nasr et al., ["The Attacker Moves Second"](https://arxiv.org/abs/2510.09023) — 12
     published defenses broken at >90% ASR under adaptive attack, PromptGuard among them, and
     "the majority of defenses originally reported near-zero attack success rates."
   - [AutoDojo](https://arxiv.org/abs/2606.15057) — against a filter that reduces static ASR to
     0%, adaptive attack recovers 28% overall and **64% on action-open tasks**, where the
     user's request delegates the action itself to attacker-controlled content. The paper
     names this a structural limit, not an implementation weakness. Sentinel's Recon, Fuzzing
     and Exploit agents are action-open by definition.
   - [PARSE](https://arxiv.org/abs/2606.17467) — domain-camouflaged payloads, which adopt
     professional domain vocabulary, achieve **zero detection by production classifiers
     including Llama Guard 3**. Sentinel's legitimate traffic is made of security vocabulary
     and attack strings, so an injection hidden in scanner output is indistinguishable from
     the work itself. The same paper finds paraphrasing — the strongest defense on synthetic
     benchmarks — produces no statistically significant ASR reduction on real documents while
     degrading utility.

   The false-positive argument is independent of the bypass argument and is arguably more
   decisive operationally: a detector trained to flag attack-looking content, deployed on a
   workload whose legitimate payloads *are* attack strings, fires constantly. Neither
   researcher found any published study quantifying false-positive rates on real
   security-testing workloads.

2. **LlamaFirewall as the primary guardrail**, on its reported AgentDojo result of 17.6% → 1.7%
   ASR. Rejected as a primary defense because that number is measured against AgentDojo's
   default static attack corpus, while its always-on component (PromptGuard) is among the
   defenses Nasr et al. broke at >90% under adaptive attack. Its stronger component,
   AlignmentCheck, needs the agent loop and so cannot run at the gateway anyway. Reconsider at
   the agent layer in Week 7 as one layer among several, never as the guarantee.

3. **CaMeL-style provenance tainting implemented at the gateway.** Rejected as impossible, not
   as undesirable. [CaMeL](https://arxiv.org/abs/2503.18813) is the strongest published
   result — 0 successful attacks on AgentDojo where the next-best defense allowed 8 — but it
   is a dual-LLM capability architecture requiring control of the agent execution model and
   tool-call mediation. A gateway hook sees a request; it does not see the agent's plan or
   mediate its tools. The same applies to the FIDES/RTBAS information-flow family. This is
   precisely why the decision splits labelling from enforcement.

4. **Build a detector now and measure it against the 10% escalation threshold.** Rejected as
   spending a cycle to reproduce a known result. The architecture proposal's risk register
   sets ASR > 10% as the trigger to escalate to provenance tainting; published work already
   places filter-based defenses far above that for this task class. Escalate directly.

## Consequences

Positive:

- The strongest available defense stays reachable. Capability gating needs to know which data
  is untrusted, and the gateway is the one component that sees every LLM call — so labelling
  there is the substrate Week 7 builds on rather than work thrown away.
- The D ↔ E interface contract the architecture proposal demanded is delivered as a
  first-class artifact instead of being discovered later.
- Stream ownership is respected: E supplies mechanism, D supplies policy. No Week-7 work is
  built in Week 1 without Week-7's context.
- Spotlighting is a transformation rather than a classification, so it adds no false-positive
  surface on a workload made of attack strings.
- Two of P5's six unblock conditions — distinct prompt-payload redaction, and an egress audit
  log — are satisfied by E's retained scope.

Tradeoffs:

- **Sentinel has no injection defense until Week 7.** This is stated rather than mitigated. The
  honest framing is that it also has no agents until then, so there is nothing yet to hijack;
  the risk becomes real exactly when Stream C ships, which is when D's enforcement is due.
- P5's remaining injection-handling unblock condition stays open, so P5 remains on HOLD after
  this work rather than becoming unblocked.
- Spotlighting is bypassable and is not claimed otherwise. It is hygiene, not a control.
- A provenance label is only as good as the discipline of whoever sets it. Mislabelled
  untrusted content is worse than no label, because downstream enforcement will trust it.

## Follow-Up

- Freeze the hook signature and provenance label schema; they are an interface contract, so
  changing them later costs both streams.
- Stand up the evaluation harness (AgentDojo static baseline, then adaptive via AutoDojo or
  [PIArena](https://github.com/sleeepeer/PIArena)) so Week 7 can report a credible before/after
  ASR rather than an assertion.
- Consider producing the missing false-positive dataset for security-testing workloads. No
  published study covers it, Sentinel is unusually well positioned to build it, and it would
  serve the Phase 3 "Security FOR AI" thesis the project treats as its differentiator.
- Never claim prompt injection is prevented. The measured claim is risk reduction with a
  stated attack model, and the project has already committed to that framing.
