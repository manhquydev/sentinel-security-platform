# 0027 The LLM belongs in the generative role, on absence-of-control classes — measured, bounded, and not transferable yet

Date: 2026-07-26

## Status

Accepted, with the bounds below treated as part of the claim rather than as caveats to it. Supersedes
nothing; **narrows** the project's standing "AI loses every comparison" position, which decisions
0018–0021 established for a role class that is not this one.

## Context

Every AI role this project had ever measured was a **verdict/gate** role — judge (0018), false-positive
verifier (0020), ranker (0021) — and the architecture forbids an LLM to hold any of them (a structural
test, DD1, asserts no model is reachable from the verdict path). The results were consistent: refuse,
lose, or tie.

From that the project had generalised to "every measured AI-vs-deterministic comparison ended badly for
AI". A meta-analysis of the lab's own history showed that generalisation was **structurally
incomplete**: the **generative** role — *the model proposes, deterministic code disposes* — had **zero
measurements**, because the one plan to test it was cancelled at a red-team gate.

Meanwhile decisions 0022–0024 had established where deterministic tooling is blind: **absence-of-control
classes** (CWE-307 no auth-attempt limit, CWE-639 IDOR, CWE-200 information exposure, CWE-862/306
missing authz/authn). An absent control writes no token, so pattern matching has nothing to match.
Measured recall there is ~0–6.8%.

That is the one place where a proposer cannot be beaten by the deterministic baseline, because the
deterministic baseline is approximately nothing.

## Decision

**The LLM's measured place in this system is the generative role on absence-of-control classes: it
proposes, deterministic code disposes, and no model is ever consulted about its own output.**

Evidence (E16a, E16b, E17; preregistered per `docs/research-protocol.md`):

| comparison | result | what it establishes |
|---|---|---|
| **PRIMARY (preregistered, two-sided):** vulnerable files vs clean control files | 10/60 = 0.167 vs 1/40 = 0.025, **p = 0.024** | the model **discriminates** — both arms could have scored |
| specificity | **1 of 40** clean files drew a false absence-class claim | it is not flagging indiscriminately |
| class attribution (post-hoc, exploratory) | **6 of 10** flags named the ground-truth class | 4 flagged the file for an unrelated issue |
| capability gap vs deterministic engines, identical files | model 6/60 · **engines 0/60** | the engines emit 33 CWE classes, **none absence-class** — a *capability statement*, not a contest (see below) |

The p-values against the deterministic arm (0.0137 / 0.00065) are **not quoted as the headline**: that
arm is structurally incapable of scoring, so a significance test against it overstates what happened.

**Bandit and Semgrep together flagged an absence-class CWE in zero of sixty files.** Not approximately
zero — zero. This is the first capability measured in this project that deterministic tooling cannot
supply at all.

> **How to state this correctly (framing correction, same day).** That zero is **structural, not
> sampled**: across 12 corpus repositories these engines emit **33 distinct CWE classes and not one is
> absence-class** — the rulesets have no rule that can express an absent control. A Fisher test between
> the two arms is therefore arithmetically valid but rhetorically misleading, because it implies a
> contest one side could never enter. **The supported claim is capability addition, not superiority:**
> the deterministic layer cannot express this class; the model names it in 10% of files. The genuinely
> two-sided result is the preregistered primary — vulnerable vs clean control files, p = 0.024.

The result was preregistered, powered in advance by simulation (83%), replicated on a sample **disjoint**
from the exploratory run, gated by a positive control, and scored by a deterministic classifier audited
against synthetic cases before any data was seen.

## The bounds are part of the claim

1. **It is a weak detector.** 10% class-attributed hit rate. Six of seven vulnerable files are missed.
2. **It is file-level, not line-level.** No model would emit machine-readable structure — five aliases ×
   three formats × an assistant prefill produced **zero** format compliance while correctly identifying
   planted defects (E16a). The disposal layer therefore consumes prose.
3. **A third of calls are non-answers** (33% on vulnerable files): the model asks a question or returns a
   refactor instead of a review.
4. **Contamination is unresolved and may be fatal to transfer.** RealVuln is public and its repos carry
   `llm_generated_corpus: true`. This measures capability and memorisation **inseparably**. Nothing here
   may be promised for a client's private code.
5. **One model, one corpus, one language.**

## Consequences

- **The project's headline claim is formally narrowed and is now two-part:** in **gate roles** the
  deterministic method wins or ties (0018–0021, repeatedly); in the **generative role on absence
  classes** the LLM supplies signal deterministic tooling cannot (this decision). Stating only the first
  half — as the Week-12 business case originally did — overclaims.
- **Architecturally nothing loosens.** The model still never holds a verdict. DD1 stands. What changes is
  that the model now has a *measured* place rather than a place justified only by architecture.
- **The business case may cite this only with the contamination bound attached**, and must not promise
  per-client transfer. What is sellable today is the deterministic layer plus the bounded AI cost; this
  finding is a **research result and a roadmap item**, not a shipped capability.
- **Next experiment, already specified:** a control arm of files that are **messy but contain no
  absence-class vulnerability**, to separate "reacts to mess" from "detects absent controls"; and a
  target the model cannot have memorised, to test transfer. Until the latter exists, generalisation is
  unproven by construction.
- **Recorded process failure:** the deterministic control arm was preregistered and the implementation
  silently dropped it during a redesign. It was caught before publication and run. The mechanism claim
  was withdrawn on a weaker comparison and then partially restored by the correct one — both movements
  are in the research log, in order.
