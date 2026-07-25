# 0018 Week-10 eval is a deterministic oracle over an observable subset; the LLM judge is measured, not trusted

Date: 2026-07-25

## Status

Accepted (Week-10 shipped — the deterministic oracle over two labelled corpora, the enriched
read-only real surface with a redacted committed capture, the fail-closed CI guard, and the
provenance-conformance judge demonstration; authenticated/state-changing observability remains
deferred with decision 0016).

## Context

Week 10 is "Eval Pipeline & Benchmarking": a benchmark over known-vulnerable endpoints that judges
whether the Fuzzing/Exploit agents identify vulnerabilities *without false positives*, with an
LLM-as-a-Judge (RAGAS or custom). A four-lens red-team of the first plan (assumption-destroyer +
failure-mode NOT-CLEAN, scope-complexity + security-adversary TRIM;
`plans/reports/redteam-260725-0106-week10-*.md`) proved, in code, that the charter's literal surface
collides with the system as built:

- **The observable surface is one endpoint.** `agent/fuzz.py::_fuzzable_targets` admits only public
  GET+read-only+named-param endpoints; over the committed baseline that is exactly
  `/rest/products/search?q=`. Exploit proposals come only from fuzz findings, so a naive per-CWE
  recall + FP-rate over "the observable subset" is vacuous — recall denominator 1, benign observable
  0 → `fp_rate = 0/0`, the project's own "checks that passed because they checked nothing" failure.
- **An LLM judge cannot be the verdict.** 2024–25 research shows frontier judges fail 50%+ of bias
  tests (position/verbosity/style/self-preference); every prior week refused to make an LLM the
  load-bearing arbiter (0012/0015/0017). RAGAS measures RAG-answer faithfulness — the wrong problem
  for "did the agent classify an endpoint as vulnerable without false positives".
- **A first-of-its-kind leak surface.** Week-10 is the first time live target-derived syndicate output
  (`captured/`) is committed to git — the redaction contract is "measured, not trusted" (0017) with
  documented residual gaps, so committing raw output unguarded is a real risk.

## Decision

**Week-10 is a deterministic code oracle over two clearly-separated labelled corpora; recall is an
honest coverage proof over the small read-only observable surface; FP=0 on benign endpoints is the
load-bearing gate; and the LLM judge is built only to be measured — and is shown unfit to be
load-bearing.**

- **Two corpora, never conflated (`evaluation/pentest-eval/`).** A `synthetic:true` corpus
  (`corpus-synthetic.json`) with hand-planted agent output of a KNOWN confusion matrix (TP=3, FP=1,
  FN=3 one-per-stage, TN=2, 1 deferred) exercises the matcher + the `vuln_class→CWE` map exhaustively;
  `tests/week10-eval-test.sh` asserts that exact matrix as independent ground truth (it measures the
  MEASUREMENT, not the agent). A `corpus-real.json` of public GET+param Juice Shop endpoints — the
  known SQLi search plus four benign read paths, labelled from PUBLIC sources, never from a capture —
  is scored over a committed, redacted live `run_syndicate` capture.
- **The oracle is the only verdict.** `measure.py` maps each code-derived `vuln_class` (all seven
  `_vuln_class` labels, `cwe_map.py`) to a CWE category, reusing the Week-1 `benchmark/scoring`
  primitives and the 0002 equivalence table plus an SSTI extension (CWE-94/1336, absent upstream). An
  endpoint is a hit if ANY of its proposals matches the expected category. Recall over the observable
  real-vuln endpoints is reported as coverage; **FP-rate on the benign real endpoints is a hard gate
  (decision 0006)**; each false negative is attributed to the first failing pipeline stage
  (recon/fuzz/exploit). The measured result: the read-only syndicate DOES identify the observable SQLi
  (recall 1/1 coverage) and false-positives on ZERO benign endpoints — a real, non-vacuous pass.
- **Unobservable vulns are deferred, never faked.** Auth/state-changing vulns (login SQLi, IDOR) are
  labelled `observable:false, requires:[…]` and reported in `deferred[]` — never a miss, never a hit
  (deferred to decision 0016).
- **Fail closed + non-vacuous by construction.** The measure exits 2 on an absent/empty corpus or
  capture, AND refuses a corpus without enough real and benign observable rows — so "0% FP" can never
  pass over an absent surface. Every test invariant carries a negative control (a mutated input fails
  the same assertion).
- **The capture is a thin redacted wrapper, and its bytes are re-guarded.** `capture.py` serialises
  only the output of the canonical `agent/supervisor.py` redaction seam
  (`_redact_map/_redact_fuzz_report/_redact_proposal`), runs `use_llm=False` (the oracle scores
  code-derived facts, so no key is needed and it is deterministic), and adds no target host/param
  (egress stays loopback-contained). A fail-closed `EA-LEAK` test re-runs `agent.pii.redact` +
  `trace.redact_persisted` over every committed `captured/`/corpus byte and asserts zero survivors. A
  `manifest.json` binds the corpus hash + the pinned image sha256 so drift is detectable.
- **The LLM judge is built to be measured — and fails the fitness bar.** `judge.py` labels narrative
  coherence against a committed ~12-example human gold set under two provenance conditions. Under the
  security-correct `target-derived` label the injection-hardened gateway models **refuse the grading
  role entirely (conformance 0/12)** — the judge cannot even be instantiated on correctly-labelled
  content. Only by DOWNGRADING trust to `operator` — the exact downgrade the project forbids for
  load-bearing calls — do they respond (12/12); and when they respond they are in fact **accurate**
  (they disagree with the human gold on 0/12), so the finding is not that the judge is *inaccurate*
  but that *reaching it at all requires abandoning provenance discipline*. The result is committed
  once to `judge-calibration.json` (a scorecard, like `runs/`); CI verifies that committed artifact
  exhibits the refusal shape offline and never calls the gateway — the empirical measurement is
  reproduced only by a live `judge.py` run. The demonstration is a refusal count under correct
  provenance, not a rigged disagreement number (the red-team's B3/M4 concern).

## Consequences

- The verdict is a deterministic, committed, regression-guarded number; the FP=0 gate has real teeth
  over benign endpoints; the small read-only recall is reported honestly as coverage with the
  unobservable remainder deferred, not inflated. The LLM judge is demonstrated non-load-bearing on the
  project's own data and provenance discipline.
- Week-10 touches no `agent/`, `benchmark/`, or `rag/` code — it is additive under
  `evaluation/pentest-eval/` + two tests; zero W1–W9 regressions.
- **Deferred (each an explicit decision first):** a larger real corpus once authenticated/
  state-changing observability lands (0016); the judge as a *gated* quality signal only after it can
  be run under correct provenance with a measured 0 FP on security narratives; a live-target eval leg
  in CI (kept offline by design).
