# AI-SAST guided-question verifier — DESIGN (Phase 0)

Design for the clean-room verifier + FP-trap scorer the plan
`docs/plans/active/2026-07-25-ai-sast-inherit-and-upgrade.md` gates. **No product code exists yet.**
This is the Phase-0 artifact; the Phase-1 spike is built only after this is accepted and the RealVuln
scout confirms the corpus facts (§5, currently pending
`plans/reports/researcher-260725-1015-realvuln-corpus-scout.md`).

Decisions locked (user, 2026-07-25): **clean-room re-implement the method** (inherit VulnHunterX's
*approach*, never its templates/source — LGPL-2.1); **measure-first spike bar**; **the verifier verdict
is measured, never load-bearing**.

## 1. What the verifier is (and is not)

A deterministic pipeline with ONE narrow LLM step that TRIAGES raw SAST findings into
`{keep | likely-false-positive | unknown}` — to raise precision on the noisy static phase without
dropping real vulnerabilities. It is **not** a detector (the SAST engine detects) and its verdict is
**not** trusted: it is scored against a labelled FP-trap corpus, and on the syndicate path a verdict
that cannot be structurally validated is discarded, not obeyed.

Why this is honest and novel: the landscape (VHX Vulnhalla, SAIST detect→validate, Metis
evidence-anchoring) all converge on "the LLM verifies over tool evidence." Sentinel's contribution is to
run that verification through its **provenance gateway** with a **structural verdict-integrity gate** and
to **measure** the FP-reduction on real traps — the Week-7/10 discipline ("the LLM is measured, the
structure holds") applied to static SAST.

## 2. Pipeline (single-turn, provenance-safe)

```
SAST engine (Semgrep/OpenGrep) on target source
  → SARIF findings  {rule_id, cwe, file, line, code_slice, message}
  → [deterministic-first gate]  high-precision rule allowlist -> auto-KEEP (no LLM); else ↓
  → [verifier]  ONE gateway call per residual finding:
        msg[0] operator      : the rubric + the CWE-specific yes/no question set (Sentinel-authored)
        msg[1] target-derived : the code slice + the finding  (datamarked; spotlighted by the gateway)
      -> structured reply {answers[], verdict ∈ {keep, likely-fp, unknown}, confidence}
  → [verdict-integrity gate]  reject/none-trust a reply that is unparseable, cites a CWE not in the
     finding, or "keeps" by inventing an unobserved sink  -> forced to `unknown`
  → residual verdicts + auto-KEEPs  ->  scored against the labelled corpus (§4)
```

**Single-turn only.** Exactly one `operator` message and one `target-derived` message per finding — no
accumulated assistant turns. This sidesteps the multi-turn provenance-schema hole the red-team found
(the gateway validates provenance statelessly with only `operator`/`target-derived`; an assistant turn
fits neither, and elevating it to `operator` is the forbidden trust inversion). Dynamic context
expansion (VHX's multi-turn "ask for callers/structs") is **deferred**; the spike uses the SARIF
`code_slice` + a bounded N lines of surrounding context extracted deterministically (tree-sitter/regex),
never an LLM-driven fetch loop.

**Clean-room questions.** Per CWE class, a SMALL Sentinel-authored yes/no set probing exploitability,
e.g. CWE-89: "Is the flagged value derived from request input?", "Is it concatenated into the query
rather than parameter-bound?", "Is there an intervening validator/escaper?". Authored from first
principles against the CWE definition — **not** copied from VHX's 394 templates (copyrightable).

## 3. Verdict-integrity gate (replaces the false "guard.py wraps verdicts" claim)

`agent/guard.py` cannot adjudicate a TP/FP verdict (it only catches a narrative contradicting
code-computed severity/CWE). So the verifier ships its OWN narrow, deterministic checks — the only
things code CAN assert about an LLM verdict:

- **Parse integrity:** the reply must be the exact structured shape; else `unknown`.
- **No CWE fabrication:** the verdict may only speak to the finding's OWN `cwe`/`rule_id`; a reply
  asserting a different vuln class is discarded (`unknown`).
- **No unsupported "keep":** a `keep` must reference a signal present in the finding/slice; a `keep`
  justified by an invented sink is downgraded to `unknown`.
- **Fail-safe direction:** `unknown` NEVER silently drops a finding — it falls back to the raw SAST
  verdict (keep). The verifier can only *reduce false positives it can justify*, never hide a real one
  on a parse/guard failure. This makes the recall floor structurally hard to breach by LLM misbehaviour.

## 4. FP-trap scorer (net-new — NOT `benchmark/scoring` reuse)

`benchmark/scoring` is OWASP-Java per-test-case; the FP-trap corpus is finding-level. New scorer,
reusing only the pure `ConfusionMatrix`/`recall`/`precision` primitives from `benchmark/scoring/stats.py`
and the CWE→category idea. Unit = **one SAST finding** matched to a corpus label (TP-vuln vs FP-trap).

**Pre-registered metric (gameable-proofed, per the red-team):**
- **Denominator = the LLM-triaged residual** (findings the deterministic gate did not auto-keep) — so
  the gate's contribution is never counted as the LLM's.
- **Ablation = LLM-marginal-over-gate:** compare (gate only) vs (gate + verifier), not pipeline-vs-raw.
- **FP-reduction** = fraction of residual FP-traps the verifier correctly marks `likely-fp`.
- **Hard recall floor:** the verifier must mark ≥ (1 − ε) of residual true-positives `keep`; breaching
  the floor fails the spike regardless of FP-reduction. ε committed (measure-first).
- **Held-out split:** any question/threshold tuning happens on a dev split; the reported numbers are on
  a frozen held-out split (no fitting on the test).
- **Fail-closed corpus:** assert `loaded_findings ≥ manifest_count` (the 0017/0018 non-vacuity gate);
  refuse to report over an absent/short corpus.
- **Measure-first bar:** run raw-SAST + gate + verifier once, record the baseline, set "proceed" just
  above the gate's precision at the recall floor. A miss is an accepted, documented negative result — no
  module gets built (like Week-10's judge).

**Cost:** live-LLM, thousands of calls; the deterministic-first gate + a per-run budget/kill-switch
(reuse `agent/finops.py`) bound it; verdict OUTPUTS are committed as fixtures so the *scoring* re-runs
offline in CI.

## 5. Corpus + fetch (RealVuln — verified facts, `researcher-260725-1015-realvuln-corpus-scout.md`)

- **License: Apache-2.0** (verified primary-source). Fetched at eval time, **never committed** (the
  `benchmark/targets/` pattern: commit manifest + scorer + `fetch.sh`, gitignore the data). NOTICE/
  attribution preserved.
- **Shape:** 66 Python-web repos (Django/FastAPI/Flask), **2,176 findings = 1,903 vulns + 279 FP-traps**;
  ~133 MB shallow-clone. Ground truth per finding: `{file, cwe, line, is_vulnerable: bool}` — the
  **`is_vulnerable:false` FP-traps are the load-bearing signal** (rule-SAST scores ~14.4% F3, so there is
  real FP headroom to measure). 18 web CWE families (SQLi/XSS/SSRF/authz/path-traversal…).
- **Matching (mirror the benchmark):** a SAST finding matches a ground-truth item on **file + CWE
  category + line within ±10**. So the spike runs **Semgrep** (the lake's existing engine) on the fetched
  source → Semgrep findings → match to RealVuln truth: matched to `is_vulnerable:true` = TP candidate;
  matched to a trap (`false`) or unmatched-but-flagged = FP candidate. The verifier then triages the
  residual; the scorer compares to the labels.
- **Pin:** no release tags — pin the per-repo commit SHAs from the upstream `benchmark-manifest.json`
  (copied into our committed manifest); `fetch.sh` shallow-clones exactly those SHAs and fails closed if
  a clone drifts from the pinned SHA.
- **Spike subset (bounded, honest):** the viability spike does NOT need all 66 repos. Use a committed
  **dev + held-out split** of a handful of repos covering the top CWEs *with their traps* — enough to
  measure LLM-marginal-over-gate precision at the recall floor without an unbounded LLM bill. The
  full-corpus run is the follow-on only if the spike passes. RealVuln's own metric is **F2** (recall 4×
  precision); we report F2 alongside the pre-registered precision-lift-at-recall-floor so the number is
  comparable to the public leaderboard.

## 6. Module layout (Phase 1, additive)

```
agent/verifier/
  questions/<cwe>.json    # Sentinel-authored yes/no question sets (clean-room)
  verify.py               # single-turn gateway triage + verdict-integrity gate
  gate.py                 # deterministic-first high-precision rule allowlist
evaluation/sast-fp-discrimination/     # renamed to avoid the evaluation/false-positive/ collision
  manifest.json  scorer.py  fetch.sh  baseline-<date>.json  captured/   # verdict fixtures
tests/
  ai-sast-verifier-test.sh   # verdict-integrity + scorer + fail-closed corpus, with negative controls
```

## 7. Non-goals / deferred
VHX code or templates; CodeQL; multi-turn dynamic context; C/C++ fuzzing; OpenGrep/gosec/Bandit
foundation (separate initiative); `evidence_paths[]` schema change; any build before this DESIGN is
accepted and the spike bar is set.
