# Execution Plan: Week-10 Eval Pipeline & Benchmark (TDD)

Date: 2026-07-25

## Status

**Active (v2, red-team-reconciled)** — outcome accepted by the user 2026-07-25; four-lens red-team ran
and the plan was reframed on new evidence. Ready for implementation.

Research base: `plans/reports/researcher-260725-0057-week10-eval-pipeline.md`. Four-lens red-team
2026-07-25 (`plans/reports/redteam-260725-0106-week10-{assumption-destroyer,failure-mode,
scope-complexity,security-adversary}.md`): assumption-destroyer NOT-CLEAN, failure-mode NOT-CLEAN,
scope-complexity TRIM, security-adversary TRIM. Every blocking finding is resolved below (see the
reconciliation ledger). The reconciliation ledger is the validate artifact.

## What the red-team changed (the load-bearing reframe)

The assumption-destroyer *ran the code*: `agent/fuzz.py::_fuzzable_targets` (lines 80–93) admits only
public + GET + read-only + named-param endpoints, and over the committed baseline that filter returns
**exactly one endpoint** (`/rest/products/search?q=`). Exploit proposals come only from fuzz findings
(`agent/exploit.py:269`). So a naive "recall + FP-rate over an observable subset" is vacuous: recall
denominator = 1 (result ∈ {0/1, 1/1}); benign observable = 0 → `fp_rate = 0/0`, satisfying the FP=0
gate by the *absence of a surface* — the repo's own "checks that passed because they checked nothing"
lesson.

**User decision (2026-07-25, on this new evidence):** reframe to *enrich the real read-only surface +
a labeled synthetic oracle corpus*. Two clearly-separated corpora, never conflated:

- **Synthetic oracle corpus** (`corpus-synthetic.json`) — hand-planted, `synthetic:true`-guarded
  captured-output records with known TP/FN/FP/TN across every `vuln_class` + benign cases. Gives the
  **oracle (`measure.py`) exhaustive, deterministic teeth**. Measures the *measurement* and the
  classification map — not the live agent.
- **Enriched real surface** (`corpus-real.json` + `captured/`) — public GET+param Juice Shop
  endpoints, **both real-vuln and real-benign** (n≈5–10, read-only/loopback), labelled with
  `expected_cwe` from public Juice Shop/NVD sources (never from a capture — de-circularised), captured
  live once (redacted). Here recall is an honest **coverage/existence proof** and **FP=0 has real
  teeth** because benign real endpoints now exist.

Decision 0018 states all three facts plainly: the real observable surface is small (coverage proof);
the synthetic corpus validates the oracle+classifier; the auth/state-changing observability that would
grow the real surface is deferred (0016). No vacuous number is presented as "the agent was measured
and passed."

## Outcome

A reproducible, offline, fail-closed evaluation framework for the read-only syndicate (Recon →
map-guided Fuzz → Exploit(sim)) with a **deterministic code oracle** as the only verdict. Over the
**synthetic** corpus it computes an exact per-CWE confusion matrix (recall/precision/F₁, reusing
`benchmark/scoring`). Over the **real** enriched surface it reports recall as coverage and enforces
**FP-rate = 0 on real benign endpoints** (decision 0006) as a hard gate. Each false negative is
attributed to the first failing pipeline stage (recon/fuzz/exploit). A narrow **narrative-coherence
LLM judge** is built and **empirically shown to disagree** with the gold-anchored oracle — proving,
not asserting, why it stays non-load-bearing (0012/0015/0017).

## Constraints (non-negotiable)

- Deterministic code oracle is the only verdict. No LLM output is load-bearing in scoring anywhere.
- Offline + pure CI; **fail closed** on absent/empty corpus or capture, AND non-vacuous by
  construction (asserted minimum real + benign rows).
- Real recall = coverage over the enriched read-only surface; deferred vulns reported separately,
  never counted as miss or hit. FP-rate = 0 on real benign endpoints is a hard gate.
- Synthetic corpus is `synthetic:true`, guarded like `agent/sim_dump.assert_synthetic()`; it scores
  the oracle exactly (deterministic → exact-equality gate, no fuzzy margin).
- **Reuse, enforced:** `benchmark/scoring/stats.py` (`ConfusionMatrix`, `recall/precision/f1`) via the
  `sys.path` trick `evaluation/pii-redaction/measure.py` already uses; the 0002 CWE-equivalence table.
  Write fresh only the path/param matcher and the `vuln_class→CWE` map.
- `capture.py` serialises **only** the redacted `run_syndicate()` result (`recon_map`, `fuzz_report`,
  `exploit_proposals`, already through `trace.redact_persisted()`); it never reaches past the
  redaction seam and adds no target parameter (loopback egress stays contained by the existing
  allowlist/gateway).
- Judge: input datamarked; one gateway call; offline fixed threshold on a ~12-example committed gold
  set (no ROC apparatus); **no live LLM in CI** (SKIP without a key, like `recon-agent-test.sh`).
- No secret/PII/target-raw ever committed: a fail-closed leak guard re-runs `pii.redact()` +
  `trace.redact_persisted()` over every committed `captured/`/corpus byte and asserts zero survivors.

## Non-goals

Authenticated/state-changing exploitation (0016); RAGAS; any LLM verdict; live-target in CI;
unbounded prompt-tuning loops; new attack surface; mutating `benchmark/` or `agent/`.

## Module layout

```
evaluation/pentest-eval/
  corpus-synthetic.json     # committed, synthetic:true-guarded: planted TP/FN/FP/TN across vuln classes
  corpus-real.json          # committed: enriched public GET+param endpoints, expected_cwe from public sources
  captured/                 # committed redacted live run_syndicate output the oracle scores the REAL surface over
    recon-map.json  fuzz-report.json  exploit-proposals.json  manifest.json   # manifest binds corpus hash + image sha256
  cwe_map.py                # vuln_class->CWE (7 labels) + template-injection 94/1336 extension over the 0002 table
  measure.py                # oracle: corpus x captured -> confusion matrix (reuses benchmark stats) + stage attribution
  judge.py                  # narrow narrative-coherence judge (datamarked, gateway, SKIP w/o key) + fixed-threshold calibration
  narrative-gold.json       # committed ~12 (signals, narrative) -> coherent/incoherent human labels
  judge-calibration.json    # committed threshold + judge-vs-oracle disagreement CASES (the prove-it)
  capture.py                # MANUAL thin wrapper: redacted run_syndicate() -> captured/ ; no re-orchestration
  baseline-260725.json      # committed metrics snapshot (synthetic exact + real coverage)
  README.md                 # provenance, the two-corpus distinction, image-sha256 pin, known gaps, update policy
tests/
  week10-eval-test.sh       # EA0-EA6 + EA-LEAK + EA9-binding: fail-closed, non-vacuous, FP=0 hard gate
  week10-judge-test.sh      # EA7-EA8: calibration reproducible, gold fail-closed, committed disagreement, no live LLM
```

## Oracle matching (measure.py) — corrected against the code

- `vuln_class→CWE` (all 7 `_vuln_class` labels, `agent/exploit.py:94-114`): `sql-injection-suspected→89`,
  `path-traversal-suspected→22`, `template-injection-suspected→{94,1336}`, `reflected-input-suspected→79`,
  `xss-injection-suspected→79`, `<payload>-injection-suspected→` per-payload, and the two **benign-side
  FP classes** `error-handling-weakness-suspected` / `response-anomaly-suspected` count as *flagged* for
  FP scoring (they are how a benign endpoint produces a false positive). Template 94/1336 are absent from
  the 0002 map → added in `cwe_map.py` (committed extension; `benchmark/` untouched).
- Matcher keys on the **normalised endpoint** (`ExploitProposal.endpoint` carries a `"GET "` prefix and
  **has no `param` field** — `agent/schema.py:159-168`, `_group_findings` drops it), joined to the fuzz
  findings which do carry `endpoint`+`payload_class`. Path+param granularity comes from `corpus`↔fuzz
  findings, not from the proposal.
- Denominators guarded: empty CWE category → reported `n/a`, never `1.0` or a crash.

## Stage attribution

For each FN, first failing stage: recon (was `expected_cwe` present on that endpoint in
`recon-map.json`?) → fuzz (did `fuzz-report.json` emit any signal on it?) → exploit (proposal existed
but wrong class?). Bounded ~15-line function over the already-captured three files; not an engine. On
the real surface, recon-CWE presence is informational (the baseline seeds few endpoint CWEs), so
attribution favours fuzz/exploit stages and says so.

## Judge + the prove-it disagreement (judge.py) — de-rigged

The strawman "narrative literally mentions `signal_kinds` token" is rejected: `_fallback_narrative`
(`agent/exploit.py:152-163`) never emits `server_error`-style tokens, so it would trivially guarantee
disagreement. Instead: (1) the disagreement is anchored to the **committed human gold labels**
(coherent/incoherent), the load-bearing truth; (2) the judged proposals use **real LLM narratives**
(`use_llm=True` through the live gateway), not fallback templates, so the judge's behaviour is real;
(3) `judge-calibration.json` commits the actual disagreement **cases** + the bias type each shows
(verbosity/style), not just a count. The demonstration is the documented catalogue; the oracle
(gold-anchored) is what any gate would use. Live judge run is manual (SKIP without a key).

## Phases (TDD — write the test first; every "absent/zero" claim carries a negative control)

### Phase 1 — Enrich the real read-only surface + capture
Enrich `corpus-real.json` with public GET+param Juice Shop endpoints (real-vuln **and** real-benign,
read-only/loopback), `expected_cwe` cited from public sources. `capture.py` = thin redacted
`run_syndicate()` wrapper; run once live (harness is up: `juice-shop` 127.0.0.1:13000, `sentinel-kong`,
`sentinel-litellm`), `use_llm=True` for real narratives; write `captured/` + `manifest.json`
(corpus hash + image sha256). README.
- **Tests first:** EA0 both corpora well-formed, real pinned to image sha256, real labels cite a public
  source (neg: malformed → fail); EA1 fail-closed on absent/empty corpus **or** capture (neg: emptied →
  exit 2); **EA-LEAK** re-run `pii.redact()`+`trace.redact_persisted()` over committed `captured/`+corpus
  bytes → zero surviving PII/secret shapes (neg: a planted email survives → fail); EA9-binding manifest
  corpus-hash + image-sha256 match (neg: drift → fail).

### Phase 2 — Synthetic oracle corpus + `measure.py`
`corpus-synthetic.json` (`synthetic:true`, guarded; planted TP/FN/FP/TN across all vuln classes +
benign). `cwe_map.py`. `measure.py` (matcher + map + `benchmark/scoring` reuse + stage attribution +
div-0 guards). `baseline-260725.json`.
- **Tests first:** EA1b non-vacuous — synthetic has ≥K real + ≥K benign rows AND `corpus-real` has ≥1
  real-vuln + ≥M real-benign observable endpoints (neg: 0 benign → guard fails, forcing a real surface);
  EA2 exact confusion matrix / per-CWE recall / fp_rate over synthetic, reusing `ConfusionMatrix` (neg:
  mutate one planted label → numbers change); EA3 **FP-rate = 0 hard gate on real benign endpoints** (neg:
  planted proposal on a benign real endpoint → fail); EA4 synthetic recall == committed exact baseline +
  real recall reported as coverage; EA5 every FN → first failing stage ∈ {recon,fuzz,exploit} (neg:
  planted miss per stage); EA6 deferred excluded from recall/fp yet present in `deferred[]` (neg: a
  deferred row is neither miss nor hit).

### Phase 3 — Narrative judge + gold + prove-it disagreement
`judge.py` (datamarked input, gateway, SKIP w/o key), `narrative-gold.json` (~12), `judge-calibration.json`
(fixed threshold + disagreement cases + bias type).
- **Tests first:** EA7 calibration/threshold reproducible over committed gold, fail-closed on absent gold,
  **no gateway call in CI**; EA8 committed disagreement artifact exists, cases are gold-anchored with real
  narratives, oracle (not judge) is load-bearing (neg: absent gold → fail).

### Phase 4 — CI wiring + docs + decision
`tests/week10-eval-test.sh`, `tests/week10-judge-test.sh`. EA9: run all W1–W9 suites → zero regressions.
Decision **0018** (deterministic oracle over two labelled corpora; real surface small/coverage; synthetic
validates the oracle; judge measured not trusted; auth/state-change deferred 0016). README + journal.

## Red-team reconciliation ledger (validate artifact)

| Finding | Lens | Resolution |
|---|---|---|
| B1 observable set = 1 endpoint | assum | Reframe: enrich real surface (vuln+benign) + synthetic oracle corpus; Decision 0018 states it plainly |
| B2 real capture TP-only; tests prove arithmetic only | assum | Synthetic corpus is the labelled oracle teeth (honestly synthetic); real = coverage; EA2 scoped to matcher; 0018 explicit |
| B3 judge disagreement rigged by strawman oracle | assum | Anchor to human gold labels + real LLM narratives; commit disagreement cases + bias type |
| H1 7 vuln_class labels, plan mapped 4 | assum | `cwe_map.py` maps all 7; benign-side classes count as flagged for FP |
| H2 no `param` field, `"GET "` prefix | assum | Matcher normalises endpoint, joins fuzz findings for path+param; no param on proposal |
| H3 / M1(fail) CWE 94/1336 absent from 0002 map | assum/fail | Committed extension in `cwe_map.py`; `benchmark/` untouched |
| M1 baseline lacks endpoint CWEs; circular labels | assum | Real labels from public Juice Shop/NVD; capture used only for scoring |
| M2 stage attribution collapses to recon | assum | Attribution favours fuzz/exploit; recon-CWE informational; documented |
| C1 vacuous recall on empty observable-real | fail | EA1b asserts ≥ real rows; synthetic guarantees non-empty |
| C2 FP vacuous with no benign | fail | EA1b asserts ≥ benign rows; FP=0 gate over real benign endpoints |
| H1(fail) margin undefined/circular | fail | Synthetic → exact-equality gate (deterministic, no margin); real → coverage report |
| H2(fail) capture↔corpus↔digest unbound | fail | `manifest.json` binds corpus hash + image sha256; EA9-binding asserts |
| H3(fail) div-by-zero per-CWE/fp | fail | Denominator guards; empty category → `n/a` |
| H4(fail) capture reproducibility | fail | Real capture committed once as record + caveats; synthetic fully deterministic |
| M2(fail) EA7 could smuggle live LLM | fail | EA7 uses committed artifacts only; no gateway in CI |
| M3(fail) use_llm=False templated narratives | fail | Judge capture runs `use_llm=True` via the up gateway |
| M4(fail) disagreement>0 gameable | fail | Commit disagreement cases + bias type, gold-anchored; not a bare count |
| F1 judge calibration gold-plated | scope | Gold ~12, fixed documented threshold, no ROC |
| F2 measure.py re-hand-rolls scoring | scope | Enforce `benchmark/scoring/stats.py` reuse; write only matcher + map fresh |
| F3 capture.py a new harness | scope | Thin wrapper over redacted `run_syndicate()`; can't bypass redaction |
| F4-6 attribution/EA2/EA0 bounds | scope | Attribution ~15 lines; EA2 tests the matcher not arithmetic; EA0 pins image sha256 |
| H1(sec) no leak guard on committed captured/ | sec | **EA-LEAK** fail-closed re-redaction guard over committed bytes |
| H2(sec) capture object source unspecified | sec | Serialise only redacted `run_syndicate()` result |
| M1(sec) capture target param | sec | No target param; reuse loopback allowlist/gateway, don't bypass |
| M2(sec) key handling | sec | Key from `infra/.env`, never persisted, SKIP without |
| L1/L2(sec) datamark judge input; CI posture | sec | Datamark narrative input; week10 CI stays zero-network/no-key |

## Validation

- `bash tests/week10-eval-test.sh` — EA0–EA6 + EA-LEAK + EA9-binding green; every negative control fails
  as designed.
- `bash tests/week10-judge-test.sh` — EA7–EA8 green; live judge SKIP documented.
- Full W1–W10 suite green (EA9). Metrics committed in `baseline-260725.json`; disagreement cases in
  `judge-calibration.json`.

## Risks & rollback

- Real observable **vuln** endpoints may still be few (perhaps 1–3) even after enrichment; that is
  honestly reported as coverage, with FP=0 carrying the load over the several benign endpoints and the
  synthetic corpus carrying oracle breadth. Not inflated.
- Live capture depends on the running pinned harness + gateway key (both confirmed up). If regenerated
  later, `fuzz_signals` live-state sensitivity may shift TP/FN — the committed capture is the record;
  reproduction caveats are documented; the synthetic corpus is deterministic.
- Additive under `evaluation/pentest-eval/` + two tests + one decision; revert removes it with no W1–W9
  behavior change.

## Deferred (named)

Authenticated/state-changing observability (0016) — unlocks the currently-unobservable CVEs and a larger
real corpus; the judge as a *gated* quality signal only once its FP on security narratives is shown 0.
