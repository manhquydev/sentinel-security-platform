# Project Sentinel Charter — Completion & Rubric Self-Assessment

**Product:** Charter only. Workbench is a separate product and is not Charter
evidence.  
**Spec:** `docs/Project_Sentinel_6-week.md` (local assignment).  
**Authority:** `docs/product/sentinel-charter-brief.md`,
`docs/sentinel-six-week-as-built-architecture.md`.  
**Verified:** 2026-08-20, from this repository, slim `.venv` plus optional-dep
overlay. No live Kong / Vertex run today.

## 1. Verdict

Charter meets every item in **Yêu cầu tối thiểu để đạt** and exceeds it: three
scanners (Semgrep / Nuclei / Trivy) with redaction, a typed Week-1/Week-2
normalizer, a provenance-bound analysis agent that publishes JSONL without
inventing endpoints, a fixed-catalog Python executor behind Kong ACL + a
dedicated API key, Ed25519 HITL that refuses to send on reject, IPI quarantine
plus labeled PII redaction with Pass/Fail tests, and a README + 10–15 minute
demo spine. Remaining gaps are operator-gated live runs (`infra/.env`, Vertex
ADC, Kong) or optional-dependency suites already green when those packages are
installed — not missing Charter behavior. Workbench stays out of this grade.

## 2. Rubric

| Bucket | Status | Evidence |
|---|---|---|
| **(1) Hệ thống hoạt động — 30%** End-to-end wiring, components connect, basic errors handled | **Meets and exceeds.** Offline path is complete and reproducible. Live 9-step run is operator-gated, not unimplemented. | Scanners: `scanners/run-semgrep.sh`, `scanners/run-nuclei.sh`, `scanners/run-trivy.sh`, `scanners/redact-report.sh`, `scanners/image-pins.env`, CI `.github/workflows/security-scan.yml`. Normalize: `agent/normalize_findings.py`, `agent/normalize_week1_artifacts.py`. Compose + controller: `scripts/sentinel-charter-up.sh`, `scripts/sentinel-demo.sh`, `scripts/sentinel-live-preflight.sh`. Gateway: `infra/kong/`. Fail-closed empty/malformed input: `tests/test_charter_contracts.py`, `tests/test_week3_aggregate_analysis.py`. Timeout / connection: `agent/charter_requests.py` (`TIMEOUT_SECONDS`, `ConnectionError` cases in `tests/test_charter_requests.py`). |
| **(2) Chất lượng AI Agent — 20%** Evidence-bound analysis, structured output, limited hallucination, proposals match data | **Meets and exceeds.** Model may enrich wording only; facts and request paths are code-owned. | Analysis: `agent/week3_analysis.py` (groups duplicates, severity, deterministic VI prose + optional enrichment), `agent/recon.py`, system prompt `agent/prompts/charter-system-prompt.md`. Knowledge: `rag/retrieve.py`, `rag/charter-corpus-manifest.json`, `rag/charter-examples/`. Structured JSONL: `Week3ReportFinding` / `propose_report_jsonl`. No invented endpoints: `tests/test_charter_contracts.py` (`test_model_invention_rejects_all_publication`, empty/malformed makes no model call). Proposals only from `SAFE_REQUEST_CASES` in `agent/charter_requests.py` via `agent/charter_proposal.py` — finding locations never become path/query/body (`tests/test_charter_proposal.py`). |
| **(3) An toàn hệ thống — 20%** Allowlist, HITL, IPI protection, PII redaction | **Meets.** Load-bearing controls are isolation + catalog + HITL + gateway; the IPI regex is a measured extra, not the guarantee. | Allowlist: `scanners/target-allowlist.sh`, Kong ACL in `infra/kong/kong.declarative.yml.tmpl` / `infra/kong/README.md` (fail-closed groups; Charter paths `/sentinel-charter/rest/products/search` and `/sentinel-charter/rest/basket`). HITL: `agent/charter_approval.py` (Ed25519 approve/reject/revoke), `scripts/sentinel-charter-approve.py`; reject never mints or sends (`tests/test_charter_requests.py`). IPI: `agent/charter_response_guard.py` + fixtures `tests/fixtures/charter-response-ipi-goal.json`, `tests/fixtures/charter-response-ipi-secrets.json`; untrusted data labeling `docs/decisions/0006-the-gateway-labels-provenance-it-does-not-detect-injection.md`. PII: `agent/pii.py`, `evaluation/pii-redaction/measure.py`, `tests/test_week5_labeled_redaction.py`. |
| **(4) Chất lượng mã nguồn — 15%** Clear structure, README, tests, no secrets in source | **Meets.** Slim grader is the published contract; optional deps are documented, not hidden. | Layout: `scanners/`, `agent/`, `rag/`, `infra/kong/`, `scripts/`, `evaluation/`. README ritual: root `README.md`. Tests: `pytest.ini` (slim default), `docs/operations/full-test-suite.md` (overlay). Secrets: `infra/.env` gitignored; template `infra/.env.example`; pins only in `scanners/image-pins.env`. Kong template uses `${PLACEHOLDER}`s; rendered config is gitignored. Raw scan output stays out of git (`scanners/out/` is gitignored; see §4). |
| **(5) Tài liệu và trình bày — 15%** Architecture, product value, limits, stable demo | **Meets.** | Architecture: `docs/sentinel-six-week-as-built-architecture.md`. Product 1–2 pages: `docs/product/sentinel-charter-brief.md`. Limits + next: brief §Limitations / §Next steps, this file §4–5. Week reports: `docs/reports/week-01.md` … `week-06.md`, index `docs/reports/index.md`. Demo 10–15 min: `docs/operations/sentinel-charter-demo-runbook.md`, facade `scripts/sentinel-week5-demo.py` + `infra/week5-demo/`. Live runbook: `docs/operations/sentinel-live-acceptance-runbook.md`. Site: `website/`, https://vinsoc.manhquy.id.vn. |

### Minimum-bar checklist (Yêu cầu tối thiểu để đạt)

| Minimum item | Owner | Status |
|---|---|---|
| Run a SAST or DAST tool | `scanners/`, `.github/workflows/security-scan.yml` | Met (Semgrep + Nuclei + Trivy) |
| Normalize scan results | `agent/normalize_findings.py`, `agent/normalize_week1_artifacts.py` | Met |
| Agent produces a security report | `agent/week3_analysis.py`, sample `docs/reports/artifacts/` | Met |
| At least one custom Python tool | `agent/charter_requests.py` | Met |
| Test requests go through the API gateway | `infra/kong/`, executor `scripts/sentinel-charter-executor.py` | Met (live send still needs operator Kong) |
| Endpoint allowlist | `infra/kong/`, `scanners/target-allowlist.sh` | Met |
| Manual approval step | `agent/charter_approval.py`, `scripts/sentinel-charter-approve.py` | Met |
| Prompt-injection tests | `agent/charter_response_guard.py`, `tests/test_charter_contracts.py`, IPI fixtures | Met |
| Sensitive-data redaction | `agent/pii.py`, `evaluation/pii-redaction/` | Met |
| README and final demo | `README.md`, `scripts/sentinel-demo.sh`, demo runbook | Met |

Advanced items named as optional in the spec (Multi-Agent, MCP/A2A, GraphRAG,
vLLM, LLM-as-a-Judge) are correctly **not** claimed as Charter completion.

## 3. Test evidence (verified 2026-08-20)

Commands run from the repository root. Slim venv: `.venv` from
`requirements.txt`. Optional overlay: packages already present in this
`.venv` (pydantic / jsonschema / pyyaml / etc.); not `rag/requirements.txt`.

| Suite | Command | Result |
|---|---|---|
| Slim grader default (`pytest.ini` ignores) | `.venv/bin/python -m pytest -q --tb=no` | **338 passed** |
| Grader trio (README / week-05 / week-06 ritual) | `.venv/bin/python -m pytest tests/test_week5_labeled_redaction.py tests/test_charter_requests.py tests/test_week5_demo_facade.py -q` | **102 passed** |
| PII eval | `.venv/bin/python evaluation/pii-redaction/measure.py` | recall **10/10**, FP **0/10**, **PASS** |
| Week-5 demo facade | `PYTHON=.venv/bin/python bash tests/week5-demo-facade-test.sh` | **19 passed** (plus compose loopback check) |
| Week-1 reproducibility | `bash tests/readme-week1-reproducibility-test.sh` | **50 passed / 0 failed** |

Extended Charter files that `pytest.ini` excludes (optional deps). Combined
invocation today: **140 passed** (16 of those are `test_week3_aggregate_analysis.py`;
an older overlay note listed 15).

| File | Passed |
|---|---|
| `tests/test_gateway_guardrails.py` | 61 |
| `tests/test_attack_surface_baseline.py` | 11 |
| `tests/test_charter_rag.py` | 8 |
| `tests/test_charter_contracts.py` | 12 |
| `tests/test_charter_proposal.py` | 11 |
| `tests/test_charter_trivy.py` | 5 |
| `tests/test_week1_artifact_normalizer.py` | 16 |
| `tests/test_week3_aggregate_analysis.py` | 16 |

The only remaining `pytest.ini` `--ignore` is
`tests/test_workbench_phase3_boundary_scripts.py`: a **Workbench** boundary
check that needs Docker. Out of Charter scope. Do not fold it into the grade.

Historical live gateway numbers (not re-run today) stay in
`docs/reports/week-04.md` (2026-08-14): `tests/test_charter_requests.py` 67
passed; `REQUIRE_KONG=1 tests/gateway-authz-test.sh` 43 passed. Week-6
scorecard `evaluation/charter-eval/charter-evaluation.json` is a committed
dry-run (`live_run = false`); a live FP/FN table needs an operator 0600 run.

## 4. Residual risks / honest limits

- **IPI filter is English-regex.** `agent/charter_response_guard.py` `_ATTEMPTS`
  matches ignore/change-objective, reveal-secret, and run-tool phrasing. Isolation
  is the load-bearing control by design: target/scanner/RAG bytes are untrusted
  data (`agent/prompts/charter-system-prompt.md`, decision 0006); the catalog
  cannot invent paths; the live response is persisted as a digest, not fed back
  to the LLM. Do not grade the regex as a prompt-injection *preventer*.
- **Live 9-step E2E and live FP/FN scorecard are operator-gated.** They need
  `infra/.env`, Vertex ADC (`VERTEXAI_ADC_PATH`), and a healthy Kong. Offline
  contracts do not substitute for one fresh `scripts/sentinel-demo.sh` run
  recorded in `docs/operations/sentinel-live-acceptance-runbook.md`.
- **Semgrep baseline targets WebGoat, not Juice Shop.**
  `docs/product/juice-shop-attack-surface-baseline.md` excludes Semgrep/SAST
  rows because the Week-1 ruleset is Java-only (`scanners/rulesets/owasp-local.yml`)
  against WebGoat/OWASP Benchmark, not a Juice Shop tree. Juice Shop DAST/SCA
  evidence is Nuclei + Trivy.
- **Raw scan JSON is NOT in git (audited 2026-08-20).** `git ls-files
  scanners/out` is empty on every ref; `.gitignore` ignores the whole
  `scanners/out/` directory, so `semgrep.json` / `trivy.json` / `nuclei.jsonl`
  (and the `.san.*` companions) exist only as local, untracked, secret-bearing
  working artifacts — never committed. The one real drift is documentation:
  week-01 prose says "`.san.*` live in this repo," but the committed durable
  Week-1 evidence is actually `artifacts/week1.aggregate.jsonl` +
  `artifacts/week1.aggregate.manifest.json`. Not a functional gap.
- **Juice Shop remains on host loopback `127.0.0.1:13000`.** Kong is the
  sanctioned agent path; an on-host process can still skip it
  (`infra/kong/README.md` residuals).
- **Charter ≠ Workbench.** Do not use Workbench corpus, CMC, or
  `scripts/workbench-up.sh` output as Charter acceptance.

## 5. Next steps

Production-shaped deploy is the GCP VM kit in `infra/gcp/` (`deploy.sh`,
`remote-bootstrap.sh`, `README.md`): same Compose owners as local Charter,
SSH/IAP only, Juice Shop private-by-construction (no public app ports). That
is operator infrastructure, not a missing rubric item.

Optional six-week extras (syndicate, GraphRAG, LLM-as-a-judge, FinOps) remain
bonus scope in `docs/product/sentinel-charter-brief.md`. They are not required
to close Charter.
