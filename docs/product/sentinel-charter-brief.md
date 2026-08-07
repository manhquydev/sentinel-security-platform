# Sentinel charter brief

**Hợp đồng sản phẩm công bố** của Project Sentinel — đồ án / lab 6 tuần
(nghiên cứu–giáo dục, VinUni × VinSOC). Đây là bản 1–2 trang mô tả sản phẩm
Charter đã giao; không phải product SaaS. Văn bản assignment đầy đủ và tài liệu
cá nhân chỉ giữ local, không thuộc cây public.

The separate [Sentinel Security Research Workbench](sentinel-security-research-workbench.md)
does not inherit this Charter's target, approval flow, capstone completion, or
evidence claims. Its CMC inventory is not Charter evidence.

Đọc thêm (tiếng Việt, cửa vào monorepo): root [`README.md`](../../README.md),
bản đồ [`docs/README.md`](../README.md), báo cáo tuần [`docs/reports/`](../reports/index.md).

## Problem — Vấn đề cần giải quyết

Web-application security testing produces high-volume, tool-specific output
(SAST/DAST/SCA) that is tedious to triage, and teams increasingly want an LLM to
help. But a naive LLM assistant hallucinates findings, follows malicious
instructions embedded in target responses (prompt injection), and can leak
secrets or personal data into prompts and logs. Sentinel addresses both halves:
turn raw scan output into a grounded, evidence-based security report **and**
harden the AI doing it so it stays safe and honest.

## Users — Người sử dụng

Security/AppSec engineers and security students working against a deliberately
vulnerable target in a sandbox. The output serves two audiences: a technical
reader who wants evidence, locations, and remediation, and a non-technical
reviewer who approves or rejects any active test through a human-in-the-loop
gate.

## Value — Giá trị của sản phẩm

One reproducible command drives the full flow: run a scanner → normalize to a
unified finding schema → retrieve grounding from a local OWASP/CVE knowledge base
→ produce a JSONL security report that is evidence-bound (no invented endpoints
or vulnerabilities) → propose a safe test request → require human approval → send
only through the Kong gateway → filter the response for prompt injection and
personal data → record the run with metrics and a private audit trail. Every
finding byte reaches the model labelled as untrusted target-derived data, and the
report preserves scanner facts rather than inferring new ones.

## Scope — Phạm vi hiện tại

- Target: OWASP Juice Shop on loopback `http://127.0.0.1:13000` only, behind a
  fail-closed allowlist. No external or redirect targets.
- Scanners: Semgrep (SAST), Nuclei (DAST), Trivy (secret/misconfig/SCA), with
  mandatory redaction before any storage; CI runs digest-pinned Trivy on push.
- Analysis: a provenance-bound agent (`agent/recon.py`) with a stored system
  prompt (`agent/prompts/charter-system-prompt.md`); the live structured-output
  report path runs on Vertex AI Gemini Flash Lite via the LiteLLM gateway.
  Week-3 aggregate analysis (`agent/week3_analysis.py`, schema
  `week3-analysis/v1`) is accepted by `propose_report_jsonl` after
  validate-then-project into grounded `ReportFinding` rows. Proposals still
  come only from the fixed SAFE_REQUEST catalog; finding locations never become
  path, query, or body. This closes the week3→proposal schema split only—it is
  not free-form request invention and is not Workbench or CMC evidence.
- Gateway: Kong fronts the app; identities use short-TTL OAuth2 plus fail-closed
  ACL. The charter executor additionally presents a dedicated API key on two
  exact `/sentinel-charter/...` routes; the key is removed before OAuth denial,
  upstream proxying, and audit logging.
  It accepts only six compiled safe cases: baseline, empty, special-character,
  and 256-character product-search queries, plus empty-object and wrong-type
  basket POST bodies. Every POST needs approval and must produce a 4xx
  non-mutation receipt.
- Guardrails: prompt-injection quarantine, human approve/reject, PII redaction,
  and gateway secret-redaction on all model egress.
- Topology startup: from the repository root, `bash scripts/sentinel-charter-up.sh`
  starts the existing Compose owners after its private-configuration, ADC,
  DefectDojo, and fresh-Kong prerequisites are present. It does not scan, import,
  run the controller, obtain approval, execute a request, or verify service health;
  success is not a fresh completed Charter run. See
  [`scripts/sentinel-charter-up.sh`](../../scripts/sentinel-charter-up.sh) for the
  executable contract.
- Run it with `bash scripts/sentinel-demo.sh run --profile charter --run-id demo`.
  Real runs require the credentialed labelled provider chat and operator-owned
  Kong executor material.

## Limitations — Hạn chế

- No real exploitation and no data mutation; the executor proposes only catalog
  cases, and every live POST has an expected 4xx.
- The live target response is persisted only as a digest, never raw, and is not
  fed back to the LLM.
- Structured-output quality depends on the provider; aliases that return prose
  instead of the requested JSON schema fail closed with no partial report.
- Raw artifacts are preserved privately on failure; imports never auto-close
  findings. Resume validates immutable input hashes; unknown remote effects
  require reconciliation, never blind retry.
- The threat model excludes same-UID host compromise and tamper-evident/WORM
  evidence guarantees; those are explicitly not claimed.

## Next steps — Hướng phát triển tiếp theo

The charter's optional extensions from the historical twelve-week research
programme include a multi-agent syndicate supervisor, structural
indirect-prompt-injection defense, adaptive evaluation and an LLM-as-judge, a
hybrid/GraphRAG knowledge layer, and FinOps budgeting. All are bonus scope beyond
the six-week minimum, not required for charter completion.
