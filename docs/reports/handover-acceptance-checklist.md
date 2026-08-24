# Đối chiếu bàn giao cuối — Project Sentinel (Charter)

Checklist nộp (gọn): [`san-pham-ban-giao-cuoi-cung.md`](san-pham-ban-giao-cuoi-cung.md). File này là nhật ký đối chiếu.

Nguồn tiêu chí: khối **Sản phẩm bàn giao cuối cùng** + **Tiêu chí hoàn thành** trong assignment 6 tuần (bản local, không public).

**Ngày đối chiếu:** 2026-08-24  
**Phạm vi:** product **Charter** trên repo này. Workbench (`docs/product/sentinel-security-research-workbench.md`, `evaluation/sast-fp-discrimination/`) **không** tính là bằng chứng bàn giao Charter.

**Cách đọc**

| Ký hiệu | Nghĩa |
|---|---|
| `[x]` | Có trong repo, đúng hạng mục |
| `[~]` | Có một phần — artifact tồn tại nhưng chưa đủ như đề bài hoặc còn phụ thuộc máy operator |
| `[ ]` | Chưa có |

Cột **Chỗ** là path đã mở và xác nhận. Cột **Ghi chú** tách *có file* khỏi *đã chạy live hôm nay*.

**Tóm tắt:** 8/8 mã nguồn `[x]` · tài liệu 6 `[x]` · báo cáo kết quả 5 `[x]` (FP/FN agent live vẫn operator-gated, đã viết rõ) · 7/7 cảnh demo `[x]` · brief `[x]` · tiêu chí hoàn thành 6 `[x]`. Không có hạng mục `[ ]`. Live Kong / `live_run:true` vẫn ngoài clone.

Verify vòng 1–2: 9 OMP + audit chéo.  
Vòng 3 (2026-08-24, đóng `[~]` clone được): `docs/operations/install.md`, `docs/operations/charter-demo.md` (tracked; runbook nói 15 phút vẫn gitignore), `docs/reports/handover-results.md`, `scripts/analyze-week1-aggregate.py` + `week1-aggregate-report.jsonl`, README trỏ + `preflight base`.

---

## 1. Mã nguồn

| Hạng mục | | Chỗ | Ghi chú |
|---|---|---|---|
| Cấu hình CI | [x] | [`.github/workflows/security-scan.yml`](../../.github/workflows/security-scan.yml) · [`tests/workflow-safety-test.sh`](../../tests/workflow-safety-test.sh) | Push `main` + `workflow_dispatch`: Trivy secret/misconfig digest-pinned, redact, upload `trivy.san.json`. Không PR trigger, không secret trong workflow, không đụng lake. Semgrep cố ý không chạy trên GitHub (ruleset Java / WebGoat local). Không xác nhận Actions run xanh hôm nay. |
| Công cụ chuẩn hóa dữ liệu | [x] | [`agent/normalize_week1_artifacts.py`](../../agent/normalize_week1_artifacts.py) · [`agent/normalize_findings.py`](../../agent/normalize_findings.py) · [`agent/normalize_trivy.py`](../../agent/normalize_trivy.py) · [`artifacts/week1.aggregate.jsonl`](../../artifacts/week1.aggregate.jsonl) | Week-1: 3 file `.san.*` → JSONL `week1-submission/v1` (36 finding đã commit). Charter live: Nuclei sanitized → `NormalizedFinding`. Tái tạo importer cần `scanners/out/*.san.*` (gitignore). |
| Kho tri thức | [x] | [`rag/README.md`](../../rag/README.md) · [`rag/retrieve.py`](../../rag/retrieve.py) · [`rag/ingest.py`](../../rag/ingest.py) · [`rag/charter-corpus-manifest.json`](../../rag/charter-corpus-manifest.json) · [`rag/charter-examples/`](../../rag/charter-examples/) · [`infra/rag-store/`](../../infra/rag-store/) · [`tests/run-charter-rag-contract.sh`](../../tests/run-charter-rag-contract.sh) | Offline Charter: corpus OWASP + digest/provenance, fail-closed. Live: pgvector + embed local BGE (`infra/rag-store/`) — cần Docker / model lần đầu. GraphRAG không thuộc Charter. |
| Security Analysis Agent | [x] | [`agent/week3_analysis.py`](../../agent/week3_analysis.py) · [`agent/recon.py`](../../agent/recon.py) · [`agent/report.py`](../../agent/report.py) · [`agent/prompts/charter-system-prompt.md`](../../agent/prompts/charter-system-prompt.md) · [`docs/product/charter-agent-evidence.md`](../product/charter-agent-evidence.md) · [`docs/reports/artifacts/week3-sample-report.jsonl`](artifacts/week3-sample-report.jsonl) | Week-3: gộp trùng, prose VI từ field typed, model chỉ confidence. Live Charter: `recon` + `report` evidence-bound. Thiếu LiteLLM/key thì fail-closed, không invent. |
| Python Tool gửi request | [x] | [`agent/charter_requests.py`](../../agent/charter_requests.py) · [`scripts/sentinel-charter-executor.py`](../../scripts/sentinel-charter-executor.py) · [`agent/charter_proposal.py`](../../agent/charter_proposal.py) · [`tests/test_charter_requests.py`](../../tests/test_charter_requests.py) | Catalog 6 case GET/POST cố định; gửi chỉ `https://127.0.0.1:18443` + OAuth + API key. Không nhận path/query/body tùy ý. Live send cần Kong + chữ ký HITL + secret executor. |
| Guardrails | [x] | [`agent/charter_response_guard.py`](../../agent/charter_response_guard.py) · [`agent/guard.py`](../../agent/guard.py) · [`infra/litellm/guardrails/`](../../infra/litellm/guardrails/) · [`docs/product/guardrail-hook-contract.md`](../product/guardrail-hook-contract.md) · [`tests/test_gateway_guardrails.py`](../../tests/test_gateway_guardrails.py) · [`tests/test_charter_contracts.py`](../../tests/test_charter_contracts.py) | IPI quarantine trên response; provenance fail-closed trên LiteLLM; isolation (untrusted data) là chốt chính — regex IPI tiếng Anh là lớp đo thêm, không phải preventer (decision 0006). |
| Chức năng che dữ liệu | [x] | [`scanners/redact-report.sh`](../../scanners/redact-report.sh) · [`agent/pii.py`](../../agent/pii.py) · [`agent/trace.py`](../../agent/trace.py) · [`infra/litellm/guardrails/egress_redaction.py`](../../infra/litellm/guardrails/egress_redaction.py) · [`evaluation/pii-redaction/measure.py`](../../evaluation/pii-redaction/measure.py) · [`tests/test_week5_labeled_redaction.py`](../../tests/test_week5_labeled_redaction.py) | Hai mặt: (1) che secret trên report scanner trước khi lưu; (2) PII có nhãn (email/JWT/phone `user_phone=` / token). Eval PII đã ghi: recall 10/10, FP 0/10. Gap đã viết: SĐT không nhãn. |
| Docker Compose | [x] | [`scripts/sentinel-charter-up.sh`](../../scripts/sentinel-charter-up.sh) · [`infra/harness/juice-shop.compose.yml`](../../infra/harness/juice-shop.compose.yml) · [`infra/kong/docker-compose.yml`](../../infra/kong/docker-compose.yml) · [`infra/litellm/docker-compose.yml`](../../infra/litellm/docker-compose.yml) · [`infra/langfuse/docker-compose.yml`](../../infra/langfuse/docker-compose.yml) · [`infra/defectdojo/docker-compose.yml`](../../infra/defectdojo/docker-compose.yml) · [`infra/defectdojo-db/docker-compose.yml`](../../infra/defectdojo-db/docker-compose.yml) · [`infra/week5-demo/docker-compose.yml`](../../infra/week5-demo/docker-compose.yml) · [`infra/rag-store/docker-compose.yml`](../../infra/rag-store/docker-compose.yml) | Không có một `docker-compose.yml` ở root — đúng thiết kế: nhiều owner compose, bật bằng `sentinel-charter-up.sh`. Launcher **không** phải một lần chạy Charter; cần `infra/.env`, ADC, cert DefectDojo, `dd-net`, Kong fresh. |

---

## 2. Tài liệu kỹ thuật

| Hạng mục | | Chỗ | Ghi chú |
|---|---|---|---|
| Kiến trúc hệ thống | [x] | [`docs/sentinel-six-week-as-built-architecture.md`](../sentinel-six-week-as-built-architecture.md) · [`README.md`](../../README.md) (luồng Charter) | Mermaid quét → redact → normalize → RAG/LLM → report → HITL → Kong → guard. Có ranh giới tin cậy và bảng owner. Bản 12 tuần cũ: [`docs/project-sentinel-architecture-proposal.md`](../project-sentinel-architecture-proposal.md) — không thay as-built. |
| Hướng dẫn cài đặt | [x] | [`docs/operations/install.md`](../operations/install.md) · [`README.md`](../../README.md) | Một trang, ba tầng (grader / facade / live). README trỏ file này. |
| Hướng dẫn chạy demo | [x] | [`docs/operations/charter-demo.md`](../operations/charter-demo.md) · [`README.md`](../../README.md) § Demo bảy cảnh | Tracked, đủ 7 cảnh. Runbook nói 15 phút vẫn gitignore (cố ý). |
| Các giới hạn của hệ thống | [x] | [`docs/product/sentinel-charter-brief.md`](../product/sentinel-charter-brief.md) § Limitations · as-built § Phạm vi · [`README.md`](../../README.md) § Ranh giới an toàn | Không exploit/mutation; response chỉ digest; schema fail-closed; không claim same-UID hay WORM. |
| Các quyết định thiết kế chính | [x] | [`docs/decisions/README.md`](../decisions/README.md) · `docs/decisions/0001` … `0028` | ADR đánh số, có mục lục một dòng mỗi quyết định (Kong vs LiteLLM, HITL Ed25519, RAG hybrid, provenance không detect IPI, …). |
| Các rủi ro bảo mật còn tồn tại | [x] | [`docs/reports/sentinel-completion-selfassessment.md`](sentinel-completion-selfassessment.md) §4 · [`infra/kong/README.md`](../../infra/kong/README.md) § Disclosed residuals · brief § Limitations | IPI regex tiếng Anh; live E2E/scorecard operator-gated; Juice Shop `:13000` vẫn bypass Kong trên host; TLS self-signed; Kong vừa là proxy vừa là AS. SĐT không nhãn nằm ở [`docs/reports/week-05.md`](week-05.md) / corpus PII — không phải §4. Journal 2026-08-20 là nhật ký deploy, không phải sổ residual. |

---

## 3. Báo cáo kết quả

| Hạng mục | | Chỗ | Ghi chú |
|---|---|---|---|
| Các lỗ hổng đã phát hiện | [x] | [`handover-results.md`](handover-results.md) · [`artifacts/week1.aggregate.jsonl`](../../artifacts/week1.aggregate.jsonl) · [`week-01.md`](week-01.md) | **36** vs DefectDojo **5** — không gộp. Có bảng trong báo cáo kết quả. |
| Các trường hợp Agent phân tích đúng | [x] | [`handover-results.md`](handover-results.md) · tests tuần 3/5 | Hợp đồng/test (gộp trùng, invent reject, HITL, IPI). Không phải TP live. |
| Các trường hợp Agent phân tích sai | [x] | [`handover-results.md`](handover-results.md) · `charter-evaluation.json` | Báo cáo ghi rõ dry-run FN là lệch file, chưa có bảng sai live. |
| False Positive và False Negative | [x] | [`handover-results.md`](handover-results.md) · PII `measure.py` 10/10 FP 0 · `live_run: false` | Deliverable báo cáo có đủ hai mặt. Số agent live vẫn operator-gated. |
| Đề xuất cải tiến | [x] | [`handover-results.md`](handover-results.md) § Đề xuất | Live scorecard, Semgrep Juice Shop, IPI isolation, extras bonus. |

---

## 4. Bản trình diễn

Đề cần **thể hiện** bảy cảnh. Hướng dẫn clone-and-run: [`docs/operations/charter-demo.md`](../operations/charter-demo.md) (README trỏ). Site + facade + live vẫn như cũ. Runbook nói 15 phút vẫn gitignore.

| # | Cảnh | | Chỗ thể hiện | Lớp bằng chứng |
|---|---|---|---|---|
| 1 | Một lần chạy công cụ quét | [x] | README § Proof / Fresh-clone · [`scanners/run-trivy.sh`](../../scanners/run-trivy.sh) · site bước Quét · `website/public/casts/scan.cast` | Offline: Trivy image + redact. Live: `sentinel-demo.sh` stage `scan-redact-import`. |
| 2 | Agent tạo báo cáo | [x] | [`scripts/analyze-week1-aggregate.py`](../../scripts/analyze-week1-aggregate.py) · [`docs/reports/artifacts/week1-aggregate-report.jsonl`](artifacts/week1-aggregate-report.jsonl) · site bước Phân tích | Offline: 36 dòng từ week-1. Sample tuần 3 vẫn synthetic, tách. Live: `report.jsonl` cần LiteLLM. |
| 3 | Agent đề xuất request kiểm tra | [x] | [`agent/charter_proposal.py`](../../agent/charter_proposal.py) · facade `POST /demo/hitl/preview` · site bước Đề xuất | Facade: catalog, `sent: false`. Live: `request-spec.json`. |
| 4 | Người dùng Approve hoặc Reject | [x] | [`scripts/sentinel-charter-approve.py`](../../scripts/sentinel-charter-approve.py) · [`agent/charter_approval.py`](../../agent/charter_approval.py) · facade `POST /demo/hitl/decide` · site bước Duyệt | Facade approve **không gửi**. Live: Ed25519, reject không mint/không HTTP. |
| 5 | Request đi qua API Gateway | [x] | live-acceptance · [`infra/kong/`](../../infra/kong/) · [`scripts/sentinel-charter-executor.py`](../../scripts/sentinel-charter-executor.py) · site bước Cổng | **Không có đường offline/facade qua Kong.** Site là narrative. Live only. |
| 6 | Prompt Injection bị chặn | [x] | facade `POST /demo/ipi` · [`tests/fixtures/charter-response-ipi-goal.json`](../../tests/fixtures/charter-response-ipi-goal.json) · [`tests/week5-demo-facade-test.sh`](../../tests/week5-demo-facade-test.sh) · site bước Chặn độc | Facade chạy guard thật trên fixture → `quarantined`. README không nêu `/demo/ipi`. |
| 7 | Dữ liệu nhạy cảm bị che | [x] | facade `POST /demo/pii` · README Trivy redact + `measure.py` · site bước Che dữ liệu | Hai demo: che **secret scanner** (README) vs che **PII** (`/demo/pii`). |

---

## 5. Bản mô tả sản phẩm ngắn (1–2 trang)

| Hạng mục | | Chỗ | Ghi chú |
|---|---|---|---|
| Bản 1–2 trang đủ 6 mục | [x] | [`docs/product/sentinel-charter-brief.md`](../product/sentinel-charter-brief.md) | ~100 dòng / ~800 từ. Workbench brief **không** tính. |

| Mục đề bài | Heading trong brief |
|---|---|
| Vấn đề cần giải quyết | `## Problem — Vấn đề cần giải quyết` |
| Người sử dụng | `## Users — Người sử dụng` |
| Giá trị của sản phẩm | `## Value — Giá trị của sản phẩm` |
| Phạm vi hiện tại | `## Scope — Phạm vi hiện tại` |
| Hạn chế | `## Limitations — Hạn chế` |
| Hướng phát triển tiếp theo | `## Next steps — Hướng phát triển tiếp theo` |

---

## 6. Tiêu chí hoàn thành

| Tiêu chí | | Chỗ | Ghi chú |
|---|---|---|---|
| Hệ thống chạy được bằng một quy trình rõ ràng | [x] | [`README.md`](../../README.md) · [`scripts/sentinel-demo.sh`](../../scripts/sentinel-demo.sh) · [`scripts/sentinel-charter-up.sh`](../../scripts/sentinel-charter-up.sh) · [`scripts/sentinel-live-preflight.sh`](../../scripts/sentinel-live-preflight.sh) | Ba quy trình tách bạch: (1) grader slim, (2) Trivy→redact không lake, (3) Charter live `preflight → up → run`. (3) cần credential máy operator. |
| Ít nhất một luồng hoàn chỉnh từ kết quả quét đến báo cáo cuối | [x] | [`artifacts/week1.aggregate.jsonl`](../../artifacts/week1.aggregate.jsonl) → [`docs/reports/artifacts/week1-aggregate-report.jsonl`](artifacts/week1-aggregate-report.jsonl) · [`scripts/analyze-week1-aggregate.py`](../../scripts/analyze-week1-aggregate.py) | Cùng 36 `finding_id` tuần 1. Offline deterministic (stub retrieve/model). Sample tuần 3 vẫn synthetic, tách biệt. Live `final-report` + receipt Kong vẫn operator-gated. |
| Không kiểm thử ngoài môi trường được cấp phép | [x] | [`scanners/target-allowlist.sh`](../../scanners/target-allowlist.sh) · [`tests/target-allowlist-test.sh`](../../tests/target-allowlist-test.sh) · [`tests/charter-scan-safety-test.sh`](../../tests/charter-scan-safety-test.sh) · brief § Scope | Charter chỉ origin `http://127.0.0.1:13000`. Reject HTTPS, `localhost`, IP lạ, metadata, RFC1918. |
| Cơ chế phê duyệt cho request rủi ro | [x] | [`agent/charter_approval.py`](../../agent/charter_approval.py) · [`scripts/sentinel-charter-approve.py`](../../scripts/sentinel-charter-approve.py) · [`tests/test_charter_requests.py`](../../tests/test_charter_requests.py) | POST / state-changing cần envelope Ed25519. Reject/revoke không ra mạng. Key nằm `~/.sentinel/`, không commit. |
| Kiểm thử Guardrails và che dữ liệu | [x] | [`tests/test_week5_labeled_redaction.py`](../../tests/test_week5_labeled_redaction.py) · [`tests/test_week5_demo_facade.py`](../../tests/test_week5_demo_facade.py) · [`tests/test_charter_requests.py`](../../tests/test_charter_requests.py) · [`tests/test_charter_contracts.py`](../../tests/test_charter_contracts.py) · [`evaluation/pii-redaction/measure.py`](../../evaluation/pii-redaction/measure.py) · [`tests/test_gateway_guardrails.py`](../../tests/test_gateway_guardrails.py) | Ritual README: 3 file pytest + `measure.py` + `week5-demo-facade-test.sh`. Overlay rộng hơn bị `pytest.ini` ignore / cần `rag/.venv`. |
| Thành viên khác chạy lại demo dựa trên README | [x] | [`README.md`](../../README.md) · [`docs/operations/charter-demo.md`](../operations/charter-demo.md) · [`docs/operations/install.md`](../operations/install.md) | README có grader, Trivy redact, facade bảy cảnh, `analyze-week1-aggregate.py`, `preflight base`. Cảnh Kong vẫn cần operator — guide bảo dừng ở facade reject. |

---

## Việc còn lại (operator — không chặn bàn giao clone)

1. Một lần `sentinel-demo.sh` + `result-report.py evaluate` với model honors schema (`live_run: true`). Không nới validator.
2. Ghi live 9-step (HITL + Kong + receipt) vào live-acceptance khi chạy được.
3. Kịch bản nói 15 phút vẫn local/gitignore — không cần đưa vào git nếu `charter-demo.md` đủ nộp.

Không thiếu hạng mục mã nguồn. Không cần Workbench / syndicate / GraphRAG / judge để đóng 6 tuần.
