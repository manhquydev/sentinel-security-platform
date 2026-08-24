# Sản phẩm bàn giao cuối cùng

Project Sentinel — product **Charter**. Workbench không tính.

Bấm **tên file** ở cột Chỗ để mở đúng chỗ (Preview / IDE).

| | Nghĩa |
|---|---|
| `[x]` | Có trong repo, đúng hạng mục |
| `[~]` | Có một phần, hoặc còn phụ thuộc máy operator |
| `[ ]` | Thiếu |

**Tóm tắt:** đủ hạng mục đề bài trên worktree. Không có `[ ]`. Live Kong và điểm AI `live_run: true` vẫn cần máy operator — không giả.

Cửa nộp: [`README.md`](../../README.md) · [`docs/operations/install.md`](../operations/install.md) · [`docs/operations/charter-demo.md`](../operations/charter-demo.md).  
Một số cửa còn chưa commit ([`install.md`](../operations/install.md), [`charter-demo.md`](../operations/charter-demo.md), [`handover-results.md`](handover-results.md), [`analyze-week1-aggregate.py`](../../scripts/analyze-week1-aggregate.py), [`week1-aggregate-report.jsonl`](artifacts/week1-aggregate-report.jsonl)) — clone `origin/main` chưa nhận chúng.

---

## 1. Mã nguồn

| | Hạng mục | Chỗ |
|---|---|---|
| [x] | Cấu hình CI | [`.github/workflows/security-scan.yml`](../../.github/workflows/security-scan.yml) |
| [x] | Công cụ chuẩn hóa dữ liệu | [`agent/normalize_week1_artifacts.py`](../../agent/normalize_week1_artifacts.py) · [`agent/normalize_findings.py`](../../agent/normalize_findings.py) · [`artifacts/week1.aggregate.jsonl`](../../artifacts/week1.aggregate.jsonl) (36 dòng) |
| [x] | Kho tri thức | [`rag/retrieve.py`](../../rag/retrieve.py) · [`rag/charter-corpus-manifest.json`](../../rag/charter-corpus-manifest.json) · [`rag/charter-examples/`](../../rag/charter-examples/) |
| [x] | Security Analysis Agent | [`agent/week3_analysis.py`](../../agent/week3_analysis.py) · [`agent/recon.py`](../../agent/recon.py) · [`agent/report.py`](../../agent/report.py) |
| [x] | Python Tool gửi request | [`agent/charter_requests.py`](../../agent/charter_requests.py) · [`scripts/sentinel-charter-executor.py`](../../scripts/sentinel-charter-executor.py) |
| [x] | Guardrails | [`agent/charter_response_guard.py`](../../agent/charter_response_guard.py) · [`infra/litellm/guardrails/`](../../infra/litellm/guardrails/) |
| [x] | Chức năng che dữ liệu | [`scanners/redact-report.sh`](../../scanners/redact-report.sh) · [`agent/pii.py`](../../agent/pii.py) · [`evaluation/pii-redaction/measure.py`](../../evaluation/pii-redaction/measure.py) |
| [x] | Docker Compose | [`scripts/sentinel-charter-up.sh`](../../scripts/sentinel-charter-up.sh) · [`infra/harness/juice-shop.compose.yml`](../../infra/harness/juice-shop.compose.yml) · [`infra/kong/docker-compose.yml`](../../infra/kong/docker-compose.yml). Không có `docker-compose.yml` ở root. |

---

## 2. Tài liệu kỹ thuật

| | Hạng mục | Chỗ |
|---|---|---|
| [x] | Kiến trúc hệ thống | [`docs/sentinel-six-week-as-built-architecture.md`](../sentinel-six-week-as-built-architecture.md) |
| [x] | Hướng dẫn cài đặt | [`docs/operations/install.md`](../operations/install.md) (grader / facade / live) |
| [x] | Hướng dẫn chạy demo | [`docs/operations/charter-demo.md`](../operations/charter-demo.md) (7 cảnh). Kịch bản nói 15 phút vẫn local. |
| [x] | Các giới hạn của hệ thống | [`docs/product/sentinel-charter-brief.md`](../product/sentinel-charter-brief.md#limitations--hạn-chế) § Limitations |
| [x] | Các quyết định thiết kế chính | [`docs/decisions/`](../decisions/README.md) (0001–0028) |
| [x] | Các rủi ro bảo mật còn tồn tại | [`docs/reports/sentinel-completion-selfassessment.md`](sentinel-completion-selfassessment.md#4-residual-risks--honest-limits) §4 · [`infra/kong/README.md`](../../infra/kong/README.md) |

---

## 3. Báo cáo kết quả

Chủ: [`docs/reports/handover-results.md`](handover-results.md).

| | Hạng mục | Chỗ / số |
|---|---|---|
| [x] | Các lỗ hổng đã phát hiện | [§ Lỗ hổng](handover-results.md#các-lỗ-hổng-đã-phát-hiện) · Tuần 1: **36** ([`artifacts/week1.aggregate.jsonl`](../../artifacts/week1.aggregate.jsonl)). DefectDojo lab: **5** ([`week-06.md`](week-06.md)). Không gộp. |
| [x] | Agent phân tích đúng | [§ Agent đúng](handover-results.md#các-trường-hợp-agent-phân-tích-đúng) |
| [x] | Agent phân tích sai | [§ Agent sai](handover-results.md#các-trường-hợp-agent-phân-tích-sai) · dry-run [`charter-evaluation.json`](../../evaluation/charter-eval/charter-evaluation.json) (`CE-01/02/03/05` lệch file, không phải bảng sai live) |
| [x] | False Positive / False Negative | [§ FP/FN](handover-results.md#false-positive-và-false-negative) · PII [`measure.py`](../../evaluation/pii-redaction/measure.py) 10/10 FP 0/10. Agent: `live_run: false`, `tp=0 fp=0 fn=4 tn=1` |
| [x] | Đề xuất cải tiến | [§ Đề xuất](handover-results.md#đề-xuất-cải-tiến) |

---

## 4. Bản trình diễn

Hướng dẫn: [`docs/operations/charter-demo.md`](../operations/charter-demo.md) ([README](../../README.md#chạy-nhanh) trỏ).

| | Cảnh | Chỗ thể hiện |
|---|---|---|
| [x] | Một lần chạy công cụ quét | [README § Proof](../../README.md#proof-quét--che-secret-không-cần-lake--llm) · [`scanners/run-trivy.sh`](../../scanners/run-trivy.sh) · [demo §1](../operations/charter-demo.md#1-một-lần-chạy-công-cụ-quét) |
| [x] | Agent tạo báo cáo | [demo §2](../operations/charter-demo.md#2-agent-tạo-báo-cáo) · [`scripts/analyze-week1-aggregate.py`](../../scripts/analyze-week1-aggregate.py) → [`week1-aggregate-report.jsonl`](artifacts/week1-aggregate-report.jsonl) (36 dòng) |
| [x] | Agent đề xuất request kiểm tra | [demo §3](../operations/charter-demo.md#3-agent-đề-xuất-request-kiểm-tra) · [`agent/charter_proposal.py`](../../agent/charter_proposal.py) |
| [x] | Người dùng Approve hoặc Reject | [demo §4](../operations/charter-demo.md#4-approve-hoặc-reject) · [`scripts/sentinel-charter-approve.py`](../../scripts/sentinel-charter-approve.py) (`sent: false` trên facade) |
| [x] | Request đi qua API Gateway | [demo §5](../operations/charter-demo.md#5-request-đi-qua-api-gateway) · [`infra/kong/`](../../infra/kong/README.md). Live only — thiếu Kong thì **dừng**, không giả gửi. |
| [x] | Prompt Injection bị chặn | [demo §6](../operations/charter-demo.md#6-prompt-injection-bị-chặn) · fixture [`charter-response-ipi-goal.json`](../../tests/fixtures/charter-response-ipi-goal.json) |
| [x] | Dữ liệu nhạy cảm bị che | [demo §7](../operations/charter-demo.md#7-dữ-liệu-nhạy-cảm-bị-che) · [`scanners/redact-report.sh`](../../scanners/redact-report.sh) · [`measure.py`](../../evaluation/pii-redaction/measure.py) |

---

## 5. Bản mô tả sản phẩm ngắn

[`docs/product/sentinel-charter-brief.md`](../product/sentinel-charter-brief.md) — khoảng 100 dòng / 800 từ.

| | Mục đề bài | Heading (bấm để nhảy mục) |
|---|---|---|
| [x] | Vấn đề cần giải quyết | [Problem — Vấn đề cần giải quyết](../product/sentinel-charter-brief.md#problem--vấn-đề-cần-giải-quyết) |
| [x] | Người sử dụng | [Users — Người sử dụng](../product/sentinel-charter-brief.md#users--người-sử-dụng) |
| [x] | Giá trị của sản phẩm | [Value — Giá trị của sản phẩm](../product/sentinel-charter-brief.md#value--giá-trị-của-sản-phẩm) |
| [x] | Phạm vi hiện tại | [Scope — Phạm vi hiện tại](../product/sentinel-charter-brief.md#scope--phạm-vi-hiện-tại) |
| [x] | Hạn chế | [Limitations — Hạn chế](../product/sentinel-charter-brief.md#limitations--hạn-chế) |
| [x] | Hướng phát triển tiếp theo | [Next steps — Hướng phát triển tiếp theo](../product/sentinel-charter-brief.md#next-steps--hướng-phát-triển-tiếp-theo) |

---

## Tiêu chí hoàn thành

| | Tiêu chí | Chỗ |
|---|---|---|
| [x] | Hệ thống chạy được bằng một quy trình rõ ràng | [`README.md`](../../README.md#chạy-nhanh) · [`scripts/sentinel-live-preflight.sh`](../../scripts/sentinel-live-preflight.sh) (`base`) · [`scripts/sentinel-charter-up.sh`](../../scripts/sentinel-charter-up.sh) · [`scripts/sentinel-demo.sh`](../../scripts/sentinel-demo.sh) |
| [x] | Ít nhất một luồng quét → báo cáo cuối | [`artifacts/week1.aggregate.jsonl`](../../artifacts/week1.aggregate.jsonl) → [`scripts/analyze-week1-aggregate.py`](../../scripts/analyze-week1-aggregate.py) → [`week1-aggregate-report.jsonl`](artifacts/week1-aggregate-report.jsonl) |
| [x] | Không kiểm thử ngoài môi trường được cấp phép | [`scanners/target-allowlist.sh`](../../scanners/target-allowlist.sh) — chỉ `http://127.0.0.1:13000` |
| [x] | Cơ chế phê duyệt cho request rủi ro | [`agent/charter_approval.py`](../../agent/charter_approval.py) — reject không gửi |
| [x] | Kiểm thử Guardrails và che dữ liệu | [`tests/test_week5_labeled_redaction.py`](../../tests/test_week5_labeled_redaction.py) · [`tests/test_charter_requests.py`](../../tests/test_charter_requests.py) · [`tests/test_week5_demo_facade.py`](../../tests/test_week5_demo_facade.py) · [`evaluation/pii-redaction/measure.py`](../../evaluation/pii-redaction/measure.py) |
| [~] | Thành viên khác chạy lại demo từ README | [`README.md`](../../README.md) · [`docs/operations/install.md`](../operations/install.md) · [`docs/operations/charter-demo.md`](../operations/charter-demo.md) — đủ trên worktree; `[x]` sau khi commit các cửa trên |

---

## Ngoài clone (không chặn bàn giao)

- Một lần live [`scripts/sentinel-demo.sh`](../../scripts/sentinel-demo.sh) + [`evaluation/charter-eval/result-report.py`](../../evaluation/charter-eval/result-report.py) với model honors schema. Không nới validator.
- Cảnh Kong cần key trên máy operator — [demo §5](../operations/charter-demo.md#5-request-đi-qua-api-gateway).
- Kịch bản nói 15 phút giữ local.
