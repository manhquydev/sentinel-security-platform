# Báo cáo kết quả Charter

Bàn giao: lỗ hổng đã thấy, agent đúng/sai, FP/FN, đề xuất. **Không** dùng Workbench / `evaluation/sast-fp-discrimination/`. Scorecard `evaluation/charter-eval/charter-evaluation.json` có `live_run: false` — không nộp như điểm AI.

## Các lỗ hổng đã phát hiện

Hai inventory **không gộp**:

| Nguồn | Số | Chỗ |
|---|---|---|
| Aggregate tuần 1 (đã commit) | **36** (Nuclei 21 + Trivy 4 + Semgrep 11) | [`artifacts/week1.aggregate.jsonl`](../../artifacts/week1.aggregate.jsonl) · [`week-01.md`](week-01.md) |
| DefectDojo lab (Juice Shop) | **5** (4 Trivy + 1 Nuclei), product `juice-shop-harness` | [`week-06.md`](week-06.md) · `app.vinsoc` |
| Sample tuần 3 (synthetic) | 3 dòng sau gộp | [`artifacts/week3-sample-report.jsonl`](artifacts/week3-sample-report.jsonl) |

Semgrep 11 là ruleset Java / WebGoat, không phải cây Juice Shop. Raw `.san.*` không lên git.

Báo cáo agent từ đúng file 36 dòng: [`artifacts/week1-aggregate-report.jsonl`](artifacts/week1-aggregate-report.jsonl) (`live_run: false`, prose do code, stub confidence).

## Các trường hợp Agent phân tích đúng

Đây là **hợp đồng / test**, không phải bảng chấm live:

| Case | Ý | Chỗ |
|---|---|---|
| Gộp trùng | 4 dòng sample → 3 finding, prose VI từ field typed | `tests/test_week3_aggregate_analysis.py` · [`week-03.md`](week-03.md) |
| Input trống / hỏng | Không gọi model, không invent report | `tests/test_charter_contracts.py` |
| Model invent field / endpoint | Reject, không publish | cùng file (`test_model_invention_rejects_all_publication`) |
| Proposal chỉ catalog | Location finding không thành path/query/body | `tests/test_charter_proposal.py` |
| HITL reject | Không mint, không HTTP | `tests/test_charter_requests.py` |
| IPI fixture | Response “đổi mục tiêu” / “lộ secret” → quarantine | `tests/test_week5_demo_facade.py` |
| Week-1 → report | 36 finding typed → 36 dòng `week3-analysis/v1` | `scripts/analyze-week1-aggregate.py` |

Dry-run `CE-04` `correct: true` là TN (ID cấm không có trong sample) — **không** phải TP live.

## Các trường hợp Agent phân tích sai

Chưa có bảng “agent sai” từ `result-report.py` lần chạy live.

File `charter-evaluation.json` đánh `CE-01/03` FN vì lệch **ID** gold ↔ sample tuần 3; `CE-02` lệch title/location/severity; `CE-05` thiếu artifact request. Tuần 6 đã nói: đó là lệch file, không phải “AI kém”.

## False Positive và False Negative

| Mặt | Kết quả | Live? |
|---|---|---|
| Che PII (`evaluation/pii-redaction/measure.py`) | recall **10/10**, FP **0/10** | Đo trên corpus commit — redactor, không phải finding agent |
| Agent finding (`charter-evaluation.json`) | `tp=0 fp=0 fn=4 tn=1` | **Không.** `live_run: false`, `mode: sample-dry-run` |

Live FP/FN: `scripts/sentinel-demo.sh` rồi `evaluation/charter-eval/result-report.py evaluate --run-dir RUN` với model honors schema. Không nới validator.

## Đề xuất cải tiến

1. Một lần `result-report.py` live sau khi model trả đúng schema — rồi mới mở rộng bộ CE.
2. Kịch bản nói 15 phút vẫn local; nộp dùng [`charter-demo.md`](../operations/charter-demo.md) (README đã trỏ).
3. Semgrep ruleset Juice Shop (JS/TS) nếu muốn SAST cùng target DAST — hiện baseline Semgrep là Java.
4. IPI regex tiếng Anh chỉ là lớp đo; chốt chính vẫn isolation + catalog + HITL.
5. Extras 12 tuần (syndicate, GraphRAG, judge) là bonus, không chặn bàn giao 6 tuần.
