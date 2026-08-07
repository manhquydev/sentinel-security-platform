---
title: "Tuần 3 — Agent phân tích bảo mật"
description: "Báo cáo Tuần 3: agent phân tích bám bằng chứng (JSONL)"
---

> **Xem nguồn:** [Markdown](/reports/week-03/markdown/) · [Raw `.md`](/raw/reports/week-03.md) · [llms.txt](https://vinsoc.manhquy.id.vn/llms.txt)

Monorepo Sentinel. Tuần 3 xây **Agent phân tích bảo mật** (Security Analysis Agent):
đọc gói kết quả đã chuẩn hóa từ Tuần 1–2, rồi xuất **báo cáo JSONL bám bằng chứng**
— không bịa endpoint hay lỗ hổng ngoài dữ liệu đầu vào.

## 1. Mục tiêu Tuần 3 em đã làm

Đối chiếu 1:1 với charter 6 tuần (mục Tuần 3):

| Yêu cầu charter | Trong monorepo |
|---|---|
| Thiết kế System Prompt cho Agent | `agent/prompts/charter-system-prompt.md` |
| Nối Agent với kết quả quét + kho tri thức Tuần 2 | `agent/week3_analysis.py` (nạp aggregate + tra cứu) |
| Nhóm cảnh báo trùng, phân mức nghiêm trọng, giải thích, đề xuất | Nhóm theo khóa máy quét; **giải thích/khắc phục tiếng Việt** do renderer viết từ field typed + đoạn tri thức đã truy xuất |
| Kết quả theo JSONL | Schema `week3-analysis/v1` |
| Ít nhất ba tình huống kiểm thử | `tests/test_week3_aggregate_analysis.py` |
| Xử lý input trống / không hợp lệ | Fail-closed: `malformed-input`, `empty-input`, `metadata-mismatch`, … |
| Không bịa endpoint / lỗ hổng | Model chỉ trả `enrichments` (chế độ + độ tin cậy); **sự kiện thật** do code ghi |

## 2. Kiến trúc

```
week1.aggregate.jsonl + manifest
        │
        ▼
 nạp & kiểm aggregate (schema + digest + thứ tự source_id)
        │
        ▼
 nhóm cảnh báo  ──► tra cứu tri thức (digest + provenance HTTPS)
        │
        ▼
 model chỉ bổ sung confidence  ── system prompt cấm bịa sự kiện
        │
        ▼
 renderer VI: explanation + remediation (typed + knowledge snippet)
        │
        ▼
 week3-report.jsonl  (week3-analysis/v1)
```

**Nguyên tắc:** *LLM chỉ gán độ tin cậy; code quyết định sự kiện và viết câu cho mentor.*

## 3. Định dạng báo cáo (JSONL)

Mỗi dòng `week3-analysis/v1` gồm: `finding_id`, `tool`, `scanner`, `name`,
`severity`, `location`, `scanner_evidence`, `explanation`, `remediation`,
`confidence`, `source_ids`, `knowledge_provenance`, `corpus_digest`,
`retrieval_digest`.

Ví dụ rút gọn từ sample committed (`docs/reports/artifacts/week3-sample-report.jsonl`):

```json
{
  "schema_version": "week3-analysis/v1",
  "name": "Missing Security Header",
  "severity": "Medium",
  "location": "path:/rest/products",
  "explanation": "Công cụ nuclei (quét ứng dụng đang chạy (DAST)) ghi nhận cảnh báo «Missing Security Header» tại path:/rest/products. …",
  "remediation": "Đối chiếu lại bằng chứng máy quét … Tham khảo đoạn tri thức đã truy xuất …",
  "confidence": "medium"
}
```

## 4. Bằng chứng chạy

| Bước | Kết quả |
|---|---|
| Sample aggregate 4 bản ghi → gộp còn **3** finding | **PASS** (`docs/reports/artifacts/`) |
| Prose VI có title + evidence + tri thức | **PASS** (không còn template EN tautology) |
| Model không viết explanation | **PASS** (chỉ confidence / modes) |
| Unit tests `test_week3_aggregate_analysis.py` | **PASS** (trừ test corpus live khi thiếu deps RAG — skip) |

Tái tạo sample:

```bash
PYTHONPATH=. python3 scripts/generate-week3-sample-artifacts.py
```

## 5. Cách chạy lại

```bash
python3 -m agent.week3_analysis \
  --week3-aggregate path/to/week1.aggregate.jsonl \
  --week3-manifest path/to/week1.aggregate.manifest.json \
  --week3-report-out /tmp/week3-report.jsonl
```

Manifest phải có `aggregate_sha256` khớp file aggregate. Thiếu key/tri thức → fail-closed.

## 6. Kiểm thử (≥3 tình huống)

1. Aggregate 3 công cụ hợp lệ → publish report, group duplicates, prose VI.
2. Schema enrichment chặt + message có nhãn nguồn.
3. Input sai/trống → dừng trước retrieve/model.
4. Model invent field → reject.

## 7. Phạm vi và lựa chọn có chủ đích

- Evidence-bound > “AI tìm bug”.
- Tri thức Tuần 2 vào **remediation** qua snippet đã guard; không tin như lệnh.
- Gateway / HITL = Tuần 4–5, không gộp vào Tuần 3.

Đây là bằng chứng phạm vi **Tuần 3**, không phải hoàn tất cả sáu tuần.
