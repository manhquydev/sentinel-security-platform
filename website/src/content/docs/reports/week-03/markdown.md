---
title: "Tuần 3: Agent phân tích bảo mật, nguồn Markdown"
description: "Nguồn Markdown đầy đủ, đọc / sao chép"
---

Trang HTML: [Tuần 3: Agent phân tích bảo mật](/reports/week-03/) · [Tải raw](/raw/reports/week-03.md) · [llms.txt](https://vinsoc.manhquy.id.vn/llms.txt)

Nội dung dưới đây là **toàn bộ file Markdown** trong monorepo (`docs/reports/week-03.md`), không qua bước render HTML.

````markdown
# Project Sentinel: Báo cáo Tuần 3

> [Demo tuần 3](/demo/week-03/) (chạy trên sample tĩnh trong site).

Tuần này em làm agent đọc aggregate tuần 1–2, gộp cảnh báo trùng, rồi in JSONL.
Giải thích và hướng xử lý bằng tiếng Việt.

Luồng evidence-bound đầy đủ (live + tuần 3, cách “chứng minh” finding):
[charter-agent-evidence.md](../product/charter-agent-evidence.md).

## 1. Việc em đã làm

| Việc | Chỗ trong repo |
|---|---|
| System prompt cho agent | `agent/prompts/charter-system-prompt.md` |
| Code chạy phân tích | `agent/week3_analysis.py` |
| Gộp trùng, severity, giải thích + remediation VI | cùng module; prose do code ghép từ field typed + đoạn tri thức đã lấy |
| Schema report | `week3-analysis/v1` (JSONL) |
| Test | `tests/test_week3_aggregate_analysis.py` (nhiều case hơn 3) |
| Input hỏng / trống | dừng sớm: `malformed-input`, `empty-input`, `metadata-mismatch`, … |

## 2. Luồng xử lý

```
week1.aggregate.jsonl + manifest
 │
 ▼
 nạp & kiểm (schema, digest, thứ tự source_id)
 │
 ▼
 gộp cảnh báo ──► tra tri thức (digest + provenance)
 │
 ▼
 model: confidence (+ mode)
 │
 ▼
 code viết explanation / remediation (VI)
 │
 ▼
 week3-report.jsonl
```

## 3. Một dòng report trông thế nào

Các field chính: `finding_id`, `tool`, `scanner`, `name`, `severity`, `location`,
`scanner_evidence`, `explanation`, `remediation`, `confidence`, `source_ids`,
`knowledge_provenance`, `corpus_digest`, `retrieval_digest`.

Ví dụ (rút từ `docs/reports/artifacts/week3-sample-report.jsonl`):

```json
{
 "schema_version": "week3-analysis/v1",
 "name": "Missing Security Header",
 "severity": "Medium",
 "location": "path:/rest/products",
 "explanation": "Công cụ nuclei … ghi nhận cảnh báo «Missing Security Header» tại path:/rest/products. …",
 "remediation": "Đối chiếu lại bằng chứng máy quét …",
 "confidence": "medium"
}
```

## 4. Em đã kiểm gì

| Bước | Kết quả |
|---|---|
| 4 dòng aggregate sample → còn **3** finding sau gộp | PASS, `docs/reports/artifacts/` |
| Prose VI có title + evidence + tri thức | PASS |
| Model không ghi explanation | PASS (chỉ confidence / modes) |
| `tests/test_week3_aggregate_analysis.py` | PASS (test corpus live skip nếu thiếu RAG) |

Làm lại sample:

```bash
PYTHONPATH=. python3 scripts/generate-week3-sample-artifacts.py
```

## 5. Chạy agent

```bash
python3 -m agent.week3_analysis \
  --week3-aggregate path/to/week1.aggregate.jsonl \
  --week3-manifest path/to/week1.aggregate.manifest.json \
  --week3-report-out /tmp/week3-report.jsonl
```

Manifest phải khớp `aggregate_sha256` với file aggregate. Thiếu key hoặc tri thức thì dừng, không invent report.

## 6. Case test (rút gọn)

1. Aggregate 3 tool ổn → có report, có gộp trùng, prose VI.
2. Enrichment schema chặt; message có nhãn nguồn.
3. Input sai/trống → dừng trước retrieve/model.
4. Model invent field → reject.
````
