---
title: "Tuần 6: Tích hợp, đánh giá và demo"
description: "Báo cáo Tuần 6: luồng Charter, CE-01..05 và đóng gói Compose"
---

> **Xem nguồn:** [Markdown](/reports/week-06/markdown/) · [Raw `.md`](/raw/reports/week-06.md) · [llms.txt](https://vinsoc.manhquy.id.vn/llms.txt)

Tuần 6 em ghép các phần đã làm thành một luồng Charter chạy được từ quét đến
duyệt request, gửi qua gateway, lọc IPI và che PII. Số liệu lấy từ test và
eval đã commit, không phải lần nghiệm thu live mới trong tháng 08/2026.

## 1. Việc em đã làm

Tuần cuối nối các chốt thành một luồng có thể giải thích: scanner tạo tín hiệu,
agent chỉ dùng tri thức có nguồn, proposal nằm trong catalog, executor cần
approval, rồi guardrail giữ dữ liệu an toàn hơn khi đi qua ranh giới.

| Việc | Chỗ trong repo |
|---|---|
| Luồng kiến trúc 9 bước | `docs/sentinel-six-week-as-built-architecture.md` |
| Lệnh demo Charter | `scripts/sentinel-demo.sh` |
| Runbook nghiệm thu | `docs/operations/sentinel-live-acceptance-runbook.md` |
| Bộ eval Charter | `evaluation/charter-eval/cases.json`, `evaluation/charter-eval/gold.json` |
| Demo site hiện có | `/demo/week-03/` |
| Mô tả sản phẩm 1–2 trang | `docs/product/sentinel-charter-brief.md` |

## 2. Luồng

```text
scan lab → chuẩn hóa finding → tra cứu tri thức
        │
        ▼
agent tạo report có evidence → proposal trong catalog
        │
        ▼
HITL reject / approve → Charter executor → Kong gateway
        │
        ├── reject: không gửi request
        ▼
response/finding → IPI quarantine + PII/secret redaction → artifact an toàn hơn
```

Sơ đồ là kiến trúc đã dựng. Số liệu live gateway gần nhất vẫn ở báo cáo Tuần 4.

## 3. Đánh giá

`evaluation/charter-eval/cases.json` có **năm** case CE-01..05 (đề bài yêu cầu
5–10). `gold.json` là đáp án để so sánh với kết quả agent.

| Nhóm | Mục tiêu |
|---|---|
| CE-01..05 | Kiểm tra workflow Charter theo case đã ghi |
| Gateway/HITL | proposal có catalog, reject không gửi, approve mới đủ điều kiện |
| Guardrail | IPI và PII có nhánh quarantine/redaction |

## 4. Số liệu và giới hạn

Bằng chứng live gần nhất của gateway nằm ở báo cáo Tuần 4, ngày
**2026-08-14**: `tests/test_charter_requests.py` **67** passed và
`REQUIRE_KONG=1 tests/gateway-authz-test.sh` **43** passed. Tuần 6 không chạy
lại bộ live đó.

Eval dừng ở CE-01..05. Demo tương tác trên site là `/demo/week-03/`.
Syndicate/Phoenix thuộc chương trình 12 tuần, không nằm trong sáu tuần này.

## 5. Mô tả sản phẩm và đóng gói

Bản mô tả sản phẩm (vấn đề, người dùng, giá trị, phạm vi, hạn chế, hướng tiếp)
nằm trong repo tại `docs/product/sentinel-charter-brief.md`.

Demo đủ cảnh đề bài (quét, báo cáo, đề xuất, approve/reject, gateway, IPI,
che PII) chạy bằng `scripts/sentinel-demo.sh` và
`docs/operations/sentinel-live-acceptance-runbook.md`.

| Hạng mục tuần 6 | Trong repo |
|---|---|
| Docker Compose | Sáu file, bật bằng `scripts/sentinel-charter-up.sh` |
| Metrics | `RunMetrics/v1` trong `scripts/sentinel-manifest.py` |
| Eval 5–10 | CE-01..05 + `gold.json` |
| README + kiến trúc | README + `docs/sentinel-six-week-as-built-architecture.md` |
| Demo | `sentinel-demo.sh` + runbook + `/demo/week-03/` |
| Test/eval nộp lại | bốn lệnh `.venv` ở mục 6 |

Khi chạy eval, `evaluation/charter-eval/result-report.py` so với gold. Báo cáo
tuần này không in thêm bảng điểm live.

## 6. Chạy lại

### Test và eval

Chạy từ thư mục gốc repo. Cần `python3` (nếu thiếu `.venv/bin/pip`, cài
`python3-venv` rồi tạo lại venv). Không `source infra/.env`. Không
`pip install -r rag/requirements.txt`.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest tests/test_week5_labeled_redaction.py tests/test_charter_requests.py -q
.venv/bin/python evaluation/pii-redaction/measure.py
```

### Demo và site

```bash
bash scripts/sentinel-demo.sh --help

bash scripts/website-sync-docs.sh
cd website && npm run build
```

Demo đầy đủ cần điều kiện trong
`docs/operations/sentinel-live-acceptance-runbook.md` và chỉ chạy trên lab
loopback. Các lệnh trên không thay cho số liệu live Tuần 4.
