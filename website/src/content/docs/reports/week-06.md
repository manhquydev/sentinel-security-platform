---
title: "Tuần 6: Tích hợp, đánh giá và demo"
description: "Báo cáo Tuần 6: luồng Charter, CE-01..05 và kịch bản 12 phút"
---

> **Xem nguồn:** [Markdown](/reports/week-06/markdown/) · [Raw `.md`](/raw/reports/week-06.md) · [llms.txt](https://vinsoc.manhquy.id.vn/llms.txt)

Tuần 6 em ghép các phần đã làm thành một demo Charter có thể trình bày trong
12 phút: quét, tạo report, đề xuất request, người duyệt reject/approve, gateway,
quarantine IPI và che PII. Số liệu ở đây lấy từ test/eval đã commit, không phải
nghiệm thu live mới trong tháng 08/2026.

## 1. Việc em đã làm

Tuần cuối tập trung vào cách nối các chốt thành một luồng có thể giải thích:
scanner tạo tín hiệu, agent chỉ dùng tri thức có nguồn, proposal bị giới hạn
catalog, executor cần approval, rồi guardrail/quarantine/redaction giữ dữ liệu
an toàn hơn khi đi qua các ranh giới.

| Việc | Chỗ trong repo |
|---|---|
| Luồng kiến trúc 9 bước | `docs/sentinel-six-week-as-built-architecture.md` |
| Lệnh demo Charter | `scripts/sentinel-demo.sh` |
| Runbook nghiệm thu | `docs/operations/sentinel-live-acceptance-runbook.md` |
| Bộ eval Charter | `evaluation/charter-eval/cases.json`, `evaluation/charter-eval/gold.json` |
| Demo site hiện có | `/demo/week-03/` |

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

Sơ đồ mô tả kiến trúc as-built. Nó không thay cho một lần live acceptance đủ
sáu tuần trên đúng checkout hiện tại.

## 3. Đánh giá

`evaluation/charter-eval/cases.json` có **CE-01..05**. Đây là năm case đạt
ngưỡng đề bài 5–10; không được nói thành 10 case. `gold.json` giữ expected
behavior để đo được thay vì chỉ kể demo bằng lời.

| Nhóm | Mục tiêu |
|---|---|
| CE-01..05 | Kiểm tra workflow Charter theo case committed |
| Gateway/HITL | proposal có catalog, reject không gửi, approve mới đủ điều kiện |
| Guardrail | IPI và PII có nhánh quarantine/redaction |

## 4. Số liệu và giới hạn

Bằng chứng live gần nhất của gateway nằm ở báo cáo Tuần 4, ngày
**2026-08-14**: `tests/test_charter_requests.py` **67** passed và
`REQUIRE_KONG=1 tests/gateway-authz-test.sh` **43** passed. Tuần 6 không tạo
lại số live đó.

Giới hạn cần nói rõ: eval chỉ có CE-01..05; kiến trúc không tự chứng minh
live acceptance; demo site tương tác là `/demo/week-03/`, không phải một lab
public cho toàn bộ Charter. Syndicate/Phoenix là phần mở rộng 12 tuần, không
phải nội dung chính của Tuần 6 mentor.

## 5. Kịch bản nói 12 phút

| Phút | Trình bày |
|---|---|
| 0:00–1:00 | Mục tiêu: scan lab nhưng không để agent tự gửi request tùy ý |
| 1:00–2:30 | Scan và chuẩn hóa finding; mở report có evidence |
| 2:30–4:00 | Agent tạo proposal từ catalog, không bịa path |
| 4:00–5:00 | Chọn **reject** và chỉ vào test no-send |
| 5:00–6:30 | Chọn approval hợp lệ rồi mô tả executor/gateway |
| 6:30–8:00 | Cho fixture IPI vào guard và xem quarantine |
| 8:00–9:30 | Cho PII/secret có nhãn qua redactor, chỉ giữ placeholder |
| 9:30–11:00 | Mở CE-01..05 và giới hạn của số liệu committed |
| 11:00–12:00 | Tóm tắt trust boundary, không overclaim live |

## 6. Chạy lại

### Chạy lại test & eval (Mentor / grader)

Chạy từ thư mục gốc repo. Cần `python3` (nếu thiếu `.venv/bin/pip`, cài `python3-venv` / `ensurepip` rồi dừng). Không `source infra/.env`. Không `pip install -r rag/requirements.txt`. Không chạy `python3 -m pip` / `python3 -m pytest` trên host. Bare `pytest` không phải bài chấm:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest tests/test_week5_labeled_redaction.py tests/test_charter_requests.py -q
.venv/bin/python evaluation/pii-redaction/measure.py
```

### Vận hành demo & site mentor (Operator)

Chạy từ thư mục gốc repo:

```bash
# Demo spine (cần prerequisite trong runbook)
bash scripts/sentinel-demo.sh --help

# Site mentor local
bash scripts/website-sync-docs.sh
cd website && npm run build
```

Nếu chạy full demo, đọc `docs/operations/sentinel-live-acceptance-runbook.md`
trước và giữ mọi dịch vụ ở môi trường lab/loopback. Không coi lệnh này là
bằng chứng đã chạy live trong báo cáo.
