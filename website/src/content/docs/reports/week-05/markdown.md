---
title: "Tuần 5: IPI, HITL và che dữ liệu, nguồn Markdown"
description: "Nguồn Markdown đầy đủ, đọc / sao chép"
---

Trang HTML: [Tuần 5: IPI, HITL và che dữ liệu](/reports/week-05/) · [Tải raw](/raw/reports/week-05.md) · [llms.txt](https://vinsoc.manhquy.id.vn/llms.txt)

Nội dung dưới đây là **toàn bộ file Markdown** trong monorepo (`docs/reports/week-05.md`), không qua bước render HTML.

````markdown
# Project Sentinel: Báo cáo Tuần 5

Tuần 5 em thêm các chốt an toàn quanh agent: coi nội dung lấy từ app là dữ liệu
không tin cậy, không làm theo chỉ dẫn trong HTTP response, duyệt tay trước khi
gửi POST, và che email / SĐT / token / API key / password trước khi lưu.

Số liệu dưới đây đo ngày **2026-08-18** trên mã trong repo (pytest +
`evaluation/pii-redaction/measure.py`). Không phải lần chạy live Kong mới.

## 1. Việc em đã làm

Đề bài cần bộ lọc Prompt Injection cơ bản, Approve/Reject, che dữ liệu nhạy cảm,
và ít nhất hai ca mỗi loại (IPI, PII, phê duyệt) với Pass/Fail rõ.

| Việc | Chỗ trong repo |
|---|---|
| Coi response app là dữ liệu | `agent/charter_response_guard.py` |
| Hai fixture IPI | `tests/fixtures/charter-response-ipi-goal.json`, `tests/fixtures/charter-response-ipi-secrets.json` |
| Prompt hệ thống (không đổi mục tiêu, không lộ secret, không gọi tool ngoài) | `agent/prompts/charter-system-prompt.md` |
| Guard cấu trúc (số liệu scanner không bị narrative nuốt) | `agent/guard.py` |
| Catalog request + duyệt CLI | `agent/charter_proposal.py`, `scripts/sentinel-charter-approve.py` |
| Reject thì không gửi | `agent/charter_requests.py`, `tests/test_charter_requests.py` |
| Che PII có nhãn | `agent/pii.py`, `evaluation/pii-redaction/` |
| Che secret trên persist / egress | `agent/trace.py`, `infra/litellm/guardrails/egress_redaction.py` |
| Test bổ sung tuần này | `tests/test_week5_labeled_redaction.py` |

## 2. Luồng

```
HTTP response / finding từ app
        │
        ▼
charter_response_guard.py
  (IPI regex + PII shape → quarantine)
        │
        ▼
agent/guard.py  — dữ liệu, không phải chỉ dẫn
        │
        ▼
charter_proposal.py  →  một case trong catalog
        │
        ▼
người duyệt  Approve / Reject
        │
        ├── Reject  →  không gọi mạng
        └── Approve →  executor gửi qua Kong
                       │
                       ▼
              pii.redact + redact_persisted
              (che trước khi lưu)
```

## 3. IPI, HITL và PII

Hai ca IPI (đúng tối thiểu đề bài):

| Fixture | Ý |
|---|---|
| `charter-response-ipi-goal.json` | response bảo đổi mục tiêu |
| `charter-response-ipi-secrets.json` | response đòi lộ secret |

Guard coi đó là dữ liệu và quarantine. Em không cam bộ lọc bắt mọi câu
tiếng Việt hay câu bị động.

Hai ca HITL: test reject và revoke không mint token, không gọi HTTP
(`tests/test_charter_requests.py`). CLI in method, path, body, mục đích,
expiry, digest rồi hỏi `[y/N]`.

Hai ca PII trở lên: email, thẻ có nhãn, JWT, UUID, và `user_phone=` (có dấu `=`).
Password gán `password=` / `db_password=` và vài prefix API key (`sk-`,
`sk_live_`, `sk_test_`, `AIzaSy`, `glpat-`) được che trên đường persist và
egress.

## 4. Số liệu 2026-08-18

| Kiểm | Kết quả |
|---|---|
| `tests/test_charter_requests.py` | **67** passed (cùng bộ Tuần 4; có case `ConnectionError`) |
| `tests/test_week5_labeled_redaction.py` | **16** passed |
| `tests/test_gateway_guardrails.py` | **61** passed |
| Preview PII không nhãn `{"contact":"0123456789"}` | quarantine (1 test hẹp) |
| `evaluation/pii-redaction/measure.py` | recall **10/10**, FP **0/10** |
| Phone không nhãn `phone +1-202-555-0143 on file` | **gap** đã ghi trong corpus |

Các số đo trên máy ngày 2026-08-18. Khối lệnh Mục 6 chạy hai file pytest và
`measure.py`; không gồm `tests/test_gateway_guardrails.py`.

## 5. Demo

Ba bước trên CLI, cùng demo tương tác Tuần 3 trên site:

1. Đưa fixture IPI vào guard → thấy quarantine.
2. Tạo request từ catalog, chọn Reject → không gửi.
3. In chuỗi `user_phone=` / `db_password=` qua `pii.redact` và
   `trace.redact_persisted` → còn placeholder.

```bash
PYTHONPATH=. .venv/bin/python -c "from agent.pii import redact; print(redact('user_phone=+12025550143')[0])"
.venv/bin/python -m pytest tests/test_week5_labeled_redaction.py -q
```

## 6. Chạy lại

Chạy từ thư mục gốc repo. Cần `python3` (nếu thiếu `.venv/bin/pip`, cài
`python3-venv` rồi tạo lại venv). Không `source infra/.env`. Không
`pip install -r rag/requirements.txt`.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest tests/test_week5_labeled_redaction.py tests/test_charter_requests.py -q
.venv/bin/python evaluation/pii-redaction/measure.py
```

Không in `infra/.env`, API key, hay payload người thật.

## 7. Việc em chưa làm tuần này

Đề bài đã có filter, HITL, che dữ liệu, và đủ ca Pass/Fail. Em chưa:

- Che SĐT viết `phone +1-…` không có dấu `=`
- Che `customer_phone=` / `admin_password=` (khóa có tiền tố `customer_` /
  `admin_` chưa nằm trong bộ khóa hiện tại)
- Che secret trong preview GET khi body đã được chấp nhận (preview giữ nguyên
  đoạn đầu)
- Gộp các bộ che secret ở importer Tuần 1, Trivy và RAG thành một chỗ
- Đưa số điện thoại sang đường egress LiteLLM (phone được che khi lưu log;
  đường gọi model chỉ che secret)
````
