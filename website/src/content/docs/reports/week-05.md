---
title: "Tuần 5: IPI, HITL và che dữ liệu"
description: "Báo cáo Tuần 5: guard dữ liệu không tin cậy, duyệt request, PII"
---

> **Xem nguồn:** [Markdown](/reports/week-05/markdown/) · [Raw `.md`](/raw/reports/week-05.md) · [llms.txt](https://vinsoc.manhquy.id.vn/llms.txt)

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
| Demo module (HTTP loopback) | `scripts/sentinel-week5-demo.py`, `infra/week5-demo/` |

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

Các số đo trên máy ngày 2026-08-18. Khối lệnh Mục 6 chạy pytest đã liệt kê,
`measure.py` và kiểm facade; không gồm `tests/test_gateway_guardrails.py`.

## 5. Demo

HITL thật của Charter vẫn là CLI (`scripts/sentinel-charter-approve.py`). Em thêm
một module facade duy nhất cho ba cảnh demo; Postman trên chính laptop này gọi
module qua `http://127.0.0.1:18055`. Facade chỉ minh họa luồng, không gửi
request qua Kong; ngay cả khi chọn Approve, demo vẫn ghi nhận request chưa
được gửi.

Ba cảnh:

1. IPI: `POST /demo/ipi` với fixture `goal` → `quarantined`.
2. HITL: `POST /demo/hitl/preview` rồi `POST /demo/hitl/decide` `reject` →
   không gửi.
3. PII: `POST /demo/pii` với `user_phone=+12025550143` → placeholder.

```bash
docker compose -f infra/week5-demo/docker-compose.yml up --build -d --wait
bash scripts/week5-demo-curl.sh
```

Postman trên máy này: import `evaluation/week5-demo/week5-demo.postman.json`
(base `http://127.0.0.1:18055`). Không chạy `python3 scripts/sentinel-week5-demo.py`
cùng lúc với Docker — trùng cổng 18055.

Không Docker thì một lệnh: `PYTHONPATH=. python3 scripts/sentinel-week5-demo.py`

CLI (sau khối venv Mục 6):

```bash
PYTHONPATH=. .venv/bin/python -c "from agent.pii import redact; print(redact('user_phone=+12025550143')[0])"
.venv/bin/python -m pytest tests/test_week5_labeled_redaction.py tests/test_week5_demo_facade.py -q
```

Postman từ máy khác trong LAN nằm ngoài chính sách của demo; mentor vui lòng
xem trên laptop chạy demo hoặc qua chia sẻ màn hình.

## 6. Chạy lại

Chạy từ thư mục gốc repo. Cần `python3` (nếu thiếu `.venv/bin/pip`, cài
`python3-venv` rồi tạo lại venv). Không `source infra/.env`. Không
`pip install -r rag/requirements.txt`.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest tests/test_week5_labeled_redaction.py tests/test_charter_requests.py tests/test_week5_demo_facade.py -q
.venv/bin/python evaluation/pii-redaction/measure.py
bash tests/week5-demo-facade-test.sh
```

Không in `infra/.env`, API key, hay payload người thật.
