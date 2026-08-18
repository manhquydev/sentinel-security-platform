---
title: "Tuần 5: IPI, HITL và che dữ liệu"
description: "Báo cáo Tuần 5: guard dữ liệu không tin cậy, duyệt request, PII"
---

> **Xem nguồn:** [Markdown](/reports/week-05/markdown/) · [Raw `.md`](/raw/reports/week-05.md) · [llms.txt](https://vinsoc.manhquy.id.vn/llms.txt)

Tuần 5 em thêm các chốt an toàn quanh agent: coi nội dung lấy từ app là dữ liệu
không tin cậy, không làm theo chỉ dẫn trong HTTP response, duyệt tay trước khi
gửi POST, và che email / SĐT / token / API key / password trước khi lưu.

Số liệu dưới đây đo ngày **2026-08-18** trên mã nguồn trong repo này (pytest +
`evaluation/pii-redaction/measure.py`). Không phải lần chạy live Kong/Juice Shop
mới.

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

Guard coi đó là dữ liệu và quarantine. Đây không phải lời hứa chặn mọi câu
tiếng Việt / câu bị động.

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
| `tests/test_charter_requests.py` | **67** passed (bằng chứng Tuần 4; có case `ConnectionError`) |
| `tests/test_week5_labeled_redaction.py` | **16** passed |
| `tests/test_gateway_guardrails.py` | **61** passed |
| Preview PII không nhãn `{"contact":"0123456789"}` | quarantine (1 test hẹp) |
| `evaluation/pii-redaction/measure.py` | recall **10/10**, FP **0/10** |
| Phone không nhãn `phone +1-202-555-0143 on file` | vẫn **gap** (cố ý) |

Các số này là test/eval trên máy, không phải live gateway tháng 08.

## 5. Demo

Em demo không cần trang `/demo/week-05/` mới:

1. Đưa fixture IPI vào guard → thấy quarantine.
2. Tạo request từ catalog, chọn Reject → không gửi.
3. In chuỗi `user_phone=` / `db_password=` qua `pii.redact` và
   `trace.redact_persisted` → còn placeholder.

Hub site chỉ link báo cáo này và demo tương tác Tuần 3.

```bash
PYTHONPATH=. python3 -c "from agent.pii import redact; print(redact('user_phone=+12025550143')[0])"
python3 -m pytest tests/test_week5_labeled_redaction.py -q
```

## 6. Chạy lại

Cần `python3`. Không cần Docker cho các lệnh dưới.

```bash
python3 -m pytest tests/test_week5_labeled_redaction.py \
  tests/test_charter_requests.py -q

python3 evaluation/pii-redaction/measure.py
```

`tests/week7-ipi-guard-test.sh` và `tests/charter-hitl-request-test.sh` cần
`rag/.venv`. Thiếu venv thì hai script đó thoát mã 2; dùng pytest ở trên.

Không in `infra/.env`, API key, hay payload người thật.

## 7. Việc em chưa đóng

Đề bài Tuần 5 đã có filter, HITL, che dữ liệu, và đủ ca Pass/Fail. Em **chưa**:

- Che SĐT viết `phone +1-…` không có `=` (gap đã ghi trong corpus)
- Che `customer_phone=` / `admin_password=` (chỉ khóa `user_phone` và `db_password`)
- Che secret nằm trong preview GET (guard giữ nguyên body đã chấp nhận)
- Gom bản copy secret ở importer Tuần 1 / Trivy / RAG vào cùng một chỗ
- Đưa phone sang đường egress LiteLLM (cố ý: phone là PII, không phải secret)

Những dòng trên vẫn còn trong mã. Báo cáo này không gọi là “Tuần 5 xong 100% mọi residual”.
