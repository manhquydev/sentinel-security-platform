---
title: "Tuần 4: API Gateway và request an toàn"
description: "Báo cáo Tuần 4: Kong, Python tool, allowlist, live 2026-08-14"
---

> **Xem nguồn:** [Markdown](/reports/week-04/markdown/) · [Raw `.md`](/raw/reports/week-04.md) · [llms.txt](https://vinsoc.manhquy.id.vn/llms.txt)

Tuần 4 em đặt API Gateway trước Juice Shop, viết Python tool gửi GET/POST
qua gateway, và khóa endpoint bằng allowlist + API key riêng.

Số liệu live lấy ngày **2026-08-14** (`outputs/week4-live/2026-08-14-evidence.md`).
Kong và Juice Shop lúc đó healthy trên loopback.

## 1. Việc em đã làm

Đề bài cần gateway (Kong/Nginx/gateway đơn giản), API key cho công cụ, allowlist,
Python tool (GET, POST, header, đọc status + một phần response), giới hạn
request/phút + timeout + kích thước response, và payload an toàn.

Em dùng Kong. Tool không nhận path/query/body tùy ý — chỉ vài case cố định
(chuỗi dài, ký tự đặc biệt, rỗng, sai kiểu).

| Việc | Chỗ trong repo |
|---|---|
| API Gateway | `infra/kong/` (TLS `127.0.0.1:18443` → Juice Shop) |
| App lab | `infra/harness/juice-shop.compose.yml` (`127.0.0.1:13000`) |
| Allowlist (route + method) | `infra/kong/kong.declarative.yml.tmpl` |
| API key riêng cho tool | `X-Sentinel-API-Key` (tên key trong `infra/.env.example`) |
| Python tool | `agent/charter_requests.py`, `scripts/sentinel-charter-executor.py` |
| Agent đề xuất request | `agent/charter_proposal.py` |
| Nhật ký | Kong `file-log` (stdout); receipt digest trong run |
| Test | `tests/gateway-authz-test.sh`, `tests/test_charter_requests.py` |

## 2. Luồng

```
Agent đọc report tuần 3
        │
        ▼
charter_proposal.py  →  một request trong catalog
        │
        ▼
người duyệt (approve / reject)
        │
        ▼
sentinel-charter-executor.py
        │
        ▼
Kong 127.0.0.1:18443  ──allowlist + API key──►  Juice Shop
        │
        ▼
status + một phần response (cắt / digest)
```

Request của tool đi `https://127.0.0.1:18443`, không đổi sang `:13000`.

## 3. Allowlist và payload

Route Kong (rút): GET `/rest/products/search` (và vài path public), POST
`/rest/basket`. Prefix tool: `/sentinel-charter/...` rồi gateway đổi lại path app.
Path không nằm trong policy thì 403/404, không lọt ACL qua `/oauth/...`.

Catalog tool (đúng loại đề bài):

| Case | Ý |
|---|---|
| GET `q=apple` | baseline |
| GET `q=` | rỗng |
| GET ký tự `%21%40%23…` | đặc biệt |
| GET `q=` + 256 chữ `a` | chuỗi dài |
| POST `{}` | rỗng |
| POST `{"quantity":"not-a-number"}` | sai kiểu |

Giới hạn phía tool: 5 request / phút, timeout 5s, response tối đa 64 KiB.
Timeout và lỗi kết nối → không crash, không giả success.

## 4. Số liệu 2026-08-14

| Kiểm | Kết quả |
|---|---|
| Juice Shop `127.0.0.1:13000` | healthy |
| Kong `127.0.0.1:18443` | healthy |
| `tests/test_charter_requests.py` | **67** passed (có case `ConnectionError`) |
| `REQUIRE_KONG=1 tests/gateway-authz-test.sh` | **43** passed, 0 failed |

Live qua gateway (cùng ngày):

| Gọi | Mã |
|---|---|
| GET `/rest/products/search` (identity đọc public) | **200** |
| GET `/rest/admin/application-version` (cùng identity) | **403** |
| POST `/rest/basket` (cùng identity) | **403** |
| Tool thiếu API key / chỉ API key | **401** |
| Tool OAuth + API key, GET search | **200** |
| POST `/oauth/rest/basket` (né ACL) | **404** |

Nhật ký Kong: có JSON request/response metadata. Không thấy bearer, provision
key, client secret, hay API key trong audit stream (cùng test live).

## 5. Demo: agent đề xuất, tool gửi

`charter_proposal.py` chọn một case trong catalog (không bịa path từ finding).
`sentinel-charter-executor.py` mới gửi qua Kong.

```bash
# đề xuất từ report tuần 3 (không gửi mạng)
PYTHONPATH=. python3 -c "from agent.charter_proposal import propose_report_jsonl; p=propose_report_jsonl('docs/reports/artifacts/week3-sample-report.jsonl'); print(p.available, p.case_id, p.method, p.path)"

# gửi thật: spec + chữ ký duyệt + secret trong env (không in key)
python3 scripts/sentinel-charter-executor.py spec.json approval.json \
  --state /tmp/executor.sqlite --public-key path/to/public.pem
```

Luồng đủ bước: `bash scripts/sentinel-demo.sh run --profile charter --run-id RUN`.
Trang demo tương tác trên site vẫn là `/demo/week-03/`.

## 6. Chạy lại

Test không live (venv trong repo, không dùng `python3 -m pytest` trên host):

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest tests/test_charter_requests.py -q
```

Kong live cần Docker Compose và `infra/.env` (mẫu `infra/.env.example`):

```bash
docker compose -f infra/harness/juice-shop.compose.yml up -d
bash infra/kong/render-config.sh
docker compose --env-file infra/.env -f infra/kong/docker-compose.yml up -d

# nếu import Kong báo UNIQUE client_id: down -v rồi up lại (README infra/kong)

set -a && . infra/.env && set +a
REQUIRE_KONG=1 bash tests/gateway-authz-test.sh
```

Không commit `infra/.env` hay `kong.rendered.yml`. Không dán API key vào báo cáo.
