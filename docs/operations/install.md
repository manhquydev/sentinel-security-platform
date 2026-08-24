# Hướng dẫn cài đặt — Charter

Một trang cho thành viên mới. Chạy mọi lệnh từ **thư mục gốc repo**. Không `source infra/.env`. Không commit `infra/.env` hay raw scan.

Ba tầng, chọn đúng tầng:

| Tầng | Cần trên máy | Làm được |
|---|---|---|
| A. Grader | `python3`, `python3-venv` / `ensurepip` | Test mentor + đo PII |
| B. Demo 7 cảnh (offline) | A + (Docker **hoặc** một process Python) | IPI / HITL preview / PII trên `127.0.0.1:18055` |
| C. Topology live | B + Docker + `jq` + `infra/.env` (từ example) + ADC | Kong / Juice Shop / `sentinel-demo.sh` — **operator** |

## A. Grader (bắt buộc cho clone mới)

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest tests/test_week5_labeled_redaction.py tests/test_charter_requests.py tests/test_week5_demo_facade.py -q
.venv/bin/python evaluation/pii-redaction/measure.py
PYTHON=.venv/bin/python bash tests/week5-demo-facade-test.sh
```

Không dùng `python3 -m pip` / `python3 -m pytest` trên host. Không `pip install -r rag/requirements.txt` cho tầng này.

Bộ overlay (pydantic, …) là tùy chọn: [`full-test-suite.md`](full-test-suite.md).

## B. Demo facade (không cần `infra/.env`)

```bash
# một trong hai — đừng chạy cả hai (cùng cổng 18055)
docker compose -f infra/week5-demo/docker-compose.yml up --build -d --wait
# hoặc:
PYTHONPATH=. .venv/bin/python scripts/sentinel-week5-demo.py
```

`GET http://127.0.0.1:18055/health` phải `{"ok": true}`. Lệnh bảy cảnh: [`charter-demo.md`](charter-demo.md). Gói curl: `bash scripts/week5-demo-curl.sh`.

## C. Topology live (operator)

1. `cp infra/.env.example infra/.env` rồi điền key (không paste vào git/chat).
2. ADC Vertex: đường dẫn trong `VERTEXAI_ADC_PATH` phải đọc được.
3. Docker, `jq`, pin `scanners/image-pins.env`.
4. `bash scripts/sentinel-charter-up.sh` — **chỉ bật compose**, không phải một lần chạy Charter.
5. `bash scripts/sentinel-live-preflight.sh base` (thiếu `base` / `dispatch` thì script exit 2).
6. Runbook live: [`sentinel-live-acceptance-runbook.md`](sentinel-live-acceptance-runbook.md).

## Quét → báo cáo (offline, từ finding đã commit)

```bash
PYTHONPATH=. .venv/bin/python scripts/analyze-week1-aggregate.py
```

Đọc `artifacts/week1.aggregate.jsonl` (36 finding) và ghi `docs/reports/artifacts/week1-aggregate-report.jsonl`. Không gọi LiteLLM. Không phải điểm AI live.

## Proof quét + che secret (Docker + `jq`, không lake)

Khối trong [`README.md`](../../README.md) § Proof: `run-trivy.sh` rồi `redact-report.sh`.

## Không làm

- Quét target ngoài `http://127.0.0.1:13000`.
- Bind facade `0.0.0.0`.
- Lấy mật khẩu lab từ git (`infra/.env` không trên GitHub).
- Dùng Workbench (`scripts/workbench-up.sh`) làm bằng chứng Charter.
