# Hướng dẫn chạy demo Charter (7 cảnh)

Tài liệu **tracked** để teammate clone-and-run. Không phải kịch bản nói 15 phút (file đó local / gitignore). Không phải nghiệm thu live: [`sentinel-live-acceptance-runbook.md`](sentinel-live-acceptance-runbook.md).

Mọi lệnh từ **thư mục gốc repo**. Cài tầng A+B: [`install.md`](install.md).

| Mặc định | Giá trị |
|---|---|
| Python | `.venv/bin/python` |
| Facade | `http://127.0.0.1:18055` only |
| Target live | Juice Shop `127.0.0.1:13000` sau Kong `127.0.0.1:18443` |

Walkthrough không mạng: [`/demo/charter/`](https://vinsoc.manhquy.io.vn/demo/charter/) — không thay CLI.

---

## 0. Bật facade (cảnh 3, 4, 6, 7)

```bash
docker compose -f infra/week5-demo/docker-compose.yml up --build -d --wait
# hoặc, không Docker:
PYTHONPATH=. .venv/bin/python scripts/sentinel-week5-demo.py
```

`GET http://127.0.0.1:18055/health` → `{"ok": true}`.

---

## 1. Một lần chạy công cụ quét

Offline (image pin, không cần Juice Shop):

```bash
command -v jq >/dev/null
workspace="$(mktemp -d)"
source scanners/image-pins.env
export IMAGE="$JUICE_SHOP_IMAGE" TRIVY_SCANNERS="secret,misconfig"
./scanners/run-trivy.sh "$workspace/trivy.raw.json"
./scanners/redact-report.sh trivy "$workspace/trivy.raw.json" /tmp/trivy.sanitized.json
```

Live (operator): `SENTINEL_PYTHON=.venv/bin/python bash scripts/sentinel-demo.sh run --profile charter --run-id demo` — stage `scan-redact-import`. Exit **75** = dừng HITL, không phải crash.

---

## 2. Agent tạo báo cáo

Từ finding tuần 1 đã commit (offline, không LiteLLM):

```bash
PYTHONPATH=. .venv/bin/python scripts/analyze-week1-aggregate.py
.venv/bin/python -c 'from pathlib import Path; print(Path("docs/reports/artifacts/week1-aggregate-report.jsonl").read_text()[:500])'
```

Kỳ vọng: JSONL `week3-analysis/v1`, 36 dòng, `finding_id` `week1-finding:…`. Sample synthetic tuần 3 (`week3-sample-report.jsonl`) là **file khác**, không nối week-1.

Live: `.sentinel-runs/demo/report.jsonl` sau stage `analysis-report`.

---

## 3. Agent đề xuất request kiểm tra

```bash
curl -fsS -H 'Content-Type: application/json' \
  -d '{"case_id":"post-empty-object"}' \
  http://127.0.0.1:18055/demo/hitl/preview
```

Kỳ vọng: `"method":"POST"`, `"path":"/sentinel-charter/rest/basket"`, `"sent":false`. Catalog cố định, không URL tùy ý.

---

## 4. Approve hoặc Reject

Facade (không gửi Kong):

```bash
curl -fsS -H 'Content-Type: application/json' \
  -d '{"case_id":"post-empty-object","decision":"reject"}' \
  http://127.0.0.1:18055/demo/hitl/decide
```

Kỳ vọng: `"decision":"reject"`, `"sent":false`. `approve` trên facade cũng `"sent":false`.

Live signer: `scripts/sentinel-charter-approve.py` + resume — xem live-acceptance.

---

## 5. Request đi qua API Gateway

**Không có đường offline.** Nếu chưa có Kong / key: dừng ở cảnh 4, đừng giả gửi.

Live: `scripts/sentinel-live-preflight.sh dispatch demo` rồi `sentinel-demo.sh resume demo` sau envelope `approve`. Kỳ vọng `receipt.json`, `action_sent: true`. Chi tiết: live-acceptance.

---

## 6. Prompt injection bị chặn

```bash
curl -fsS -H 'Content-Type: application/json' \
  -d '{"fixture":"goal"}' \
  http://127.0.0.1:18055/demo/ipi
```

Kỳ vọng: `"status":"quarantined"`, `"sent":false`. Fixture: `tests/fixtures/charter-response-ipi-goal.json`.

---

## 7. Dữ liệu nhạy cảm bị che

```bash
curl -fsS -H 'Content-Type: application/json' \
  -d '{"text":"user_phone=+12025550143"}' \
  http://127.0.0.1:18055/demo/pii
```

Kỳ vọng: số điện thoại không còn trong `"redacted"`; `"sent":false`.

Gói 3+4+6+7: `bash scripts/week5-demo-curl.sh` → `ipi quarantined`, `pii redacted`, `hitl reject not_sent`.

Không server:

```bash
PYTHONPATH=. .venv/bin/python -c "from agent.pii import redact; print(redact('user_phone=+12025550143')[0])"
```

---

## Tắt facade

```bash
docker compose -f infra/week5-demo/docker-compose.yml down
```

hoặc Ctrl-C process `sentinel-week5-demo.py`.

Không in `infra/.env`, API key, hay body target thô.
