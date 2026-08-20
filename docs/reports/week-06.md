# Project Sentinel: Báo cáo Tuần 6

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
| Runbook nghiệm thu live | `docs/operations/sentinel-live-acceptance-runbook.md` |
| Bộ eval Charter | `evaluation/charter-eval/cases.json`, `evaluation/charter-eval/gold.json` |
| Scorecard mẫu (dry-run) | `evaluation/charter-eval/charter-evaluation.json` |
| Demo 10–15 phút | `docs/operations/sentinel-charter-demo-runbook.md` |
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
5–10). `gold.json` là đáp án reviewer-owned. Bộ đánh giá **không** phải lần
nghiệm thu live: `result-report.py evaluate --run-dir` cần thư mục run 0600
(manifest, JSONL schema 1.0, request outcome, artifact-bindings). Artifact
tuần 3 đã commit là `week3-analysis/v1` / `week1-submission/v1`, không có
request hay manifest, nên evaluator chính thức **không chạy được** trên sample.

Scorecard đã commit là **sample / dry-run**, sinh bằng
`.venv/bin/python evaluation/charter-eval/score-sample.py` (cùng luật
`_matches` / TP-FP-FN-TN của `result-report.py`). File:
`evaluation/charter-eval/charter-evaluation.json`.
`live_run` = false. Lần chấm live vẫn cần operator chạy
`scripts/sentinel-demo.sh` rồi `result-report.py evaluate`.

| | Gold positive | Gold negative |
|---|---|---|
| Sample khớp | TP **0** | FP **0** |
| Sample không khớp | FN **4** | TN **1** |

| Case | Artifact | Truth | Outcome | Vì sao |
|---|---|---|---|---|
| CE-01 | normalized | positive | **FN** | Gold đòi `finding:54f7ccdc…` / nuclei / DAST. Sample tuần 3 dùng `week1-finding:57ffa7d8…`. |
| CE-02 | normalized | positive | **FN** | Gold đòi title `Charter HTTP missing security headers`, Info, `http://127.0.0.1:13000/`. Sample: `Missing Security Header`, Medium, `path:/rest/products`. |
| CE-03 | report | positive | **FN** | Cùng lệch identity / tên / vị trí / `confidence` (`medium` vs `high`). |
| CE-04 | normalized | negative | **TN** | Sample **không** chứa `finding:charter-forbidden-false-positive` — đúng vì đây là control âm. |
| CE-05 | request | positive | **FN** | Sample không có request outcome; gold đòi `action_sent: true`, `request_count: 1`. |

FN ở đây là **lệch thế hệ artifact** (mẫu tuần 3 vs gold Nuclei Charter), không
phải bảng điểm live của agent trên Juice Shop. FP = 0: sample không bịa
finding cấm. Không có số live TP/FN mới trong tháng 08/2026.

| Nhóm | Mục tiêu |
|---|---|
| CE-01..05 | So sample đã commit với gold đã ghi |
| Gateway/HITL | proposal có catalog, reject không gửi, approve mới đủ điều kiện |
| Guardrail | IPI và PII có nhánh quarantine/redaction |

## 4. Số liệu và giới hạn

Bằng chứng live gần nhất của gateway nằm ở báo cáo Tuần 4, ngày
**2026-08-14**: `tests/test_charter_requests.py` **67** passed và
`REQUIRE_KONG=1 tests/gateway-authz-test.sh` **43** passed. Tuần 6 không chạy
lại bộ live đó.

Eval dừng ở CE-01..05. Demo talk track 10–15 phút:
`docs/operations/sentinel-charter-demo-runbook.md`. Demo tương tác trên site
vẫn là `/demo/week-03/`. Syndicate/Phoenix thuộc chương trình 12 tuần, không
nằm trong sáu tuần này.

## 5. Mô tả sản phẩm và đóng gói

Bản mô tả sản phẩm (vấn đề, người dùng, giá trị, phạm vi, hạn chế, hướng tiếp)
nằm trong repo tại `docs/product/sentinel-charter-brief.md`.

Bảy cảnh đề bài (quét, báo cáo, đề xuất, approve/reject, gateway, IPI, che PII)
có talk track tại `docs/operations/sentinel-charter-demo-runbook.md`. Luồng
live đầy đủ vẫn cần
`docs/operations/sentinel-live-acceptance-runbook.md`.

| Hạng mục tuần 6 | Trong repo |
|---|---|
| Docker Compose | Sáu file, bật bằng `scripts/sentinel-charter-up.sh` |
| Metrics | `RunMetrics/v1` trong `scripts/sentinel-manifest.py` |
| Eval 5–10 | CE-01..05 + `gold.json` |
| Scorecard FP/FN | `evaluation/charter-eval/charter-evaluation.json` (dry-run) |
| README + kiến trúc | README + `docs/sentinel-six-week-as-built-architecture.md` |
| Demo 10–15 phút | `docs/operations/sentinel-charter-demo-runbook.md` |
| Module Tuần 5 (Postman loopback) | Một facade tại `infra/week5-demo/`; Postman trên laptop này gọi `127.0.0.1:18055`, không gửi Kong. LAN từ máy khác nằm ngoài chính sách. |
| Test/eval nộp lại | năm lệnh `.venv` ở mục 6 |

Tái tạo scorecard (không cần live run):

```bash
.venv/bin/python evaluation/charter-eval/score-sample.py
```

Evaluator chính thức (`result-report.py evaluate --run-dir RUN`) chỉ chạy sau
một lần Charter local đã xong.

## 6. Chạy lại

### Test và eval

Chạy từ thư mục gốc repo. Cần `python3` (nếu thiếu `.venv/bin/pip`, cài
`python3-venv` rồi tạo lại venv). Không `source infra/.env`. Không
`pip install -r rag/requirements.txt`.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest tests/test_week5_labeled_redaction.py tests/test_charter_requests.py tests/test_week5_demo_facade.py -q
.venv/bin/python evaluation/pii-redaction/measure.py
PYTHON=.venv/bin/python bash tests/week5-demo-facade-test.sh
.venv/bin/python evaluation/charter-eval/score-sample.py
```

### Demo và site

```bash
bash scripts/sentinel-demo.sh

bash scripts/website-sync-docs.sh
cd website && npm run build
```

Talk track 10–15 phút: `docs/operations/sentinel-charter-demo-runbook.md`.
Demo đầy đủ (approve rồi gửi Kong) cần điều kiện trong
`docs/operations/sentinel-live-acceptance-runbook.md` và chỉ chạy trên lab
loopback. Các lệnh trên không thay cho số liệu live Tuần 4.
