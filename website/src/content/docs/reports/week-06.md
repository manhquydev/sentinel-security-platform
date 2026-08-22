---
title: "Tuần 6: Tích hợp, đánh giá và demo"
description: "Báo cáo Tuần 6: ghép luồng, đánh giá, demo và đóng gói"
---

> **Xem nguồn:** [Markdown](/reports/week-06/markdown/) · [Raw `.md`](/raw/reports/week-06.md) · [llms.txt](https://vinsoc.manhquy.id.vn/llms.txt)

## 1. Việc em đã làm

Đề bài cần đóng gói Compose, nhật ký các bước chính, bộ 5–10 trường hợp có
đáp án, so sánh với đáp án, sơ đồ kiến trúc, và demo 10–15 phút.

| Việc | Chỗ trong repo |
|---|---|
| Sơ đồ kiến trúc | `docs/sentinel-six-week-as-built-architecture.md` |
| Một lệnh chạy demo | `scripts/sentinel-demo.sh` |
| Nhật ký (thời gian, số request, cảnh báo, lần duyệt, lỗi) | `scripts/sentinel-manifest.py` |
| 5 trường hợp + đáp án | `evaluation/charter-eval/cases.json`, `gold.json` |
| Bảng điểm mẫu | `evaluation/charter-eval/charter-evaluation.json` |
| Hướng dẫn chạy lại (nộp) | README · trang `/demo/charter/` · `scripts/sentinel-demo.sh` |
| Mô tả sản phẩm 1–2 trang | `docs/product/sentinel-charter-brief.md` |
| Docker Compose | `scripts/sentinel-charter-up.sh` |

## 2. Luồng

```
Máy quét (Trivy / Nuclei / Semgrep)
        │
        ▼
Gộp về một định dạng, che mật khẩu / token
        │
        ▼
Agent viết báo cáo (bám dữ liệu máy quét)
        │
        ▼
Đề xuất một request trong danh sách có sẵn
        │
        ▼
Người duyệt  Đồng ý / Từ chối
        │
        ├── Từ chối  →  không gửi
        └── Đồng ý   →  gửi qua cổng Kong
                       │
                       ▼
              Lọc chỉ dẫn độc + che email / token
              Ghi nhật ký
```

## 3. Bộ đánh giá

Đề cần 5–10 trường hợp. Em có năm case (`CE-01` … `CE-05`) và đáp án trong
`evaluation/charter-eval/`.

File bảng điểm đã commit là lần **chạy thử trên mẫu**, chưa phải chấm AI khi
hệ thống đang chạy thật. Đáp án dùng mã số khác với mẫu tuần 3 nên bảng trông
như 0 đúng / 4 trượt — đó là lệch file, không phải kết luận “AI kém”. Em không
dùng bảng đó như điểm lần chạy live.

Các bài kiểm tra an toàn trên repo (cùng ngày đo):

| Việc | Kết quả |
|---|---|
| Ba bài mentor hay chạy | **102** đạt |
| Che email / token / mật khẩu | **10/10**, không báo nhầm |
| Bộ đầy đủ hơn | **338** đạt |

In lại bảng điểm mẫu:

```bash
.venv/bin/python evaluation/charter-eval/score-sample.py
```

## 4. Demo

Đề cần thể hiện bảy cảnh. Trang [`/demo/charter/`](/demo/charter/) đi hết
cả bảy (bấm từng bước hoặc chạy lần lượt):

| # | Cảnh đề | Trên trang demo |
|---|---|---|
| 1 | Một lần chạy công cụ quét | Bước Quét + bản ghi Trivy |
| 2 | Agent tạo báo cáo | Bước Phân tích |
| 3 | Agent đề xuất request | Bước Đề xuất |
| 4 | Approve hoặc Reject | Bước Duyệt (bấm hai phía) |
| 5 | Request qua API Gateway | Bước Cổng |
| 6 | Prompt injection bị chặn | Bước Chặn độc (bấm hai phía) |
| 7 | Dữ liệu nhạy cảm bị che | Bước Che dữ liệu (bấm hai phía) |

Bằng chứng lấy từ lần chạy trên máy. Hai bản ghi màn hình:

1. Quét bằng Trivy rồi đưa 4 lỗ hổng vào DefectDojo (khoảng 7 giây).
2. Chạy bài kiểm tra trên máy: 102 đạt, che dữ liệu 10/10.

Cách vào DefectDojo cũng nằm trên trang demo: nút copy email Access, tài
khoản `admin`, và mật khẩu lab. `infra/.env` không có trên GitHub nên
không lấy mật khẩu từ repo. Rồi Products → `juice-shop-harness`. Hiện
bảng đó có **5** lỗ hổng lab (4 Trivy, 1 Nuclei).

DefectDojo chỉ hiện bước quét. Phân tích / duyệt / cổng vẫn là lệnh trên máy
(README + `scripts/sentinel-demo.sh`). Kịch bản nói 15 phút để em tự luyện,
không nộp.

## 5. Site tài liệu và DefectDojo

Sau khi ghép luồng, em đưa báo cáo lên site và cho xem lỗ hổng đã quét trên
DefectDojo (phần mềm sẵn có của OWASP, không phải giao diện do em tự viết).

| Địa chỉ | Việc |
|---|---|
| `vinsoc.manhquy.io.vn` | Đọc báo cáo và xem demo. Không cần đăng nhập. |
| `app.vinsoc.manhquy.io.vn` | Xem lỗ hổng đã đổ vào DefectDojo. |
| Repo trên máy | Chạy lệnh ở Mục 6. |

Sentinel quét Juice Shop (lab, không ra internet), che secret, rồi đổ kết quả
vào DefectDojo. Hiện bảng đó có **5** lỗ hổng lab (4 Trivy, 1 Nuclei). Số **36**
là file tổng hợp tuần 1 trong repo — khác chỗ.

Cách vào: trang [`/demo/charter/`](/demo/charter/) có nút copy email Access,
tài khoản `admin`, và mật khẩu lab. `infra/.env` không có trên GitHub.
Rồi vào Products → `juice-shop-harness`.

## 6. Chạy lại

### Test và eval

Chạy từ thư mục gốc repo. Cần `python3`. Không `source infra/.env`.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest tests/test_week5_labeled_redaction.py tests/test_charter_requests.py tests/test_week5_demo_facade.py -q
.venv/bin/python evaluation/pii-redaction/measure.py
PYTHON=.venv/bin/python bash tests/week5-demo-facade-test.sh
.venv/bin/python evaluation/charter-eval/score-sample.py
```

### Demo

```bash
SENTINEL_PYTHON=.venv/bin/python bash scripts/sentinel-demo.sh run --profile charter --run-id demo
```

Lệnh trên là cửa nộp. Kịch bản nói 15 phút em giữ trên máy, không đưa vào
git. Demo đủ Kong / duyệt cần
`docs/operations/sentinel-live-acceptance-runbook.md`, chỉ lab loopback.

Không in `infra/.env`, API key, hay dữ liệu người thật.
