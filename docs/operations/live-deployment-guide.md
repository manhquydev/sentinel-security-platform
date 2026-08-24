# Hướng dẫn dùng & test bản deploy production

Cập nhật: 2026-08-20. Dành cho người mở website mà **chưa rõ phải làm gì**.

Có **3 địa chỉ**, mỗi cái một vai trò khác nhau — đừng nhầm:

| URL | Là gì | Cần đăng nhập? |
|---|---|---|
| `https://vinsoc.manhquy.io.vn` (và `.id.vn`) | **Site tài liệu/demo** — báo cáo tuần, kiến trúc, `/llms.txt`. Đây là "mặt tiền" đọc-được-công-khai. | Không |
| `https://app.vinsoc.manhquy.io.vn` | **App live** — dashboard bảo mật DefectDojo, hiện các finding thật quét từ Juice Shop. Nằm sau Cloudflare Access. | **Có** (2 lớp) |
| (local repo) | **Chỗ "test dự án" đúng nghĩa** — chạy lại luồng quét → agent → HITL → gateway → guardrail bằng test/runbook. | Chạy trên máy |

> Điểm hay nhầm: **`app.vinsoc` không phải "toàn bộ dự án để test"** — nó là *một* bề mặt (dashboard finding DefectDojo). Luồng end-to-end được chấm nằm ở repo (mục 3–4 bên dưới).

### `app.vinsoc.manhquy.io.vn` thực sự là gì?

Nó là **DefectDojo** — một nền tảng **quản lý lỗ hổng mã nguồn mở của OWASP** (có sẵn, không phải Sentinel viết ra). Vai trò trong hệ thống:

- Scanner của Sentinel (Trivy/Nuclei/Semgrep) quét Juice Shop → kết quả được **che secret (redact)** → **import vào DefectDojo**. DefectDojo là nơi **lưu và xem/triage** các finding đó.
- Chạy trên VM GCP (bind loopback), đưa ra ngoài qua **Cloudflare Tunnel**, chặn trước bằng **Cloudflare Access**.

Nó **KHÔNG phải**: web UI riêng của Sentinel, không phải giao diện AI agent, không phải màn HITL duyệt request, cũng không phải Juice Shop. "Sản phẩm Sentinel" là **pipeline chạy bằng script** (scanner → chuẩn hóa → agent bám bằng chứng → HITL → Kong gateway → guardrail) xuất **báo cáo JSONL** — không có web UI bespoke. `app.vinsoc` chỉ là bề mặt xem finding.

Vì sao dùng DefectDojo thay vì tự viết UI: đúng phạm vi đồ án (spec cho phép lưu finding vào DB/tool có sẵn), tránh tự dựng frontend, và cho một dashboard finding thật để trình diễn.

---

## 1. Vào `app.vinsoc.manhquy.io.vn` (bạn đang kẹt ở đây)

Có **hai lần đăng nhập**, lần lượt:

### Lần 1 — Cloudflare Access (cổng)

Tài khoản lab (trang `/demo/charter/` có nút copy email, tài khoản, mật khẩu):

1. Mở `https://app.vinsoc.manhquy.io.vn`.
2. Nhập email `vinsoc@manhquy.id.vn`.
3. Bấm gửi mã (OTP).
4. Lấy mã tại hộp thư lab:
   `https://app.manhquy.id.vn/inbox-viewer?email=vinsoc%40manhquy.id.vn`
5. Dán mã → cổng cho qua.

### Lần 2 — DefectDojo (xem lỗ hổng)

Sau cổng, trang login DefectDojo (không phải mã OTP vừa rồi):

- **Username:** `admin`
- **Password:** KHÔNG phải mã OTP của Access. Copy từ trang
  [`/demo/charter/`](https://vinsoc.manhquy.io.vn/demo/charter/).
  `infra/.env` không có trên GitHub nên không lấy mật khẩu từ repo.

- **Nếu muốn đổi sang mật khẩu bạn tự chọn** (đăng nhập cho dễ nhớ), đổi trực tiếp trên VM:
  ```bash
  export PATH="/home/manhquy/project/VinSoc/.tools/google-cloud-sdk/bin:$PATH"
  gcloud --project project-25e7d128-f340-4d0b-b32 compute ssh sentinel-charter --zone asia-southeast1-b --tunnel-through-iap \
    --command "docker exec -i dd-uwsgi python manage.py changepassword admin"
  ```
  (Nhập mật khẩu mới 2 lần; đây là mật khẩu Django của DefectDojo, độc lập với `infra/.env`.)

### Bạn sẽ thấy gì / bấm gì
- Vào **Products → `juice-shop-harness` → Engagement `week1-baseline`**.
- Có **5 finding thật** đã quét từ Juice Shop:
  - 4 từ **Trivy** (secret/misconfig: private key, JWT trong ảnh…)
  - 1 từ **Nuclei** (thiếu HTTP security header)
- Bấm **Findings** để xem chi tiết từng lỗi: mức độ, vị trí, bằng chứng.

Nếu chỉ thấy trang login DefectDojo mà không phải màn Access → DNS/tunnel bình thường; cứ đăng nhập admin như trên.

---

## 2. Xem site tài liệu `vinsoc.manhquy.io.vn`

Không cần đăng nhập. Đáng xem:
- `/reports/` — báo cáo tuần 1–6.
- `/demo/` — demo tương tác (tuần 3).
- `/llms.txt` — bản tóm tắt cho LLM.

---

## 3. "Test dự án" đúng nghĩa — chạy trên máy (bài chấm)

Đây là phần mentor chấm, chạy từ thư mục gốc repo. Không cần cloud.

**Bộ test grader tối thiểu (nhanh, ~vài giây):**
```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest tests/test_week5_labeled_redaction.py tests/test_charter_requests.py tests/test_week5_demo_facade.py -q
.venv/bin/python evaluation/pii-redaction/measure.py
PYTHON=.venv/bin/python bash tests/week5-demo-facade-test.sh
```
Kỳ vọng: **102 passed**, PII **recall 10/10 FP 0/10 PASS**, facade **19 passed**.

**Bộ test đầy đủ (tùy chọn, cần thêm dep):** xem [`full-test-suite.md`](full-test-suite.md) — thêm `requirements-full.txt` rồi chạy các file bị grader-slim bỏ qua (đã verify 140 passed).

**Bằng chứng hoàn thiện tổng hợp:** [`../reports/sentinel-completion-selfassessment.md`](../reports/sentinel-completion-selfassessment.md).

---

## 4. Demo luồng end-to-end (quét → agent → HITL → gateway → guardrail)

Cửa nộp clone-and-run: [`install.md`](install.md) (ba tầng) và
[`charter-demo.md`](charter-demo.md) (7 cảnh). Facade không cần `infra/.env`.
Kịch bản nói 15 phút vẫn local / gitignore.

Luồng đầy đủ (live) là operator-gated (cần `infra/.env` + Vertex ADC + Kong) — mô tả trong [`sentinel-live-acceptance-runbook.md`](sentinel-live-acceptance-runbook.md).

---

## 5. Vận hành VM production (GCP)

Cần `gcloud` đã đăng nhập. Từ thư mục gốc repo:
```bash
export PATH="/home/manhquy/project/VinSoc/.tools/google-cloud-sdk/bin:$PATH"
bash infra/gcp/deploy.sh status     # xem VM + container
bash infra/gcp/deploy.sh tunnel     # mở tunnel về localhost (8080=DefectDojo, 3001=Langfuse, 13000=Juice Shop, 18443=Kong)
bash infra/gcp/deploy.sh teardown   # XOÁ VM để dừng tính phí (thêm --all để xoá cả firewall)
```
- VM `sentinel-charter` (zone `asia-southeast1-b`). **Còn chạy là còn tính phí (~$97/tháng).**
- Juice Shop và mọi service chỉ bind `127.0.0.1` trên VM → **không ra Internet**; chỉ vào được qua tunnel/Access. Chi tiết kiến trúc + bảo mật: [`../../infra/gcp/README.md`](../../infra/gcp/README.md).

---

## 6. Sự cố thường gặp

| Triệu chứng | Nguyên nhân / xử lý |
|---|---|
| `app.vinsoc` không nhận email | Email chưa nằm trong Access policy → thêm ở Zero Trust → Access → Applications. |
| Qua Access nhưng DefectDojo báo sai mật khẩu | Dùng `admin` + `DD_ADMIN_PASSWORD` trong `infra/.env` (không phải mã OTP của Access). |
| DefectDojo trống, không thấy finding | Chưa import; chạy lại pipeline quét→import trên VM (xem `scripts/scan-and-import.sh`). Bản hiện tại đã có 5 finding. |
| `deploy.sh` báo "gcloud not installed" | `export PATH="/home/manhquy/project/VinSoc/.tools/google-cloud-sdk/bin:$PATH"` trước khi chạy. |
| Muốn dừng tốn tiền | `bash infra/gcp/deploy.sh teardown` (hoặc `gcloud compute instances stop sentinel-charter --zone asia-southeast1-b`). |
