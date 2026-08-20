# Hướng dẫn dùng & test bản deploy production

Cập nhật: 2026-08-20. Dành cho người mở website mà **chưa rõ phải làm gì**.

Có **3 địa chỉ**, mỗi cái một vai trò khác nhau — đừng nhầm:

| URL | Là gì | Cần đăng nhập? |
|---|---|---|
| `https://vinsoc.manhquy.io.vn` (và `.id.vn`) | **Site tài liệu/demo** — báo cáo tuần, kiến trúc, `/llms.txt`. Đây là "mặt tiền" đọc-được-công-khai. | Không |
| `https://app.vinsoc.manhquy.io.vn` | **App live** — dashboard bảo mật DefectDojo, hiện các finding thật quét từ Juice Shop. Nằm sau Cloudflare Access. | **Có** (2 lớp) |
| (local repo) | **Chỗ "test dự án" đúng nghĩa** — chạy lại luồng quét → agent → HITL → gateway → guardrail bằng test/runbook. | Chạy trên máy |

> Điểm hay nhầm: **`app.vinsoc` không phải "toàn bộ dự án để test"** — nó là *một* bề mặt (dashboard finding DefectDojo). Luồng end-to-end được chấm nằm ở repo (mục 3–4 bên dưới).

---

## 1. Vào `app.vinsoc.manhquy.io.vn` (bạn đang kẹt ở đây)

Có **2 lớp đăng nhập nối tiếp**:

### Lớp 1 — Cloudflare Access (cổng)
1. Mở `https://app.vinsoc.manhquy.io.vn`.
2. Cloudflare hiện màn hình đăng nhập, nhập **email được cấp phép**:
   - `manhquydev@gmail.com` hoặc `manhq.id@gmail.com`
3. Chọn **"Send me a code"** → Cloudflare gửi **mã một lần (OTP)** vào email đó.
4. Mở email, copy mã, dán vào → Access cho qua.
   - Muốn thêm email khác được vào? Cloudflare **Zero Trust → Access → Applications → "Sentinel App" → Policies** → thêm email.

### Lớp 2 — Đăng nhập DefectDojo (ứng dụng)
Sau Access, bạn thấy trang login DefectDojo:
- **Username:** `admin`
- **Password:** giá trị `DD_ADMIN_PASSWORD` trong `infra/.env`. Lấy ra bằng (trên máy có repo):
  ```bash
  grep '^DD_ADMIN_PASSWORD=' infra/.env
  ```
  (Không in mật khẩu ra nơi công khai.)

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

Kịch bản trình diễn 10–15 phút, 7 cảnh, lệnh đã verify: [`sentinel-charter-demo-runbook.md`](sentinel-charter-demo-runbook.md).

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
