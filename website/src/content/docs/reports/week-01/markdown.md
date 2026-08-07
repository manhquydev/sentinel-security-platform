---
title: "Tuần 1 — Quét bảo mật nền — nguồn Markdown"
description: "Nguồn Markdown đầy đủ — đọc / sao chép"
---

Trang HTML: [Tuần 1 — Quét bảo mật nền](/reports/week-01/) · [Tải raw](/raw/reports/week-01.md) · [llms.txt](https://vinsoc.manhquy.id.vn/llms.txt)

Nội dung dưới đây là **toàn bộ file Markdown** trong monorepo (`docs/reports/week-01.md`), không qua bước render HTML.

````markdown
# Project Sentinel — Báo cáo Tuần 1

Monorepo Sentinel (VinUni × VinSOC). Đây là **nền** của đồ án 6 tuần: dựng ứng
dụng web thử nghiệm, chạy công cụ quét bảo mật, và lưu kết quả dạng JSON **đã che
secret**, đọc lại được.

> Nguồn narrative gốc: gói nộp Tuần 1 (2026-07-29, đã gộp vào monorepo).
> Số liệu và digest dưới đây đối chiếu với `scanners/out/*.san.*` **trong repo này**.

## 1. Mục tiêu Tuần 1 em đã làm

Theo yêu cầu đồ án: dựng app thử nghiệm bằng Docker, tạo CI đơn giản, tích hợp ít
nhất một công cụ SAST/DAST, lưu kết quả JSON, và xác định endpoint chính. Em làm
nhiều hơn mức tối thiểu — tích hợp **3** công cụ (Semgrep, Trivy, Nuclei) để có
góc nhìn đầy đủ: mã nguồn, image, và ứng dụng đang chạy thật.

## 2. Kiến trúc

```
Juice Shop (docker, cố ý có lỗ hổng)
        │
        ├── Trivy   → quét image (secret, misconfig)   ─┐
        ├── Nuclei  → quét DAST (app đang chạy thật)    ─┼─► redact-report.sh ─► *.san.json*
        └── Semgrep → quét SAST (mã nguồn)              ─┘        (che secret trước khi lưu)
```

- **Target**: image Juice Shop ghim `@sha256` trong `scanners/image-pins.env`, chạy
  loopback (thường `127.0.0.1:13000`) — không public ra ngoài.
- Mỗi scanner ghim image bằng digest (không dùng tag nổi).
- **Bắt buộc che dữ liệu nhạy cảm trước khi lưu**: chỉ file `.san.json` / `.san.jsonl`
  được lưu/commit.

## 3. Endpoint chính đã ghi nhận (Nuclei / DAST)

| Endpoint | Ghi chú |
|---|---|
| `/` | trang gốc |
| `/metrics` | Prometheus metrics — bị lộ công khai (finding MEDIUM) |
| `/api-docs/swagger.json` | tài liệu API bị lộ |
| `/robots.txt` | |
| `/.well-known/security.txt` | |

## 4. Lỗ hổng / cảnh báo đã phát hiện

| Công cụ | Loại | Target | Số lượng | Digest SHA-256 (file san) |
|---|---|---|---|---|
| Nuclei | DAST | loopback Juice Shop | **21** | `749fcb54f2e963f1ac7cc276f368b82600e9913e09b8d81c79fb4efe59fdb336` |
| Trivy | secret scan | image Juice Shop | **4** | `aced484ea5868a9ac0386873b5b1076ed0f7a8b48a32b909def6fbbe6a8623ba` |
| Semgrep | SAST | source tree | **11** | `4330b7b387e8ff2b92ab9fa78acc71ac4c6f5be0a104891d288d6cf29b45f923` |

**Tổng: 36 cảnh báo**, không đếm trùng. File nằm ở `scanners/out/`:

- `nuclei.san.jsonl`
- `trivy.san.json`
- `semgrep.san.json`

Em cũng từng chạy Trivy đầy đủ (`vuln,secret,misconfig`) — số CVE **không** cộng vào
bảng baseline (CVE DB trôi theo thời điểm quét). Baseline chính thức chỉ secret/misconfig
cho Trivy + Nuclei + Semgrep như trên.

## 5. Cách chạy lại (monorepo)

Yêu cầu: Docker + Docker Compose, `python3`.

```bash
# 1. Juice Shop harness (loopback) — xem scripts/infra compose hiện hành
#    (submission-era: infra/harness/juice-shop.compose.yml)

# 2. Pin images
source scanners/image-pins.env

# 3. Trivy secret scan + redact (ví dụ)
export IMAGE="$JUICE_SHOP_IMAGE"
export TRIVY_SCANNERS="secret"
cd scanners
./run-trivy.sh /tmp/trivy.raw.json
./redact-report.sh trivy /tmp/trivy.raw.json /tmp/trivy.san.json

# 4. Nuclei DAST (ALLOWLIST bắt buộc)
export TARGET_URL="http://127.0.0.1:13000"
export ALLOWLIST="127.0.0.1:13000"
./run-nuclei.sh /tmp/nuclei.raw.jsonl
./redact-report.sh nuclei /tmp/nuclei.raw.jsonl /tmp/nuclei.san.jsonl
```

Raw report (`*.raw.*`) chứa secret thật — **không** commit. Chỉ lưu bản `.san.*`.

## 6. CI

Workflow scanner (nếu bật) chạy Trivy secret/misconfig, che kết quả, upload artifact.
Không đưa secret vào workflow; không nhận trigger từ fork tùy tiện.

## 7. Phạm vi và lựa chọn có chủ đích

Yêu cầu tối thiểu chỉ cần **một** công cụ SAST/DAST. Em đạt và vượt (3 công cụ).
Những phần sau là lựa chọn phạm vi, không phải thiếu:

- **ZAP** chưa là baseline bắt buộc khi đã có Nuclei DAST.
- **WebGoat source** có thể không vendoring trong gói; Semgrep script nhận `TARGET_SRC`.
- **Nuclei template drift**: hai lần quét không nhất thiết trùng số — ghi nhận như đặc
  điểm tool, không che giấu.

Đây là bằng chứng phạm vi **Tuần 1**, không phải hoàn tất cả 6 tuần.
````
