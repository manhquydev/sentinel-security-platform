# Project Sentinel: Báo cáo Tuần 1

Tuần 1 em dựng Juice Shop local, chạy quét, rồi lưu JSON đã che secret.

Gói nộp 2026-07-29 đã gộp vào monorepo. Số liệu dưới đây lấy từ
`scanners/out/*.san.*` trong repo này.

## 1. Việc em đã làm

Đề bài cần app Docker, CI đơn giản, ít nhất một SAST/DAST, file JSON, và vài
endpoint chính. Em gắn ba tool (Semgrep, Trivy, Nuclei) để có cả mã nguồn, image
và app đang chạy.

## 2. Luồng quét

```
Juice Shop (docker, lab có lỗ hổng)
        │
        ├── Trivy    → image (secret, misconfig)
        ├── Nuclei   → DAST (app loopback)
        └── Semgrep  → SAST (mã nguồn)
                 │
                 ▼
          redact-report.sh  →  *.san.json / *.san.jsonl
```

- Image Juice Shop ghim `@sha256` trong `scanners/image-pins.env`, thường chạy
  `127.0.0.1:13000` (không public).
- Scanner cũng ghim image bằng digest, không dùng tag nổi.
- Chỉ commit bản `.san.json` / `.san.jsonl`. File raw có secret thì không đưa vào git.

## 3. Endpoint Nuclei ghi nhận

| Endpoint | Ghi chú |
|---|---|
| `/` | trang gốc |
| `/metrics` | metrics public (MEDIUM) |
| `/api-docs/swagger.json` | swagger lộ |
| `/robots.txt` | |
| `/.well-known/security.txt` | |

## 4. Số cảnh báo

| Công cụ | Loại | Target | Số | Digest SHA-256 (file san) |
|---|---|---|---|---|
| Nuclei | DAST | loopback Juice Shop | **21** | `749fcb54f2e963f1ac7cc276f368b82600e9913e09b8d81c79fb4efe59fdb336` |
| Trivy | secret | image Juice Shop | **4** | `aced484ea5868a9ac0386873b5b1076ed0f7a8b48a32b909def6fbbe6a8623ba` |
| Semgrep | SAST | source tree | **11** | `4330b7b387e8ff2b92ab9fa78acc71ac4c6f5be0a104891d288d6cf29b45f923` |

Tổng **36** (không gộp trùng). File ở `scanners/out/`:

- `nuclei.san.jsonl`
- `trivy.san.json`
- `semgrep.san.json`

Em có chạy Trivy thêm chế độ `vuln,secret,misconfig` nhưng **không** cộng CVE vào
bảng baseline (DB CVE đổi theo ngày). Baseline chỉ secret/misconfig + Nuclei + Semgrep
như trên.

## 5. Chạy lại

Cần Docker Compose và `python3`.

```bash
# 1. Juice Shop loopback (compose trong infra/harness/)
# 2. Pin images
source scanners/image-pins.env

# 3. Trivy secret + redact
export IMAGE="$JUICE_SHOP_IMAGE"
export TRIVY_SCANNERS="secret"
cd scanners
./run-trivy.sh /tmp/trivy.raw.json
./redact-report.sh trivy /tmp/trivy.raw.json /tmp/trivy.san.json

# 4. Nuclei (cần ALLOWLIST)
export TARGET_URL="http://127.0.0.1:13000"
export ALLOWLIST="127.0.0.1:13000"
./run-nuclei.sh /tmp/nuclei.raw.jsonl
./redact-report.sh nuclei /tmp/nuclei.raw.jsonl /tmp/nuclei.san.jsonl
```

Bản `*.raw.*` không commit.

## 6. CI

Workflow scanner (nếu bật) chạy Trivy secret/misconfig, redact, upload artifact.
Không nhét secret vào workflow; không nhận trigger từ fork lung tung.

## 7. Việc em chưa đưa vào baseline

Đề bài chỉ bắt buộc một tool; em đã có ba. Vẫn chưa:

- ZAP (đã có Nuclei DAST)
- Vendoring full WebGoat (Semgrep nhận `TARGET_SRC` khi cần)
- Ép số finding Nuclei luôn giống nhau giữa hai lần quét (template có thể lệch)
