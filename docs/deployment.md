# Deployment

Hai bề mặt production: **(A) site tài liệu** (Cloudflare Worker) và **(B) full
Charter topology** (GCP VM). Hướng dẫn dùng/test cho người mới:
[`operations/live-deployment-guide.md`](operations/live-deployment-guide.md).

---

## A. Site tài liệu — Cloudflare Worker

## Platform

Cloudflare Workers (static assets + Worker charset). Worker name: `sentinel-docs`.
Config: `website/wrangler.toml`. Chi tiết lệnh: `website/README.md`.

## Production URL

https://vinsoc.manhquy.io.vn và https://vinsoc.manhquy.id.vn (cùng một Worker;
`.io.vn` là domain dự án mới, `.id.vn` giữ cho báo cáo).

Fallback: https://sentinel-docs.manhquydev.workers.dev

## Deploy Command

```bash
bash scripts/website-sync-docs.sh
cd website
npm ci
npm run build
npx wrangler deploy
```

## Environment Variables

Không cần biến môi trường trên Worker cho site báo cáo tuần. Secret lab (`infra/.env`) không deploy.

## Custom Domain

`vinsoc.manhquy.id.vn` bind trong `website/wrangler.toml` (`custom_domain = true`), zone `manhquy.id.vn`.

## Rollback

```bash
cd website
npx wrangler rollback
```

## Troubleshooting

- Thiếu tuần mới trên site: thêm slug vào `scripts/website-sync-docs.py` (`REPORTS`) và sidebar `website/astro.config.mjs`, rồi sync + deploy.
- Smoke: `WORKER=1 bash scripts/website-smoke-check.sh https://vinsoc.manhquy.id.vn`

---

## B. Full Charter topology — GCP Compute Engine (production, live 2026-08-20)

Kit: [`../infra/gcp/`](../infra/gcp/README.md) (`deploy.sh` + `remote-bootstrap.sh`).

- **VM:** `sentinel-charter`, `e2-standard-4`, zone `asia-southeast1-b`, project
  `project-25e7d128-f340-4d0b-b32`. Chạy nguyên topology compose (Juice Shop +
  Kong + LiteLLM + Langfuse + DefectDojo) — mirror local 1:1. Còn chạy là còn
  tính phí (~$97/tháng); dừng: `deploy.sh teardown`.
- **Bề mặt public:**
  - `https://app.vinsoc.manhquy.io.vn` → Cloudflare Tunnel → DefectDojo (`:8080`),
    chặn trước bằng **Cloudflare Access** (email OTP). Hiện có 5 finding thật
    (Trivy secret/misconfig + Nuclei header) trong Product `juice-shop-harness` /
    Engagement `week1-baseline`.
- **Bảo mật (đã verify độc lập):** mọi app port bind `127.0.0.1` trên VM; **không
  firewall rule nào mở app port** → Juice Shop không ra Internet. SSH chỉ qua IAP
  (`sentinel-allow-iap-ssh` @800 + tag-scoped `sentinel-deny-public-ssh` @900).
  **Không gắn service account** cho VM (`--no-service-account`; Vertex dùng ADC
  file) + systemd `sentinel-metadata-guard` chặn container→metadata (169.254.169.254).
- **Vertex:** LiteLLM dùng ADC file tại `VERTEXAI_ADC_PATH` (copy ngoài git, không
  phải SA của VM).
- **Deploy / vận hành:**
  ```bash
  export PATH="/home/manhquy/project/VinSoc/.tools/google-cloud-sdk/bin:$PATH"
  bash infra/gcp/deploy.sh preflight   # kiểm tra gcloud/auth/billing/API + secret local
  bash infra/gcp/deploy.sh all         # provision → sync → bootstrap → up (1 lệnh)
  bash infra/gcp/deploy.sh status | tunnel | teardown
  ```
- **Lưu ý:** external IP là ephemeral (đổi khi stop/start; domain không ảnh hưởng
  vì tunnel là outbound). Secret (`infra/.env`, ADC) chuyển out-of-band, không vào git.
