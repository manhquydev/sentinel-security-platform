# Site tài liệu mentor (Astro Starlight)

Chrome kiểu docs (Starlight) cho **báo cáo tuần** Project Sentinel.  
Nội dung soạn trong monorepo tại `docs/reports/`, rồi sync vào Starlight.

**Production:** https://vinsoc.manhquy.id.vn  
**Allowlist sync:** `docs/reports/{index,week-01,week-02,week-03}.md`  
(Product/as-built **không** publish lên site — tránh link monorepo 404.)

## Lệnh

```bash
# Từ root repo — bắt buộc trước build
bash scripts/website-sync-docs.sh

cd website
npm install
npm run dev      # http://localhost:4321
npm run build
npm run preview
```

## Deploy Cloudflare

Chỉ static assets (+ Worker gắn `charset=utf-8` cho text).

```bash
bash scripts/website-sync-docs.sh
cd website
npm ci
npm run build
npx wrangler deploy
```

Cần login Cloudflare trên account sở hữu zone `manhquy.id.vn`.

| URL | Vai trò |
|-----|---------|
| https://vinsoc.manhquy.id.vn | Production (custom domain) |
| https://sentinel-docs.manhquydev.workers.dev | Fallback workers.dev |

`wrangler.toml` bind `vinsoc.manhquy.id.vn`. Sau khi sửa nội dung:

```bash
bash scripts/website-sync-docs.sh && cd website && npm run build && npx wrangler deploy
```

Smoke: `bash scripts/website-smoke-check.sh`

## Bề mặt agent & nguồn Markdown

| URL | Nội dung |
|-----|----------|
| `/llms.txt` | Mục lục llms.txt (HTML + MD view + raw), UTF-8 |
| `/reports/week-0N/markdown/` | Xem nguồn Markdown trên site |
| `/raw/reports/week-0N.md` | File `.md` thô |

Sinh bởi `scripts/website-sync-docs.py`.

## An toàn

- Chỉ allowlist báo cáo tuần.  
- Không sync charter cá nhân / kịch bản riêng.  
- Không nhúng raw scanner secret hay `infra/.env`.  
