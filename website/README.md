# Site tài liệu mentor (Astro Starlight)

Chrome kiểu docs (Starlight) cho **báo cáo tuần** Project Sentinel. 
Nội dung soạn trong monorepo tại `docs/reports/`, rồi sync vào Starlight.

**Production:** https://vinsoc.manhquy.id.vn 
**Allowlist sync:** `docs/reports/{index,week-01,week-02,week-03,week-04,week-05,week-06}.md`
**Publish:** đủ tuần 1–6 (`SITE_UNPUBLISHED` trong `scripts/website-sync-docs.py` đang trống).
(Product/as-built **không** publish lên site, tránh link monorepo 404.)

## Lệnh

```bash
# Từ root repo: bắt buộc trước build
bash scripts/website-sync-docs.sh

cd website
npm install
npm run dev # http://localhost:4321
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

## Demo tương tác (static)

| URL | Nội dung |
|-----|----------|
| `/demo/` | Hub demo mentor |
| `/demo/charter/` | Walkthrough Charter (7 cảnh trên site; CLI nằm trong repo) |
| `/demo/week-03/` | Interactive Week 3 pipeline (sample JSONL) |
| `/demo/week-03/*.jsonl` | Fixtures (không wipe bởi sync) |

**Production:** https://vinsoc.manhquy.id.vn/demo/charter/ · https://vinsoc.manhquy.id.vn/demo/week-03/

Demo Tuần 3 gồm: map **4→3** (aggregate → findings), badge code/prose/model, digests thu gọn, fail-closed CLI shape, honesty banner, pin `meta.sha256`.

**UI structure:** demo pages use `<StarlightPage>`, cùng sidebar / header / theme / footer với báo cáo tuần. CSS demo map token `--sl-*` (không tách dark theme riêng).

Fixtures: `public/demo/`, xem `public/demo/README.md`. 
Sync docs **không** xóa `public/demo/` hay `src/pages/demo/`. 
Landing + `llms.txt` demo links được generate trong `scripts/website-sync-docs.py`.

Smoke local: `bash scripts/website-smoke-check.sh http://127.0.0.1:4321` 
Smoke + Worker charset (production): `WORKER=1 bash scripts/website-smoke-check.sh https://vinsoc.manhquy.id.vn`

## An toàn

- Chỉ allowlist báo cáo tuần + demo sample fixtures. 
- Không sync charter cá nhân / kịch bản riêng. 
- Không nhúng raw scanner secret hay `infra/.env`. 
