# Deployment

## Platform

Cloudflare Workers (static assets + Worker charset). Worker name: `sentinel-docs`.
Config: `website/wrangler.toml`. Chi tiết lệnh: `website/README.md`.

## Production URL

https://vinsoc.manhquy.id.vn

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
