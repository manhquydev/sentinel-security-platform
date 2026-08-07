# Sentinel docs site (Astro Starlight)

OpenCode-style documentation chrome for mentor-facing **weekly reports**.
Content is authored under `docs/reports/`, then synced into Starlight.

**Sync allowlist (exact files):** `docs/reports/{index,week-01,week-02,week-03}.md`
only. Product/as-built Markdown stays in the monorepo (not published on the
site) so monorepo-relative links do not 404.

## Commands

```bash
# From repo root — refresh content (required before build)
bash scripts/website-sync-docs.sh

cd website
npm install
npm run dev      # http://localhost:4321
npm run build    # static output in dist/
npm run preview
```

## Cloudflare deploy

Static assets only (no SSR, no secrets).

```bash
bash scripts/website-sync-docs.sh
cd website
npm ci
npm run build
npx wrangler deploy
```

Requires Cloudflare login (`npx wrangler login`) on the account that owns zone
`manhquy.id.vn`.

| URL | Role |
|-----|------|
| https://vinsoc.manhquy.id.vn | **Production** custom domain |
| https://sentinel-docs.manhquydev.workers.dev | workers.dev fallback |

`wrangler.toml` binds `vinsoc.manhquy.id.vn` as a Workers custom domain on the
same zone. Redeploy after content changes:

```bash
bash scripts/website-sync-docs.sh
cd website && npm run build && npx wrangler deploy
```

## Security rails

- Sync allowlist is **only** `docs/reports/**` plus charter brief + as-built.
- Personal charters (`Project_Sentinel_6-week.md`, `*_NguyenManhQuy_*`) stay
  gitignored and are never synced.
- Do not embed raw scanner reports or `infra/.env` values in Markdown.
