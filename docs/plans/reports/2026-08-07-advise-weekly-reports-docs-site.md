# Advise: Weekly reports + Starlight docs site

**Date:** 2026-08-07  
**Context:** Prior research `docs/plans/reports/2026-08-07-docs-site-opencode-pattern-and-weekly-reports.md`. User ordered full pipeline: advise → plan --deep → red-team → validate → cook → test → code-review → ship.

## Verdict

Ship **three public Markdown weekly reports in this monorepo** and a **static Astro Starlight site on Cloudflare**. Do not revive separate submission repos. Do not put personal charters on the site. Reuse existing `agent/week3_analysis.py` evidence path for Week 3.

## Reframed problem

Mentors need to **read** Week 1–3 evidence without cloning three repos or hunting private charters. The monorepo already holds scanners, Week-2 adapter, and Week-3 agent; missing piece is **narrative handoff + browseable docs chrome**.

## Exact requirements

1. `docs/reports/week-01.md` — rewrite from Week1 submission README, monorepo paths, voice W1/W2.
2. `docs/reports/week-02.md` — rewrite from Week2 submission README.
3. `docs/reports/week-03.md` — same voice; charter Tuần 3 + live/measured agent evidence.
4. `docs/reports/index.md` — index + how to read evidence.
5. `website/` — Astro Starlight static, sidebar for reports (+ product brief subset).
6. Sync script so `docs/reports` is the edit surface.
7. Cloudflare deploy config (wrangler / pages build notes) — preview URL path documented even if deploy needs account token.
8. Link from `docs/README.md` / root README.

## Non-goals

- Mintlify SaaS
- Publishing `Project_Sentinel_6-week.md` or `*_NguyenManhQuy_*` personal files
- Workbench UI embedding reports
- SSR, auth, i18n v1
- History purge of old personal docs

## Constraints

- No secrets / raw scanner reports on site
- Static only on CF
- YAGNI: no custom design system
- Personal charters stay gitignored

## Work checklist

- [ ] Plan phases for reports + site
- [ ] Write week-01, week-02, week-03, index
- [ ] Scaffold website Starlight + sync
- [ ] Wire docs map
- [ ] Build site; run related tests
- [ ] Review + PR

## Success metrics

- `docs/reports/week-0{1,2,3}.md` exist and cite monorepo paths
- `website` `npm run build` exit 0
- Site pages include report titles
- No personal charter paths published in site content
- PR open on GitHub
