# Research Report: OpenCode-style docs site + weekly reporting in-repo

**Date:** 2026-08-07  
**Scope:** (1) reverse-engineer https://opencode.ai/docs/ IA/stack, (2) propose Cloudflare-deployed docs site for this repo, (3) extract Week 1–2 report voice from submission repos, (4) map Week 3 charter to current code and a report outline.  
**Status:** Research only — no production deploy or full week reports written in this step.

---

## Executive Summary

**OpenCode docs are Astro + Starlight on Cloudflare.** HTML fingerprints (`/_astro/*`, Starlight components, `cf-ray`) prove that stack. The UX pattern to copy is not “pretty CSS”; it is **docs-as-code IA**: left sidebar groups, in-page TOC, Cmd-K search, callouts (Tip/Note), tabbed install snippets, short pages that chain “Install → Configure → Use”.

For Sentinel, the fit is: **keep weekly student reports as Markdown in this monorepo**, render them with **Astro Starlight (static)**, deploy to **Cloudflare Workers/Pages static assets**. That matches OpenCode’s public shape and Cloudflare’s first-class Astro path (Cloudflare acquired Astro in 2026; Workers static assets are the current deploy target).

**Do not use Mintlify** as the default for this capstone: hosted SaaS, less control over offline/lab narrative, and prior project work already treats personal charters carefully. Starlight is OSS, Markdown-first, CF-native, and visually in the same family as OpenCode.

**Reporting model change:** stop separate submission repos (`2026-07-29_…_Week1`, `2026-07-31_…_Week2`). Put public weekly reports under `docs/reports/` (track in git), feed Starlight from that tree, keep full personal charters local-only as already gitignored.

Week 3 charter (Security Analysis Agent) is **largely implemented** in-repo (`agent/week3_analysis.py`, `agent/prompts/charter-system-prompt.md`, tests). The Week 3 **report** should prove that path with the same voice as Week 1–2 READMEs: architecture diagram, measured counts, rerun commands, deliberate scope choices — not marketing.

---

## Research Methodology

| Item | Detail |
|------|--------|
| Sources | Live `opencode.ai/docs` HTML/headers; Mintlify/Astro/CF official docs; Week1/Week2 submission READMEs; local charter `docs/Project_Sentinel_6-week.md`; current `agent/` |
| Date range | Live probes 2026-08-06/07; CF/Astro docs current through 2026 |
| Key terms | Astro Starlight, Cloudflare Workers static assets, docs-as-code, weekly report IA |
| Tool budget | Fingerprint fetch + CF deploy search + local evidence |

---

## Key Findings

### 1. OpenCode docs — structure (what to copy)

Observed from live site:

| Layer | Observation |
|-------|-------------|
| **Hosting** | Cloudflare (`server: cloudflare`, `cf-ray`, cache HIT) |
| **Framework** | Astro (`/_astro/*.js|css`, screenshot under `_astro/`) |
| **Docs theme** | Starlight (component names: `Search`, `TableOfContents`, `MobileTableOfContents`; high hit rate of “starlight”/“astro” tokens in HTML) |
| **Locale cookie** | `oc_locale` — multi-locale ready |
| **Entry page** | Short intro → Prerequisites → Install (tabs: npm/bun/pnpm/yarn/brew…) → Configure → Initialize → Usage recipes → Share → Customize |

**IA pattern (information architecture):**

```text
Top bar: logo | product | Docs | search (Ctrl/Cmd K)
Left nav: hierarchical groups (Intro, Config, Providers, …)
Main: H1 + short lead + sections with anchors
Right: on-page TOC
Body primitives: Tip / Note / tabs / terminal fences / deep links
```

**Content rules OpenCode follows (steal these):**

1. One job per page; deep topics get their own routes.
2. Lead with “what it is” in one paragraph.
3. Commands are copy-pasteable and platform-tabbed.
4. Callouts carry *policy* (commit AGENTS.md, don’t share by default).
5. Screenshots only where they reduce ambiguity (TUI screenshot on intro).

**Do not copy:** full product marketing site shell; agent chat UI. Only the **docs chrome**.

### 2. OpenCode docs — stack decision implication

| Option | Fit for Sentinel weekly reports | CF deploy | Notes |
|--------|----------------------------------|-----------|--------|
| **Astro + Starlight** (OpenCode twin) | **Best** | Official Workers/Pages guides | Markdown/MDX, sidebar config, search, a11y defaults |
| Fumadocs (Next/React) | Good if you want React components | CF Workers possible, heavier | More framework surface than needed |
| Docusaurus | Mature | Static on CF | Heavier React bundle; not OpenCode-like |
| VitePress | Light Vue | Static on CF | Fine, less Starlight IA polish |
| Mintlify | Fast hosted polish | Their cloud (not your CF) | SaaS lock-in; weaker “repo is the product” story |
| Hand-rolled Next + MDX | Max control | CF | YAGNI for a report site |

**Decision (recommended):**  
**Astro 5.x + Starlight, `output: 'static'`, deploy Cloudflare Workers static assets (or Pages if account still uses that UI).** No SSR needed for weekly reports.

Rationale:

- Same family as the reference UX the user pointed at.
- Pure Markdown pipeline = weekly reports stay reviewable in PRs.
- Static = free tier friendly, no secrets on edge, no worker logic for v1.
- Cloudflare docs and Astro’s own guide both first-class this path; Astro is now aligned with Cloudflare’s stack.

### 3. Proposed site architecture (this monorepo)

```text
vinsoc/
├── docs/                          # source of truth (already)
│   ├── reports/                   # NEW — public weekly reports (tracked)
│   │   ├── week-01.md
│   │   ├── week-02.md
│   │   ├── week-03.md
│   │   └── index.md               # index of weeks + how to read evidence
│   ├── product/ …
│   ├── operations/ …
│   └── plans/ …                   # keep plans; optional later nav group
├── website/                       # NEW — Starlight app (only docs site code)
│   ├── package.json
│   ├── astro.config.mjs
│   ├── src/content/docs/          # thin wrappers OR content collections linking ../docs
│   └── public/
└── wrangler.toml / CF project     # deploy config
```

**Content strategy (important):**

| Content | On website? | In git? |
|---------|-------------|---------|
| `docs/reports/week-0N.md` | Yes | Yes |
| `docs/product/*`, ops runbooks | Yes (subset) | Yes |
| Full `Project_Sentinel_6-week.md`, `*_NguyenManhQuy_*` | No | Local-only (already ignored) |
| Raw scan secrets / `.raw.json` | No | No |
| `docs/plans/reports/*` research | Optional “Research” nav | Yes if non-sensitive |

**Nav sketch (Starlight `sidebar`):**

```text
Báo cáo tuần
  · Tuần 1 — baseline scan
  · Tuần 2 — normalize + knowledge
  · Tuần 3 — security analysis agent
Sản phẩm
  · Charter brief
  · As-built architecture
  · Live acceptance (if safe)
Vận hành
  · Workbench (clearly separate product)
```

**Monorepo content options:**

1. **Copy/sync** `docs/reports/*.md` into `website/src/content/docs/` at build (simple).
2. **Content collection** with root outside website (Starlight supports custom paths with care).
3. **Symlink** — fragile on Windows; avoid.

Recommend **(1) small build script** `scripts/website-sync-docs.sh` so `docs/` stays the human edit surface.

### 4. Cloudflare deploy shape (v1)

```text
git push main
  → GitHub Action or CF Git integration
  → npm ci && npm run build (in website/)
  → wrangler deploy / CF Pages publish dist/
  → https://sentinel-docs.<account>.workers.dev  (or custom domain)
```

**Security rails for the site:**

- Static only in v1 — no binding to production keys, DefectDojo, LiteLLM.
- CI must fail if build tries to embed `infra/.env` or raw scanner secrets.
- Optional later: Cloudflare Access in front of mentor-only drafts.
- Do not publish personal full charters (already policy).

**Cost/complexity:** free CF tier sufficient for traffic of mentors + TAs.

### 5. Week 1–2 voice (extract from submission READMEs)

Both READMEs share a **stable skeleton** — rewrite reports must keep it:

| § | Pattern | Week 1 example | Week 2 example |
|---|---------|----------------|----------------|
| Title | `Project Sentinel — Báo cáo Tuần N` | yes | yes |
| Lead | 2–4 câu: repo là gì, tuần này làm gì, quan hệ tuần trước | nền tảng scan | normalize + offline knowledge |
| 1. Mục tiêu | Map **charter requirement → what was done** (sometimes “more than minimum”) | 3 tools not 1 | dual deliverables |
| 2. Kiến trúc | ASCII/box diagram of data flow | Juice→Trivy/Nuclei/Semgrep→redact | san files→aggregate + corpus→search |
| 3. Evidence tables | Counts by tool, severity, endpoints | 36 findings | 36 admitted JSONL rows |
| 4. Deep result | Concrete IDs, sample JSON, digests | endpoints, severities | schema sample + SHA |
| 5. Cách chạy lại | Numbered bash, self-verified | compose + scanners | venv + `run-week2-checks.sh` |
| 6. Packaging / CI | What is in the handoff | workflow artifact | tree of scripts/tests |
| 7. Phạm vi có chủ đích | Explicit non-goals — not “missing work” | no ZAP, WebGoat not vendored | offline not live RAG; separate adapter |

**Tone rules:**

- First person “em” (student → mentor), not corporate “we”.
- Numbers first; every claim points at a path or command.
- Honesty about non-determinism (Nuclei template drift, CVE DB churn).
- Safety discipline: only `.san.*`, no secrets in repo, fail-closed adapters.
- End with boundary: “bằng chứng phạm vi Tuần N, không phải xong cả 6 tuần”.

**Sources for rewrite:**

| Week | Source tree | Primary narrative |
|------|-------------|-------------------|
| 1 | `/home/manhquy/Downloads/2026-07-29_NguyenManhQuy_Week1/README.md` (+ scanners/out if needed) | 36 findings, 3 tools, loopback Juice Shop |
| 2 | `/home/manhquy/Downloads/2026-07-31_NguyenManhQuy_Week2/README.md` | aggregate 36 + offline offline search |
| 3 | charter § Tuần 3 + `agent/week3_analysis.py` + tests | evidence-bound JSONL analysis agent |

### 6. Week 3 charter vs current monorepo

**Charter (Project_Sentinel_6-week.md — Tuần 3):**

- Agent reads scan results + Week 2 knowledge.
- Group duplicates, severity, plain-language explanation, remediation.
- Output JSONL; fields: name, severity, location, evidence, explanation, remediation, confidence.
- Deliverables: working agent, system prompt in repo, auto report, ≥3 test scenarios.
- Done when: report from W1+W2 data; **no invented endpoints/vulns**; stable format; empty/invalid input handled.

**Already in monorepo (evidence):**

| Asset | Role |
|-------|------|
| `agent/week3_analysis.py` | Standalone analysis over Week-2 aggregate; schema `week3-analysis/v1`; fail-closed; no free-form model facts |
| `agent/prompts/charter-system-prompt.md` | System prompt: model may only enrich typed fields; renderer owns prose facts |
| `tests/test_week3_aggregate_analysis.py` | Agent scenarios |
| `tests/test_charter_proposal.py` | Week3 JSONL accepted into proposal path |

**Report Week 3 must emphasize:** evidence-bound design (model cannot invent endpoints) — this is the pedagogical center of Week 3, not “LLM magic”.

### 7. Outlines for the three public reports (next write step)

Paths (tracked, site-facing):

```text
docs/reports/week-01.md
docs/reports/week-02.md
docs/reports/week-03.md
docs/reports/index.md
```

**week-01.md** — rewrite from Week1 submission README into monorepo context:

1. Lead: Tuần 1 trong monorepo Sentinel (không còn repo tách).
2. Mục tiêu map charter 6-week.
3. Kiến trúc scanners + juice-shop harness **as exist in this repo** (`infra/`, `scanners/`).
4. Bảng 36 findings (cite paths under this repo or archived `scanners/out` if present).
5. Rerun via monorepo scripts (prefer current `scripts/` / compose, not only old repo paths).
6. Phạm vi: 3 tools, redact-before-store.

**week-02.md** — rewrite from Week2 README:

1. Lead: normalize + offline knowledge.
2. Adapter `agent/normalize_week1_artifacts.py`, artifacts/manifest digests.
3. Corpus search offline (`rag/` or week2 paths in monorepo).
4. `run-week2-checks` / tests mapping if unified.
5. Scope: not live RAG.

**week-03.md** — new, same voice:

1. Lead: Security Analysis Agent; input = Tuần 1+2 artifacts only.
2. Mục tiêu map charter bullet list 1:1.
3. Kiến trúc: aggregate → `week3_analysis` → JSONL; optional LLM enrichments constrained by system prompt.
4. Schema sample `week3-analysis/v1` + “no invented facts”.
5. ≥3 test scenarios (cite test names).
6. Rerun command(s) against sample aggregate.
7. Phạm vi: analysis report only; gateway/HITL = later weeks.

---

## Comparative Analysis (docs platforms)

| Criterion | Starlight+Astro | Mintlify | Fumadocs | Docusaurus |
|-----------|-----------------|----------|----------|------------|
| Match OpenCode UX | ★★★★★ | ★★★★ | ★★★ | ★★ |
| Cloudflare native | ★★★★★ | ★ | ★★★ | ★★★★ |
| Markdown-in-repo | ★★★★★ | ★★★★ | ★★★★ | ★★★★ |
| Cost for student project | Free self-host | Free tier / SaaS limits | Free | Free |
| Maintenance | Low | Lowest (hosted) | Medium | Medium |
| Vietnamese content | OK | OK | OK | OK |
| YAGNI for reports | Best | Overkill polish | Overkill React | Heavier |

**Rejected for v1:** custom React SPA, SSR-only Workers app, embedding reports inside Workbench UI (product boundary: reports ≠ workbench).

---

## Implementation Recommendations

### Phase A — Content (can ship without site)

1. Create `docs/reports/{index,week-01,week-02,week-03}.md`.
2. Rewrite W1/W2 from submission READMEs; point evidence at monorepo paths.
3. Write W3 from charter + `week3_analysis` + tests; run agent once and attach measured digests.
4. Link from root `README.md` and `docs/README.md` under “Báo cáo tuần”.

### Phase B — Starlight site (OpenCode-like)

```bash
# sketch
npm create astro@latest website -- --template starlight
# configure sidebar → reports + product subset
# static output
# wrangler.toml assets.directory = dist
```

### Phase C — Cloudflare

1. CF project connected to monorepo, root `website/`, build `npm run build`, output `dist`.
2. Optional GitHub Action with `cloudflare/wrangler-action`.
3. Custom domain later.

### Quick start (site only)

```bash
cd website
npm install
npm run dev      # local http://localhost:4321
npm run build
npx wrangler deploy   # or CF dashboard Git deploy
```

### Common pitfalls

| Pitfall | Mitigation |
|---------|------------|
| Publishing personal charters | Keep gitignore; Starlight only mounts `docs/reports` + safe product docs |
| Broken relative links after move | Base path `/` or `/docs/`; link-check in CI |
| Copying secrets into MD | Only cite `.san.*` / redacted samples |
| SSR complexity | Stay static until a real need |
| Mixing Workbench claims into weekly reports | Explicit product boundary section |

---

## Resources & References

### Official / primary

- [OpenCode docs (live)](https://opencode.ai/docs/) — Astro+Starlight+CF fingerprint
- [Astro deploy to Cloudflare](https://docs.astro.build/en/guides/deploy/cloudflare/)
- [Cloudflare: deploy Astro](https://developers.cloudflare.com/pages/framework-guides/deploy-an-astro-site/)
- [Starlight](https://starlight.astro.build/)
- [Cloudflare blog: Astro joins Cloudflare (2026-01)](https://blog.cloudflare.com/astro-joins-cloudflare/)

### Local evidence

- `/home/manhquy/Downloads/2026-07-29_NguyenManhQuy_Week1/README.md`
- `/home/manhquy/Downloads/2026-07-31_NguyenManhQuy_Week2/README.md`
- `docs/Project_Sentinel_6-week.md` § Tuần 3
- `agent/week3_analysis.py`, `agent/prompts/charter-system-prompt.md`
- `.gitignore` personal internship patterns

### Further reading

- Mintlify docs-as-code blog (for contrast, not adoption)
- Starlight i18n if bilingual VI/EN later

---

## Decision record (proposed)

| Decision | Choice |
|----------|--------|
| Docs UX reference | OpenCode (Starlight IA) |
| Framework | Astro + Starlight, static |
| Deploy | Cloudflare Workers static assets (or Pages) |
| Report home | `docs/reports/week-0N.md` in **this** repo |
| Personal charters | Remain local-only, not on site |
| Site package root | `website/` (separate from Workbench) |

---

## Next steps (actionable)

1. **Write** `docs/reports/week-01.md` and `week-02.md` from the two submission READMEs (monorepo path rewrites).
2. **Run** Week 3 agent on aggregate artifacts; capture counts/digests; **write** `docs/reports/week-03.md`.
3. **Scaffold** `website/` Starlight + sync script + sidebar for reports.
4. **Deploy** CF preview URL for mentor review.
5. Optional ADR: `docs/decisions/00xx-public-docs-site-is-starlight-on-cloudflare.md`.

---

## Unresolved questions

1. **Public vs Access-gated?** Mentor-only preview vs fully public GitHub+CF?
2. **Bilingual?** VI-only reports (current voice) or VI+EN tabs?
3. **Domain?** `*.workers.dev` enough for Week 3 handoff, or need custom domain now?
4. **Evidence assets:** copy Week1 `scanners/out/*.san.*` into monorepo if missing, or only narrative + digests from submission repos?
5. **Should completed plans stay off the public nav?** (Recommend yes for v1.)

---

## Appendices

### A. Glossary

| Term | Meaning |
|------|---------|
| Starlight | Astro’s official docs framework |
| docs-as-code | Markdown in git, PR-reviewed, CI-built site |
| Evidence-bound | Report facts only from scanner/knowledge inputs |
| `.san.*` | Redacted scanner artifact safe to store |

### B. OpenCode → Sentinel mapping

| OpenCode page role | Sentinel equivalent |
|--------------------|---------------------|
| Intro | `docs/reports/index.md` |
| Install | “Cách chạy lại” sections in each week |
| Configure | Safety/redact + env notes (no secrets) |
| Usage recipes | Week 1–3 scenarios |
| Customize | Out of scope for reports site |

### C. Fingerprint notes (raw)

- `curl -sI https://opencode.ai/docs/` → `server: cloudflare`, `cf-cache-status: HIT`
- HTML tokens: `astro` ×411, `starlight` ×78, `_astro` assets for Search/TOC
- `llms.txt` at `/docs/llms.txt` → 404 (not Mintlify-style agent index on that path)
