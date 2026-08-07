# Đánh giá hệ thống site docs Sentinel (sau fix charset / llms.txt)

**Ngày:** 2026-08-07  
**Vai trò:** Staff Engineer — production-readiness / hostile review (read-only)  
**URL production:** https://vinsoc.manhquy.id.vn  
**Phạm vi đọc:**

| Surface | Đường dẫn |
|---|---|
| Worker charset | `website/src/worker.js` |
| Deploy CF | `website/wrangler.toml` |
| Sync nội dung | `scripts/website-sync-docs.py` (+ wrapper `.sh`) |
| Smoke | `scripts/website-smoke-check.sh` |
| Catalog agent | `website/public/llms.txt` |
| Build tĩnh | `website/dist/**`, `astro.config.mjs`, `Footer.astro`, `i18n/vi.json` |
| Live probe | `GET /`, `/llms.txt`, `/reports/`, `/reports/week-03/`, `/raw/reports/week-01.md`, `/sitemap-index.xml`, 404 giả |

**Không sửa code trong bước này.**

---

## Tóm tắt điều hành

| Câu hỏi | Kết luận |
|---|---|
| Fix charset / mojibake `llms.txt` có đúng gốc? | **Có.** Gốc là `Content-Type: text/plain` thiếu `charset=utf-8` → browser decode ISO-8859-1. |
| Fix đã đủ trên production? | **Có (bằng chứng live):** body `llms.txt` / raw MD / HTML hiển thị đúng tiếng Việt (`Báo cáo`, `tuần`, `đồ án`…), không còn mojibake. |
| Còn rủi ro hồi quy? | **Có, vừa phải** — phụ thuộc worker proxy; cache policy quá chặt; smoke chưa bắt header chính xác tuyệt đối. |
| Site “mentor-ready” toàn phần? | **Đạt cho đọc + UTF-8 + link mục lục.** Còn residual UX/i18n/security headers (không chặn ship charset). |

**Verdict charset fix:** **SHIP / giữ** — đúng chỗ, đúng contract, có smoke regression.  
**Verdict site tổng thể:** **SHIP_WITH_FOLLOWUPS** — không có blocker UTF-8; polish mentor + hardening edge còn lại.

---

## 1. Xác nhận fix charset

### 1.1 Chuỗi nhân quả (đúng)

1. `website-sync-docs.py` ghi `public/llms.txt` bằng UTF-8 (`encoding="utf-8"`, `newline="\n"`) — **file nguồn đúng**.
2. Astro copy sang `dist/llms.txt` — body vẫn UTF-8.
3. Cloudflare Workers Static Assets (`env.ASSETS.fetch`) phục vụ `text/plain` **không** (hoặc không ổn định) kèm `charset=utf-8`.
4. Browser / một số client text-only decode Latin-1 → mojibake kiểu `BÃ¡o cÃ¡o`.
5. `worker.js` proxy mọi response text theo đuôi file, **ghi đè** `Content-Type` có `charset=utf-8`.

### 1.2 Cơ chế worker (đúng hướng)

```5:43:website/src/worker.js
const TEXT_EXT = new Map([
	[".txt", "text/plain; charset=utf-8"],
	[".md", "text/markdown; charset=utf-8"],
	// … json, xml, css, js, svg, html …
]);
// …
const response = await env.ASSETS.fetch(request);
const desired = textContentType(url.pathname);
// …
headers.set("Content-Type", desired);
headers.set("Cache-Control", "public, max-age=0, must-revalidate");
```

Điểm đúng:

- Map extension → MIME + charset bao phủ surface agent: `.txt`, `.md`, `.json`, `.xml`, `.svg`, HTML.
- Chỉ override khi nhận diện text; binary (wasm, pagefind index) để ASSETS tự quyết.
- `Cache-Control: max-age=0, must-revalidate` tránh sticky cache charset sai sau deploy — **hợp lý cho `llms.txt` / raw MD**.
- `wrangler.toml` gắn `main = "src/worker.js"` + `[assets] directory = "./dist"` + custom domain — không deploy “static-only bỏ worker”.

### 1.3 Bằng chứng live (2026-08-07)

| URL | Quan sát |
|---|---|
| `/llms.txt` | Tiêu đề `# Project Sentinel — Báo cáo tuần`; có `week-03`; không mojibake |
| `/raw/reports/week-01.md` | Tiếng Việt đầy đủ; digest/bảng intact |
| `/` | Footer **TTS Nguyễn Mạnh Quý · VINSOC × VINUNI**; không còn nhãn “Thực tập sinh” |
| `/reports/` | Bảng link HTML/MD/raw absolute-path Starlight (`/reports/week-0N/`) |
| 404 giả | Trang VI: “Không tìm thấy trang…” + footer TTS |

`web_fetch` trả body đã decode đúng UTF-8. (Công cụ fetch markdown **không** in raw response headers; smoke script là lớp xác minh `Content-Type` chính thức.)

### 1.4 Smoke script — khớp regression

`scripts/website-smoke-check.sh`:

- HTTP 200 + `Content-Type` chứa `charset=utf-8` cho `/llms.txt` và `/raw/reports/*.md`.
- `iconv` validate UTF-8 body.
- Heuristic mojibake: `BÃ¡o|tuáº§n|â€”`.
- Content assert: `Báo cáo tuần`, `week-03`, credit TTS, cấm chuỗi “Thực tập sinh”.
- Phủ HTML tuần 1–3 + markdown views + favicon + sitemap.

**Đánh giá:** đủ để bắt lại bug gốc. Nên chạy sau mỗi `wrangler deploy`.

---

## 2. Rủi ro còn lại của chính fix charset

### Cao (không chặn ship, nên theo dõi)

#### R1 — `Cache-Control: max-age=0` áp cho **mọi** text extension, kể cả asset hash

Worker đặt `must-revalidate` cho `.css`, `.js`, `.html`, `.svg`… chứ không chỉ `.txt`/`.md`.

- **Tác động:** `/_astro/*` (đã content-hash) không được cache dài → TTFB/repeat-visit kém hơn mức static bình thường.
- **Gốc:** một policy “an toàn charset” lan quá rộng.
- **Hướng sửa:** chỉ force `Cache-Control` cho path agent/catalog (`/llms.txt`, `/raw/**`) hoặc extension `.txt`/`.md`; giữ immutable/long-cache cho `/_astro/`.

### Trung bình

#### R2 — Phụ thuộc worker; mất `main` là hồi quy im lặng

Nếu ai đó đổi deploy sang Pages pure-static / bỏ `main`, body UTF-8 vẫn đúng nhưng **header charset** có thể mất → mojibake trở lại trên một số client. Smoke live sẽ bắt, nhưng build local `astro preview` **không** chạy worker logic.

- **Hướng:** document “deploy bắt buộc wrangler + worker”; optional unit test map extension; CI chạy smoke chống production (hoặc preview worker).

#### R3 — `endsWith(ext)` thô

- `.mjs` khớp `.js` trước (cùng MIME → **không bug** hiện tại).
- Path lạ `something.txt.bak` không khớp — OK.
- Pretty URL HTML (`/reports/`) **không** vào map → dựa ASSETS + `<meta charset="utf-8">` trong HTML (ổn cho HTML; **không** phải vector bug `llms.txt`).

#### R4 — Smoke dùng `/tmp/ws-body` dùng chung

Hai tiến trình song song có thể đè file tạm. Rủi ro CI thấp; nên `mktemp` nếu đưa vào pipeline song song.

#### R5 — Smoke không assert MIME subtype cho text

Chỉ `*charset=utf-8*` cho `llms.txt` — nếu server trả `text/html; charset=utf-8` nhầm vẫn PASS. Nên assert `text/plain` (llms) / `text/markdown` hoặc `text/plain` (raw md).

### Thấp

#### R6 — Không có unit test worker

Chỉ smoke live. Map extension đổi sai khó thấy trước deploy.

#### R7 — `compatibility_date = "2026-04-11"` ổn (trước ngày review); không liên quan charset.

---

## 3. Residual toàn site (ngoài charset)

### 3.1 Liên kết (links)

| Trạng thái | Chi tiết |
|---|---|
| **Đã hết C1 red-team cũ** | `docs/reports/index.md` dùng `/reports/week-0N/`, `/reports/week-0N/markdown/`, `/raw/reports/week-0N.md` — **không** còn `./week-01.md` 404. Xác nhận trên live `/reports/`. |
| Allowlist sync | Chỉ `index`, `week-01..03` + landing + raw + llms — đúng rail “không public charter”. |
| Sitemap | `sitemap-0.xml` liệt kê 9 URL HTML (/, reports, markdown views). **Không** gồm `/llms.txt` hay `/raw/**` — chấp nhận được (agent dùng llms; sitemap cho người/SEO HTML). |
| Link monorepo trong thân báo cáo | Path kiểu `agent/week3_analysis.py`, `scanners/out` là **đường dẫn repo**, không phải URL site — mentor không click được từ browser (đúng với “đọc báo cáo + clone repo nếu cần”). |

**Không tìm thấy broken internal HTML route** trong dist index / sidebar / bảng mục lục hiện tại.

### 3.2 i18n / ngôn ngữ

| Lớp | Đánh giá |
|---|---|
| Chrome Starlight | `lang="vi"`, `vi.json` (skip link, search, TOC, 404, theme) — **tốt**. |
| Branding | Lẫn **VINSOC × VINUNI** (chrome/llms/landing) vs **VinUni × VinSOC** (thân `docs/reports/*`) — residual consistency. |
| Jargon monorepo | Vẫn dày: monorepo, charter, digest, fail-closed, loopback, aggregate — mentor ngoài repo phải “dịch trong đầu” (finding red-team H1 vẫn đúng, **không phải regression charset**). |
| Expressive Code EN cứng | `title="Copy to clipboard"`, `data-copied="Copied!"`, `sr-only`: `Terminal window` trong dist — residual a11y/i18n framework. |
| Week-3 sample | `explanation` / `remediation` mẫu **tiếng Anh** (đã note “cải tiến sau”) — intentional technical debt. |

### 3.3 Accessibility

**Ổn mức Starlight default:**

- `lang="vi"`, skip link “Chuyển tới nội dung”.
- Search / theme / sidebar có `aria-label` VI.
- Mobile TOC có.
- 404 tiếng Việt.

**Chưa audit:** contrast custom footer (`--sl-color-gray-2` / white trên dark), focus ring, keyboard full path. Không có blocker rõ từ HTML tĩnh.

### 3.4 Security / trust boundary

| Mục | Đánh giá |
|---|---|
| Secrets trên site | Grep public/raw: chỉ thảo luận “che secret”, **không** nhúng key/token/`infra/.env`. |
| Raw scanner `.raw.*` | Không publish (allowlist + llms ghi chú). |
| Worker surface | Chỉ proxy ASSETS; không SSR, không env secret, không user input → attack surface thấp. |
| Security headers | **Worker không set** CSP / `X-Frame-Options` / `Referrer-Policy` / HSTS. Phụ thuộc zone Cloudflare. Site tĩnh mentor → rủi ro XSS thấp; clickjacking/framing vẫn có thể nếu zone không chặn. |
| `workers_dev = true` | Surface thứ hai `*.workers.dev` song song custom domain — chấp nhận dev, nhớ cùng nội dung. |
| Open redirect / injection | Không có dynamic routing. |

**Không có critical security defect** trên threat model “static weekly reports”.

### 3.5 Performance / SEO / brand

| Mục | Mức | Ghi chú |
|---|---|---|
| Cache asset hash bị tắt (R1) | Medium | Xem §2 |
| `twitter:card=summary_large_image` **không** `og:image` | Low–Med | Share Slack/mail nghèo |
| Favicon Astro star mặc định | Low | Yếu brand VINSOC/VINUNI |
| `houston.webp` scaffold thừa | Low | Dead asset |
| Landing splash không sidebar | Low | CTA chính đủ; hierarchy “đồ án 6 tuần” đã rõ hơn bản red-team cũ (tagline 1–3/6) |

### 3.6 Pipeline nội dung

`website-sync-docs.py` là canonical; shell wrapper chỉ `exec` Python — tốt.

- `prebuild`/`predev` gọi sync → khó build lệch allowlist.
- REPORTS hardcode tuần 1–3: thêm tuần 4–6 **phải** sửa script + sidebar `astro.config.mjs` + smoke paths (dễ quên một chỗ).

### 3.7 So với red-team UI 2026-08-07

| Finding cũ | Hiện trạng |
|---|---|
| C1 link `./week-0x.md` 404 | **Đã sửa** |
| Footer “Thực tập sinh” lặp | **Đã bỏ** (smoke cấm chuỗi) |
| Landing assignment/loopback nặng | **Đã nhẹ hơn**; còn “monorepo” trên landing |
| Sidebar “&” vs “và” Tuần 2 | **Đã thống nhất “và”** |
| README phạm vi sai | README hiện khớp allowlist reports-only |

---

## 4. Ma trận ưu tiên

### Critical

*Không có.* Fix charset đúng; live UTF-8 đúng; không secret leak; link mục lục không 404.

### High

1. **R1** — Thu hẹp `Cache-Control` (chỉ catalog text), trả long-cache cho `/_astro/*`.
2. Chạy / gắn `scripts/website-smoke-check.sh` vào checklist deploy (nếu chưa).

### Medium

3. **R5** — Smoke assert MIME cụ thể (`text/plain` cho llms).
4. Security headers tối thiểu trên worker (hoặc CF Transform Rules): `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `X-Frame-Options`/`frame-ancestors`.
5. Thống nhất branding VINSOC × VINUNI vs VinUni × VinSOC trong `docs/reports/*`.
6. Giảm jargon monorepo trên landing + mục lục (mentor-facing).

### Low

7. `og:image`, favicon brand, dọn `houston.webp`.
8. Việt hóa chuỗi Expressive Code (nếu Starlight/EC cho phép).
9. Week-3 explanation/remediation VI (product debt đã ghi trong báo cáo).
10. `mktemp` trong smoke; unit test map extension worker.
11. Mở rộng smoke assert header live (in `Content-Type` đầy đủ ra log).

---

## 5. Khuyến nghị hành động (theo thứ tự)

1. **Giữ** worker charset fix; coi là contract production cho text surfaces.
2. **Tách** cache policy: charset cho mọi text OK; `max-age=0` chỉ `/llms.txt` + `/raw/**` (và có thể HTML docs nếu muốn instant publish).
3. **Bắt buộc** smoke sau mỗi deploy production.
4. (Tuỳ chọn hardening) security headers tĩnh trên worker.
5. (Tuỳ chọn mentor polish) branding + bớt monorepo-speak + og:image.

---

## 6. Metrics / bằng chứng

| Metric | Kết quả |
|---|---|
| Live `llms.txt` tiếng Việt đúng | **PASS** (probe 2026-08-07) |
| Live raw week-01 UTF-8 | **PASS** |
| Live home TTS credit | **PASS** |
| Live 404 VI | **PASS** |
| Broken `./week-0x.md` trên mục lục | **ABSENT** (đã fix) |
| Secret/token trong `public/` | **Không thấy** |
| Security headers trong worker | **0** (chưa có) |
| `og:image` | **Thiếu** |
| Unit test worker | **0** |
| Smoke script coverage paths | **15+ URL** + 4 content asserts |

> Lưu ý: phiên review **không** chạy được shell smoke local (môi trường agent chỉ có fetch HTTP). Body live đã xác minh; **header `Content-Type` exact** nên re-confirm bằng `bash scripts/website-smoke-check.sh` trên máy maintainer sau deploy.

---

## 7. Kết luận

Fix charset là **corrective change đúng gốc**: không “sửa nội dung”, không fake encoding trong file, mà **khai báo charset tại trust boundary HTTP** nơi browser từng đoán sai. Sync UTF-8 + worker override + smoke mojibake tạo thành vòng phòng thủ hợp lý cho site tiếng Việt phục vụ mentor và agent (`llms.txt`).

Residual quan trọng nhất sau fix không phải mojibake, mà **cache quá chặt cho asset tĩnh**, **phụ thuộc worker**, và **polish mentor/i18n/security headers** đã biết từ red-team trước — không làm hỏng kết luận “charset đã xong”.

---

**Status:** DONE  
**Summary:** Charset fix đúng và đã thấy hiệu lực trên production (llms/raw/HTML tiếng Việt sạch); còn follow-up cache policy, smoke MIME chặt hơn, và residual UX/security không chặn ship.
