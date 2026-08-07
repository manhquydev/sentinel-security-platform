# Red-team UX/Docs UI — Site Starlight Project Sentinel

**Ngày:** 2026-08-07  
**Vai trò:** Hostile UX/docs UI reviewer (mentor-facing, tiếng Việt)  
**Phạm vi:** `website/`, `docs/reports/`, `scripts/website-sync-docs.sh`, `astro.config.mjs`, `Footer.astro`, `i18n/vi.json`  
**URL mục tiêu:** https://vinsoc.manhquy.id.vn  
**Bằng chứng:** build tĩnh `website/dist/**` + nguồn Markdown (không sửa code trong bước này)

---

## Tóm tắt đánh giá

Site **có khung đúng** (Starlight, `lang=vi`, sidebar 4 mục, TOC, search label VI, footer TTS đầy đủ, không publish charter cá nhân). Nhưng **chưa sẵn sàng “đưa mentor đọc ngay”**: mục lục chính có **link gãy 404**, nội dung vẫn mang **giọng monorepo/kỹ thuật EN–VN**, và landing/index chưa bán được **độ tin cậy đồ án** cho người ngoài repo.

| Mục tiêu site | Kết quả |
|---|---|
| 1. Mentor đọc Tuần 1–3 tiếng Việt rõ | **Một phần** — chrome VI ổn; thân báo cáo lẫn jargon EN + monorepo-speak |
| 2. Footer TTS · VINSOC × VINUNI | **Đạt** — có trên mọi trang build |
| 3. Chrome docs chuyên nghiệp, mobile-ok | **Đạt khung** — Starlight chuẩn; thiếu polish thương hiệu |
| 4. Không public charter đầy đủ | **Đạt** — allowlist chỉ `docs/reports/*` |

**Verdict ship:** **HOLD** cho “mentor demo URL” cho đến khi sửa link gãy + làm sạch mục lục/landing. Nội dung tuần có thể ship sau polish ngôn ngữ.

---

## 1. Findings

### Critical

#### C1 — Mục lục báo cáo link 404 (`./week-0x.md`)

- **Bằng chứng:**  
  - Nguồn: [`docs/reports/index.md`](../../reports/index.md) dòng 12–14:  
    `[week-01.md](./week-01.md)` / `week-02` / `week-03`  
  - Build: `website/dist/reports/index.html` →  
    `<a href="./week-01.md">week-01.md</a>`  
  - Route thật: `/reports/week-01/` (không có `/reports/week-01.md`)  
  - 404 page đã có VI: `Không tìm thấy trang…` (`dist/404.html`) — mentor sẽ **thấy 404** nếu click cột “File”.
- **Tác động:** Đây là **bảng điều hướng chính** trên trang “Báo cáo tuần”. Mentor click đúng chỗ “mục lục” → gãy. Sidebar/pagination vẫn đi được, nhưng bảng trong body thì không.
- **Gốc:** Sync script copy Markdown nguyên văn; **không rewrite** link monorepo → route Starlight.
- **Sửa:** Trong `docs/reports/index.md` đổi sang `/reports/week-01/` (hoặc `./week-01/` nếu resolver ổn), **nhãn** “Tuần 1 — …” thay vì `week-01.md`. Thêm check CI: grep `href=".*\.md"` trong `dist/reports/`.

---

### High

#### H1 — Giọng monorepo / EN–VN lẫn, mentor ngoài repo khó đọc

Chrome (sidebar, search, TOC, pagination) đã Việt hóa tốt (`vi.json`). **Thân trang** thì không:

| Vị trí | Chuỗi vấn đề | Vì sao xấu với mentor |
|---|---|---|
| Landing `index.mdx` | `assignment`, `monorepo`, `loopback` | Từ nội bộ dev; không phải tiếng Việt mentor |
| `reports/index.md` | “lưu ngay trong monorepo…”, “thư mục `website/` (Astro Starlight)” | Meta triển khai, không phải nội dung đồ án |
| week-01/02/03 | `monorepo`, `charter`, `provenance`, `digest`, `fail-closed`, `aggregate`, `submission-era`, `narrative` | Hỗn EN–VN kỹ thuật dày |
| week-03 §3 | `explanation`/`remediation` mẫu **tiếng Anh** | Bằng chứng agent hiện ra EN; mentor VI phải “dịch trong đầu” |
| Heading lặp | `Mục tiêu Tuần X em đã làm` | Giọng học viên ok, nhưng “em” lọt vào **TOC phải** — hơi thân mật trên chrome docs |

- **Bằng chứng tiêu biểu:**  
  - `docs/reports/index.md` L3–4, L20–25  
  - `docs/reports/week-03.md` L55–67 (JSON EN + note “cải tiến sau: bản tiếng Việt”)  
  - Landing: `Văn bản assignment đầy đủ…` (`website/src/content/docs/index.mdx` L39)

- **Sửa hướng:**  
  - Giữ thuật ngữ tool (SAST/DAST, Nuclei…) + gloss ngắn lần đầu.  
  - Đổi meta: monorepo → “kho mã nguồn đồ án”; charter → “khung yêu cầu 6 tuần”; digest → “mã băm”; fail-closed → “dừng an toàn khi dữ liệu sai”.  
  - Landing: “đề bài / kịch bản trình bày” thay “assignment”.

#### H2 — Trang mục lục vẫn là “file repo”, không phải “báo cáo mentor”

- Cột **File** trỏ `week-01.md` (tên file kỹ thuật).  
- Đoạn “Cách đọc bằng chứng” tốt về **kỷ luật bằng chứng**, nhưng liền kề meta “site public / website Starlight”.  
- **Branding lệch:** description/chrome dùng `VINSOC × VINUNI`; thân index/week-01 dùng `VinUni × VinSOC`.

- **Bằng chứng:** `docs/reports/index.md` L7 vs description L3; week-01 L3.

#### H3 — Landing yếu về hierarchy & trust cho mentor

- Hero title: chỉ **“Project Sentinel”** (EN), tagline chen `loopback`.  
- Không nói rõ: **Tuần 1–3 / 6**, ai chấm, môi trường lab-only.  
- Card tuần ổn, nhưng “Juice Shop loopback” / “JSONL” chưa gloss.  
- CTA phụ “Mã nguồn monorepo” — từ monorepo lặp lại; mentor có thể chỉ cần “Xem trên GitHub”.  
- **Không có `og:image`** (grep site config = 0) → share link mentor/Slack nhìn nghèo.

- **Bằng chứng:** `scripts/website-sync-docs.sh` L61–101; `dist/index.html` meta không có og:image.

#### H4 — Sidebar title lệch page title (Tuần 2)

- Sidebar (`astro.config.mjs` L36): `Tuần 2 — Chuẩn hóa & kho tri thức`  
- Page title (sync L50–51): `Tuần 2 — Chuẩn hóa và kho tri thức`  
- Pagination prev trên week-03 cũng dùng label sidebar (`&amp;`).

- **Tác động:** Nhỏ về kỹ thuật, **lớn về cảm giác “chưa rà soát”** với mentor đọc kỹ.

---

### Medium

#### M1 — Footer đạt yêu cầu, còn 1–2 chỗ cứng

- **Đạt:**  
  `TTS Nguyễn Mạnh Quý · Thực tập sinh · VINSOC × VINUNI`  
  + dòng phụ Project Sentinel — có trên index, reports, 404 (`Footer.astro`, `dist/**`).  
- **Ghi chú:**  
  - “TTS” + “Thực tập sinh” hơi lặp (cố ý theo brief — chấp nhận).  
  - “lab loopback” trong footer vẫn EN.  
  - Footer nằm **dưới** pagination; trên mobile scroll dài vẫn thấy — OK.  
  - Không thấy credit “Built with Starlight” chiếm chỗ (custom footer ổn).

#### M2 — i18n chrome tốt; residual EN từ Expressive Code

- `vi.json` đầy đủ: search, theme, TOC (“Trên trang này”, “Tổng quan”), skip link, 404, aside…  
- Còn EN cứng framework:  
  - `title="Copy to clipboard"` / `data-copied="Copied!"`  
  - `sr-only`: `Terminal window`  
- **Bằng chứng:** `dist/reports/week-01/index.html` (nút copy terminal).

#### M3 — Sync allowlist đúng an toàn, nhưng README nói dối một phần

- Script **chỉ** sync `index + week-01..03` + landing; `rm -rf` product/architecture — **đúng** không public charter.  
- `website/README.md` L53: “plus charter brief + as-built” — **không khớp** script hiện tại → maintainer/mentor đọc README sẽ hiểu sai phạm vi site.

#### M4 — Splash không có sidebar; mentor “lạc” nếu không bấm CTA

- `template: splash` → landing không sidebar trái.  
- Chỉ 2 CTA + 3 card. Ổn nếu CTA rõ; hiện card link “tuần 1” lowercase — OK nhưng hierarchy “đồ án 6 tuần” mờ.

#### M5 — A11y cơ bản ổn, chưa audit sâu

- `lang="vi"`, skip link “Chuyển tới nội dung”, search `aria-label="Tìm kiếm"`, theme select sr-only VI.  
- Mobile TOC có.  
- Chưa kiểm tra focus ring / contrast custom footer (`--sl-color-gray-2` trên nền dark — khả năng pass, chưa đo).  
- Favicon mặc định Astro star — không sai a11y, **yếu brand**.

---

### Low

#### L1 — Asset `houston.webp` thừa (scaffold Starlight), không dùng trên landing.

#### L2 — Không logo VINSOC/VINUNI; title bar chỉ text “Sentinel — Báo cáo tuần”.

#### L3 — TOC H2 week-03 có ký tự `≥` (`6. Kiểm thử (≥3 tình huống)`) — đọc được nhưng hơi “kỹ thuật”.

#### L4 — README website tiếng Anh; site public tiếng Việt — chấp nhận cho maintainer, không ảnh hưởng mentor nếu không mở repo.

#### L5 — Live URL: review dựa trên **dist + config `site`**; chưa probe HTTP live trong phiên này. Nếu CF chưa redeploy sau build mới, production có thể lệch dist local.

---

## 2. Checklist mục tiêu (chi tiết)

### Footer

| Kiểm tra | Kết quả |
|---|---|
| Có tên TTS Nguyễn Mạnh Quý | Có |
| Có “Thực tập sinh” | Có |
| Có VINSOC × VINUNI | Có |
| Hiển thị mọi trang docs (kể cả 404) | Có trong dist |
| Dòng project context | Có (nên Việt hóa “loopback”) |

### IA / Sidebar / Search / TOC

| Thành phần | Ngôn ngữ | Ghi chú |
|---|---|---|
| Site title | VI | `Sentinel — Báo cáo tuần` |
| Sidebar group | VI | `Báo cáo tuần` |
| Search placeholder | VI | `Tìm kiếm` |
| TOC | VI | `Trên trang này` / `Tổng quan` |
| Prev/Next | VI | `Trang trước` / `Trang sau` |
| Link nội bộ mục lục | **Gãy** | C1 |
| Tuần 4–6 | Chưa có | Đúng phạm vi v1; nên ghi “đã hoàn thành 3/6” trên landing |

### Charter / privacy

| Kiểm tra | Kết quả |
|---|---|
| Không sync `Project_Sentinel_6-week.md` | Đạt |
| Không sync `*_NguyenManhQuy_*` | Đạt |
| Landing tuyên bố không đăng assignment đầy đủ | Có (cần sửa từ “assignment”) |
| Raw scanner / secrets trên site | Không thấy |

---

## 3. Danh sách cải thiện ưu tiên (tối đa 10)

1. **[P0]** Sửa link mục lục → `/reports/week-01/` …; đổi nhãn cột File → tiêu đề tuần.  
2. **[P0]** Viết lại `docs/reports/index.md` theo audience mentor (bỏ meta monorepo/Starlight; giữ “cách đọc bằng chứng”).  
3. **[P1]** Chuẩn hóa branding: **VINSOC × VINUNI** (hoặc VinSOC × VinUni) **một** kiểu trên chrome + body.  
4. **[P1]** Landing: hero VI rõ “Báo cáo tuần 1–3 · đồ án 6 tuần · lab nội bộ”; gloss loopback; CTA “Mã nguồn trên GitHub”.  
5. **[P1]** Đồng bộ title sidebar Tuần 2 với page title (`và` vs `&`).  
6. **[P1]** Rà EN–VN trong 3 báo cáo: glossary 8–10 từ lặp; heading bỏ “em” khỏi H2 nếu muốn TOC trang trọng hơn (giữ “em” trong đoạn văn được).  
7. **[P2]** Week-3: thêm 1 ví dụ `explanation`/`remediation` **tiếng Việt** (vẫn typed fields) ngay dưới mẫu EN, hoặc chỉ show VI.  
8. **[P2]** Thêm `og:image` đơn giản (tên + VINSOC×VINUNI) cho share mentor.  
9. **[P2]** CI/check: fail build nếu `dist/**` còn `href="*.md"` hoặc path charter cá nhân.  
10. **[P3]** Favicon/logo nhẹ; Việt hóa copy-button nếu Starlight/EC cho phép override; dọn README allowlist cho khớp script.

---

## 4. Quick wins vs polish sau

### Quick wins (≤1 buổi, risk thấp)

| # | Việc | File chính |
|---|---|---|
| Q1 | Sửa 3 link + bảng mục lục mentor-facing | `docs/reports/index.md` |
| Q2 | Align sidebar label Tuần 2 | `website/astro.config.mjs` |
| Q3 | Landing: bỏ “assignment/monorepo”; nói 3/6 tuần | `scripts/website-sync-docs.sh` (khối `index.mdx`) |
| Q4 | Footer: “lab nội bộ (loopback)” | `Footer.astro` |
| Q5 | Branding VINSOC/VINUNI thống nhất trong 4 MD | `docs/reports/*` |
| Q6 | README website: xóa claim “charter brief + as-built” | `website/README.md` |
| Q7 | `npm run build` + click thủ công 3 link mục lục | — |

### Later polish

| # | Việc |
|---|---|
| L1 | Pass ngôn ngữ mentor toàn week-01..03 (glossary + bớt monorepo-speak) |
| L2 | Mẫu output agent tiếng Việt (week-03) |
| L3 | OG image + favicon brand |
| L4 | Override i18n Expressive Code (Copy/Copied) |
| L5 | Progress Tuần 4–6 placeholder khi tới hạn |
| L6 | Probe live https://vinsoc.manhquy.id.vn sau mỗi deploy (smoke 5 URL) |

---

## 5. Điểm giữ được (risk calibration — không phải khen)

1. **Allowlist sync** đúng threat model: không đẩy product/as-built/charter → tránh 404 monorepo-relative hàng loạt (comment script L10–11 đúng hướng).  
2. **`lang=vi` + `vi.json`** đầy đủ hơn nhiều site Starlight “để default EN”.  
3. **Footer credit** đúng brief, render mọi trang kể cả 404.  
4. **Cấu trúc 7 mục** mỗi tuần (mục tiêu → kiến trúc → số liệu → rerun → phạm vi) nhất quán — mentor có thể so tuần.  
5. **Không commit raw scan / secret** được tuyên bố và path chỉ `.san.*` — phù hợp site public.

---

## 6. Ma trận bằng chứng file

| Finding | Path |
|---|---|
| C1 link gãy | `docs/reports/index.md`, `website/dist/reports/index.html` |
| H1 ngôn ngữ | `docs/reports/week-0{1,2,3}.md`, `index.mdx` (sync) |
| H2 mục lục monorepo | `docs/reports/index.md` |
| H3 landing | `scripts/website-sync-docs.sh` L61–101 |
| H4 title lệch | `astro.config.mjs` L36 vs sync L50–51 |
| M1 footer | `website/src/components/Footer.astro` |
| M2 residual EN | `dist/reports/week-01/index.html` (copy btn) |
| M3 README drift | `website/README.md` L53 vs script allowlist |
| Charter not published | `scripts/website-sync-docs.sh` ALLOWLIST; grep content |

---

## 7. Kết luận ship

| Câu hỏi | Trả lời |
|---|---|
| Mentor click “Báo cáo tuần” từ landing có ổn không? | Có (CTA `/reports/`) |
| Mentor click bảng tuần trên mục lục có ổn không? | **Không — 404** |
| Footer đủ chưa? | **Đủ** |
| Tiếng Việt chrome đủ chưa? | **Đủ** |
| Tiếng Việt body đủ “tự nhiên mentor” chưa? | **Chưa** |
| Charter cá nhân lọt public? | **Không thấy** |

**Khuyến nghị:** chặn “mentor-ready” cho đến **P0 (C1 + index rewrite)**. Sau đó mới polish ngôn ngữ tuần và OG.

---

## 8. Ghi chú phương pháp

- Review **read-only**; không sửa source.  
- Ưu tiên audience **mentor VinSOC/VinUni**, không audience contributor monorepo.  
- Hostile posture: polished Starlight shell **không** chứng minh nội dung đọc được.  
- Live HTTP không probe trong phiên; dist + `site` config là nguồn sự thật build.

---

Status: DONE  
Summary: Site Starlight có chrome VI + footer TTS đúng brief và không lọt charter, nhưng mục lục báo cáo link `.md` → 404 và thân trang vẫn monorepo/EN–VN — chưa mentor-ready cho đến khi sửa P0.
