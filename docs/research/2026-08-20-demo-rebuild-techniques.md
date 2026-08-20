# Research Report: Kỹ thuật demo phù hợp để làm lại demo Sentinel

Ngày: 2026-08-20. Phạm vi: cách/tech xây demo tương tác ấn tượng cho một công cụ
bảo mật **CLI-first** (Project Sentinel), sống trên **site Astro Starlight tĩnh**,
theme-aware, a11y, dùng **bằng chứng thật**, thời gian capstone. Nguyên tắc:
YAGNI › KISS › DRY. Brutal & ngắn.

## Executive Summary

Bản demo hiện tại "cảm quan xấu, không trải nghiệm" vì ta **tự vẽ một UI custom**
(stepper/CSS) để mô phỏng thứ vốn chạy ở terminal — vừa tốn công, vừa trông ngây,
vừa kém tin. Kết luận nghiên cứu: với **công cụ CLI**, cách demo ấn tượng + tin
cậy + ít công nhất là **quay phiên terminal thật bằng asciinema** rồi nhúng player
(text copy được, tua, sắc nét) — đây đúng "kết quả thật" mentor cần. Phần "wow" thị
giác nên là **một sơ đồ pipeline động** (Svelte Flow — hợp Astro island vì Astro
không mặc định React) làm hero mà lời kể/‌asciinema dẫn qua, thay vì stepper text.

Đừng dùng nền tảng demo SaaS (Navattic/Storylane…) — chúng cho *evaluation demo*
marketing, không hợp site self-hosted học thuật và thêm phụ thuộc. Đừng build lại
thành một web-app React nặng. Ưu tiên: **asciinema (thật) + Svelte Flow hero (đẹp)
+ khung tường thuật "vòng đời sự cố" theo chuẩn SOC dashboard**.

## Methodology
- Nguồn: 5 nhóm tìm kiếm (định dạng demo 2026; asciinema; xyflow React/Svelte
  Flow; UX SOC dashboard 2026; Astro Islands/Starlight).
- Recency: tài liệu 2026 + docs chính chủ (asciinema, xyflow, astro/starlight).

## Key Findings

### 1. Định dạng demo (2026) — chọn theo "job", không phải "đẹp hơn"
- **Interactive clickable demo trên site** = mạnh nhất ở giai đoạn *đánh giá* (tự
  xem, tự nhịp). Best practice: 5–13 bước (1–6 hoàn thành cao nhất), mở bằng modal,
  2–4 "a-ha", visual beacon, nút skip, anchor bằng `data-*` ổn định. (swiftdemos,
  navattic, demosmith, howdygo 2026)
- **Guided tour** (driver.js/shepherd.js) = cho *onboarding trong app thật*, không
  hợp demo tĩnh trên docs.
- **Video** = thắng *phân phối* (social/email), dễ share MP4; nhưng không copy
  được, không tương tác.
- Đội tốt **ghép** nhiều định dạng theo phễu, không chọn một.

### 2. asciinema — "chân ái" cho công cụ CLI
- Ghi phiên terminal → file `.cast` nhẹ; player web cho **copy text, pause, tua,
  tốc độ, sắc nét mọi độ phân giải**, keystroke overlay, marker/auto-pause,
  poster. Nhúng 1 dòng JS (self-host `asciinema-player.min.js` + `.css` + `.cast`).
  (docs.asciinema.org)
- Nơi cấm `<script>`: xuất **GIF (agg)** hoặc **animated SVG (svg-term-cli)** —
  SVG nhẹ + nét hơn GIF nhưng mất copy/tua (chỉ cosmetic).
- Vì Sentinel chạy thật ở CLI (`sentinel-demo.sh`, `scan-and-import.sh`, grader
  ritual), asciinema = bằng chứng **thật, không dàn dựng UI**, độ tin cao nhất.

### 3. Sơ đồ pipeline động — Svelte Flow (xyflow) hợp Astro
- **React Flow / Svelte Flow** (xyflow, MIT) = chuẩn ngành cho node-graph tương
  tác: zoom/pan/drag, custom node/edge, Background/MiniMap/Controls out-of-box.
- Astro **không** mặc định React → **Svelte Flow** (`@xyflow/svelte`) là lựa chọn
  ít-ma-sát hơn cho island (hoặc giữ SVG/CSS thuần nếu muốn zero-dep). Alt:
  JointJS (framework-agnostic, tới 100k node) — thừa cho nhu cầu 7 node.
- Dùng cho hero: 7 node pipeline (scan→agent→proposal→HITL→gateway→guard→PII),
  active node sáng, cạnh "chảy" khi qua bước.

### 4. UX dashboard bảo mật (SOC) 2026 — cái làm demo "chững"
- **Decision-first + progressive disclosure**: 5–7 phần tử/màn, chi tiết ẩn trong
  drill-down. F-pattern, thông tin quan trọng trên-trái.
- **Status trước, biểu đồ sau**: nhãn on-track/blocked, mũi tên, badge — và
  **KHÔNG chỉ dựa màu** (đỏ/xanh phải kèm icon+chữ, sống sót khi greyscale) →
  WCAG 2.2 AA.
- **Dark theme + accent** là chuẩn cảm quan SOC; **skeleton** thay spinner.
- Cảnh báo lặp lại nhiều nguồn: *"đừng thiết kế cho demo, hãy cho người dùng hằng
  ngày"* — với capstone thì demo LÀ mục tiêu, nhưng bài học rút ra: **kể theo
  vòng đời sự cố** (alert → drill-down bằng chứng → playbook/HITL → báo cáo), đừng
  bày màn tĩnh/trống.

### 5. Astro Islands / Starlight — nhúng tương tác đúng cách
- Island: thêm `client:load`/`client:visible` cho component React/Svelte/Vue/
  Solid/Alpine → hydrate riêng, JS tối thiểu. Zero JS mặc định.
- Dùng class **`not-content`** để tránh style markdown Starlight can thiệp
  component; theme qua **CSS custom props**; `astro-embed` cho video (lazy).

## Comparative Analysis

| Hướng | Cảm quan | Trải nghiệm | Tin cậy (thật) | Công | Fit CLI+Astro |
|---|---|---|---|---|---|
| **A. asciinema cast phiên thật** | Cao (terminal xịn) | Trung (tua/copy) | **Rất cao** | **Thấp** | **Xuất sắc** |
| **B. Svelte Flow pipeline động (island)** | **Rất cao** | Cao (zoom/nhấp) | Trung (minh hoạ) | Trung | Tốt |
| C. Walkthrough SOC-narrative (nâng bản hiện tại) | Cao | Cao (toggle/step) | Trung | Trung | Tốt |
| D. Video screencast + narration | Cao | Thấp | Cao | Trung | Khá (phân phối) |
| E. Nền tảng SaaS (Navattic/Storylane) | Cao | Cao | Thấp (clone) | Thấp | **Kém** (phụ thuộc, không self-host) |
| F. Web-app React đầy đủ | Cao | Rất cao | Thấp→gánh nặng | **Rất cao** | Kém (scope creep) |

## Implementation Recommendations

**Chốt (KISS): A làm xương sống + B làm hero + khung narrative của C.** Bỏ E, F.

### Ưu tiên 1 — asciinema cast phiên chạy thật (impact/công cao nhất)
1. Ghi 2–3 cast ngắn (mỗi cái < 90s, tua idle): (a) grader ritual → `102 passed` +
   PII PASS; (b) `scan-and-import` → finding vào DefectDojo; (c) HITL approve/reject
   (`sentinel-charter-approve.py`) cho thấy reject = không gửi.
   ```bash
   asciinema rec -i 2 demo-grader.cast    # -i 2: nén idle > 2s
   # chạy lệnh thật → exit
   ```
2. Nhúng player (self-host, hợp CSP):
   ```html
   <link rel="stylesheet" href="/asciinema-player.css" />
   <div id="cast"></div>
   <script src="/asciinema-player.min.js"></script>
   <script>AsciinemaPlayer.create('/casts/demo-grader.cast',
     document.getElementById('cast'), { theme:'asciinema', idleTimeLimit:2, poster:'npt:0:03' });</script>
   ```
   Đặt `.cast` + bundle vào `website/public/`; bọc trong 1 Astro component có
   class `not-content`. (Không secret trong cast — quay trên fixture/redacted.)

### Ưu tiên 2 — Svelte Flow hero (nếu muốn "wow" thị giác)
- `npm i @xyflow/svelte`; tạo `PipelineFlow.svelte` (7 node + edge), nhúng island
  `<PipelineFlow client:visible />`, class `not-content`, màu theo token Starlight.
- Nhấp node → hiện panel bằng chứng thật (JSONL/finding). Đây thay stepper text.

### Ưu tiên 3 — Khung narrative SOC
- Kể theo vòng đời: **Alert (finding) → Evidence (JSONL) → Decision (HITL) →
  Action (Kong) → Guard (IPI/PII)**. Status badge icon+chữ, dark+accent, drill-down.

### Common Pitfalls
- Tự vẽ UI giả-terminal thay vì quay terminal thật (lỗi hiện tại).
- Màu-đơn cho trạng thái (fail a11y) → luôn icon+chữ.
- Autoplay mặc định / spinner giả "connecting" → mất tin + fail WCAG 2.2.2.
- Cast lộ secret → chỉ quay trên fixture/redacted, xem lại trước khi commit.
- Kéo React vào Astro cho 7 node (dùng Svelte Flow hoặc SVG thuần).

## Resources & References
- Định dạng demo 2026: swiftdemos, raykolabs, demosmith, navattic, howdygo (đã dẫn).
- asciinema: https://docs.asciinema.org/manual/player/ · getting-started · agg · svg-term-cli.
- xyflow: https://reactflow.dev · https://svelteflow.dev · github.com/xyflow/xyflow.
- SOC UX 2026: sanjaydey, cabinco, designmonks (cybersecurity dashboard), ixdf progressive-disclosure.
- Astro/Starlight: docs.astro.build/en/concepts/islands · starlight.astro.build/components/using-components (`not-content`).

## Next Steps (actionable)
1. Chọn combo: **A (asciinema)** bắt buộc; **+B (Svelte Flow)** nếu muốn hero đẹp;
   giữ narrative C.
2. Cài `asciinema` + quay 2–3 cast thật (fixture/redacted), self-host player.
3. (Nếu B) thêm Svelte island Pipeline; (nếu không) nâng SVG/CSS hero hiện có.
4. Thay trang `/demo/charter/`: hero (flow) + tab "Xem chạy thật" (asciinema) +
   narrative SOC. Build → deploy → verify.

## Unresolved Questions
- Có được cài `asciinema` trên máy này không (cần để quay)? Hay quay ở nơi khác?
- Muốn hero là **Svelte Flow** (thêm dep island) hay **SVG/CSS thuần** (zero-dep)?
- Cast quay từ **live VM** (có credential) hay từ **grader ritual + fixture** local
  (an toàn hơn, đủ ấn tượng)?
