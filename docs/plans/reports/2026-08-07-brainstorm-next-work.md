# Brainstorm: Vấn đề hiện tại & công việc tiếp theo

**Date:** 2026-08-07  
**Context:** Docs site đã ship main (`a0a3156`); workbench WIP trong stash; charter 6 tuần còn Tuần 4–6; red-team Tuần 3 = PARTIAL.

---

## Brainstorm contract

### Outcome

Mentor/đồ án có **chuỗi báo cáo tuần 1→N tin cậy** trên monorepo + site, và **charter Tuần 3 đạt đúng “báo cáo dễ hiểu”** (không chỉ schema cứng), trong khi **workbench WIP không bị mất** và môi trường git gọn trên `main`.

### Constraints

- Anti-hallucination: model **không** được invent endpoint/vuln (đã PASS, giữ).
- Site public: không ship secret, không charter cá nhân.
- Workbench vs Charter: hai product, không trộn evidence.
- Stash `wip(workbench)` phải được xử lý có chủ đích (pop branch riêng hoặc drop).
- Nhánh local `feat/benchmark-router-tiers` còn commit chưa merge (Week-1 personal report + router tiers).

### Non-goals (lượt tiếp theo)

- Không xây Mintlify / redesign site lớn.
- Không force-ship workbench B0 chưa test/review.
- Không bắt đầu full Tuần 6 demo cuối khi 3–5 đủ charter.
- Không rewrite lịch sử git.

### Acceptance criteria (cho “vấn đề chính” nếu chọn P0 Tuần 3)

1. `explanation` / `remediation` **tiếng Việt đơn giản**, từ field typed + snippet knowledge (code renderer), vẫn fail-closed.
2. Có sample `week3-report.jsonl` (hoặc path artifacts) commit hoặc link ổn định trên report.
3. Tests tuần 3 vẫn pass; không nới anti-invent.
4. `docs/reports/week-03.md` cập nhật khớp code (không overclaim).
5. Site redeploy nếu report text đổi.

---

## Vấn đề hiện tại (phân lớp)

### P0 — Charter Tuần 3 còn hổng sản phẩm (load-bearing)

| Hiện tượng | Nguyên nhân (đã chứng minh red-team) |
|---|---|
| Mentor đọc JSONL không “dễ hiểu” hơn title scanner | Renderer template EN tautology (`week3_analysis.py` ~555–556) |
| Kho tri thức Tuần 2 “nối” nhưng không vào báo cáo | Retrieve có; prose không dùng content |
| Thiếu artifact báo cáo tự động | Chỉ narrative `week-03.md`, không sample JSONL committed |

**Rủi ro:** Claim “Tuần 3 xong” trước mentor **không đứng**.

### P1 — WIP workbench bị treo ngoài main

- Stash: B0 CodeQL/Semgrep policy, `prepared_deps`, scanner runner, tests.
- Không ship được lúc docs ship (đúng).
- **Rủi ro:** stash quên → mất công / conflict sau.

### P2 — Nhánh local mồ côi

- `feat/benchmark-router-tiers`: commit có personal Week-1 report + benchmark proxy — **không** nên merge mù (chạm policy ignore personal reports).

### P3 — Charter Tuần 4–6 chưa có báo cáo public

- Tuần 4 Gateway, Tuần 5 Guardrails/HITL/PII, Tuần 6 demo — code monorepo có nhiều phần, **chưa** đóng gói mentor-facing như 1–3.

### P4 — Hygiene nhỏ

- Untracked `outputs/` (webwright), `website/.vscode/` — không ship.
- Active plans cũ (AI-SAST / week10) có thể stale so với charter 6-week hiện tại.

---

## Ba hướng tiếp theo

### A — **Đóng Tuần 3 charter-true (khuyến nghị)**

**Làm:** grounded VI explanation/remediation từ typed + knowledge; sample JSONL; sửa week-03.md; test; redeploy site.  
**Ưu:** Đúng gap đỏ red-team; giữ anti-hallucination; mentor-facing ngay.  
**Nhược:** Chưa đụng workbench stash / Tuần 4.

### B — **Cứu & hoàn tất workbench B0 WIP**

**Làm:** `git stash pop` trên branch `feat/workbench-b0-…`, test, review, PR riêng.  
**Ưu:** Không mất WIP; product Workbench tiến.  
**Nhược:** Không giải gap Tuần 3 charter.

### C — **Nhảy Tuần 4 (Gateway + request an toàn) + report week-04**

**Làm:** Map code Kong/tool hiện có → báo cáo + gaps.  
**Ưu:** Tiến timeline 6 tuần.  
**Nhược:** Tuần 3 vẫn PARTIAL — stack gap học thuật.

---

## Quyết định đề xuất

| Ưu tiên | Việc | Lý do |
|---|---|---|
| **1 (now)** | **A — P0 Tuần 3 grounded prose + sample artifact** | Gap charter duy nhất còn FAIL rõ; site/report đã có chỗ gắn |
| **2** | **B — pop stash → branch workbench → PR riêng** | Tránh mất WIP; tách product boundary |
| **3** | Quyết định `feat/benchmark-router-tiers`: archive/drop/port an toàn (không personal report) | Hygiene git |
| **4** | Tuần 4 report khi 3 PASS | Charter sequence |

**Không khuyến nghị:** merge stash vào main không test; claim Tuần 3 xong chỉ vì docs site đẹp.

---

## Work checklist (nếu accept A rồi B)

### Phase A — Tuần 3 charter close

- [ ] Renderer: `explanation`/`remediation` VI từ title/location/evidence + knowledge snippet (deterministic template hoặc bound fields only)
- [ ] Giữ model chỉ confidence/modes
- [ ] Sample aggregate+manifest+report JSONL (path under `docs/reports/artifacts/` hoặc `agent/out/` tracked-safe)
- [ ] Tests cập nhật expectation prose
- [ ] Update `docs/reports/week-03.md` + sync site
- [ ] `website-smoke-check` + redeploy

### Phase B — Workbench stash

- [ ] `git switch -c feat/workbench-b0-prepared-deps`
- [ ] `git stash pop`
- [ ] Run workbench tests
- [ ] PR riêng, không trộn charter reports

### Phase C — Branch hygiene

- [ ] Inspect `feat/benchmark-router-tiers` commits
- [ ] Drop personal Week-1 report commit; keep useful benchmark only **or** delete branch if obsolete

---

## Success metrics

| Metric | Target |
|---|---|
| Red-team C3c (giải thích đơn giản) | PASS (VI, non-tautology, evidence-bound) |
| Sample week3 JSONL | Exists, loadable, 0600/safe content |
| Stash workbench | On named branch or discarded deliberately |
| Local branches | Only intentional WIP; main clean |
| Site | Smoke ALL PASS after report update |

---

## Unresolved questions

1. Mentor demo deadline: ưu tiên **charter Tuần 3** hay **Workbench B0** trước?
2. `feat/benchmark-router-tiers` còn cần không (có personal report risk)?
3. Prose Tuần 3: chỉ VI deterministic template, hay cho phép LLM viết explanation trong schema **đã typed** (vẫn cấm field mới)?
