# Red-team: Tuần 3 vs Charter (hostile, charter-only)

**Date:** 2026-08-07  
**Reviewer posture:** hostile red-team (internship capstone VINSOC × VINUNI)  
**Scope authority:** `docs/Project_Sentinel_6-week.md` § Tuần 3 (lines 109–145) only  
**Out of scope:** Week 4–6, monorepo security gold-plating beyond charter, market product claims  

**Evidence read:**

| Surface | Path |
|---|---|
| Charter | `docs/Project_Sentinel_6-week.md:109-145` |
| Week report | `docs/reports/week-03.md` |
| Agent | `agent/week3_analysis.py` |
| System prompt | `agent/prompts/charter-system-prompt.md` |
| Tests | `tests/test_week3_aggregate_analysis.py` |
| Optional | `tests/test_charter_proposal.py` (week3 schema bridge) |

**Verdict overall:** **PARTIAL — pipeline cứng, sản phẩm “báo cáo dễ hiểu” rỗng.**  
Không FAIL toàn phần vì agent chạy được, JSONL ổn định, anti-hallucination mạnh, ≥3 tests.  
Không PASS vì charter Tuần 3 hứa **giải thích đơn giản + đề xuất khắc phục + báo cáo dễ hiểu**, còn delivery hiện tại chủ yếu **lặp lại title scanner bằng câu mẫu tiếng Anh**.

---

## 1. Scorecard (charter criterion → verdict)

### 1.1 Mục tiêu

| # | Criterion (charter) | Verdict | Evidence |
|---|---|---|---|
| M1 | Xây AI Agent đọc kết quả quét và tạo **báo cáo bảo mật dễ hiểu** | **PARTIAL** | Agent + CLI tồn tại (`agent/week3_analysis.py:490-565`, `568-577`). “Dễ hiểu” **không đạt**: `explanation`/`remediation` là template tautology tiếng Anh (`week3_analysis.py:555-556`); `docs/reports/week-03.md:65-67` tự thừa nhận. Mentor đọc JSONL không hiểu được lỗ hổng hơn title scanner. |

### 1.2 Công việc

| # | Criterion (charter) | Verdict | Evidence |
|---|---|---|---|
| C1 | Thiết kế System Prompt cho Agent | **PASS** | `agent/prompts/charter-system-prompt.md:1-13` (versioned, load tại `week3_analysis.py:533-535`; assert trong `tests/test_week3_aggregate_analysis.py:181-186`). |
| C2a | Kết nối Agent với **dữ liệu kết quả quét** | **PASS** | `load_aggregate` + schema `week1-submission/v1` (`week3_analysis.py:334-395`); CLI `--week3-aggregate` / `--week3-manifest`. |
| C2b | Kết nối Agent với **kho tri thức tuần 2** | **PARTIAL** | Có gọi `retrieve_charter` / inject (`week3_analysis.py:413-418`, `503-526`, `536-537`). **Nhưng** nội dung tri thức **không vào** `explanation`/`remediation` (cùng file `:555-556` chỉ dùng `record.title`). Kết nối hạ tầng có; kết nối sản phẩm (báo cáo dùng tri thức) **thiếu**. |
| C3a | Nhóm các cảnh báo trùng nhau | **PASS** | `_groups` gộp theo tool/scanner/title/severity/location/evidence (`week3_analysis.py:398-410`); test gộp 2 nuclei → 1 finding (`test_week3_aggregate_analysis.py:138-147`). |
| C3b | Phân loại mức độ nghiêm trọng | **PARTIAL** | `severity` pass-through từ aggregate (`Week3ReportFinding.severity` ← `record.severity`, `:117`, `:554`). Không có bước agent “phân loại” / chuẩn hóa / ưu tiên. Chấp nhận được nếu policy rõ; charter wording là hành động của Agent — hiện chỉ **giữ nguyên** scanner. |
| C3c | Giải thích lỗ hổng bằng **ngôn ngữ đơn giản** | **FAIL** | Hardcoded: `The scanner reported '{title}' at the listed location.` (`week3_analysis.py:555`). Không giải thích *là gì / vì sao nguy hiểm / ai bị ảnh hưởng*. Không tiếng Việt. Model **bị cấm** viết prose (`charter-system-prompt.md:11-13`; schema chỉ `confidence` + modes, `week3_analysis.py:443-487`). |
| C3d | Đề xuất cách kiểm tra hoặc khắc phục | **PARTIAL** | Hardcoded generic: *Review the scanner evidence and retrieved guidance…* (`week3_analysis.py:556`). Có field `remediation`, không có bước kiểm tra cụ thể hay fix cụ thể theo loại lỗ hổng / tri thức. |
| C4 | Kết quả trả về theo JSONL | **PASS** | `write_jsonl_atomic` + schema `week3-analysis/v1` (`week3_analysis.py:110-126`, `:561-562`). |

### 1.3 Định dạng báo cáo gợi ý

| # | Field gợi ý | Verdict | Evidence |
|---|---|---|---|
| F1 | Tên lỗ hổng | **PASS** | `name` ← title scanner (`:116`, `:553`) |
| F2 | Mức độ nghiêm trọng | **PASS** | `severity` enum Critical…Info (`:117`) |
| F3 | Vị trí | **PASS** | `location` (`:118`, `:554`) |
| F4 | Bằng chứng từ công cụ quét | **PASS** | `scanner_evidence` (`:119`, `:554`) |
| F5 | Giải thích | **PARTIAL** | Field có; **nội dung không đạt** mục “dễ hiểu / đơn giản” (cùng C3c) |
| F6 | Đề xuất khắc phục | **PARTIAL** | Field có; nội dung generic (cùng C3d) |
| F7 | Mức độ tin cậy | **PASS** | `confidence` low/medium/high từ model enrichment (`:122`, `:546-557`) |

**Schema gợi ý: PASS về mặt field completeness; FAIL/PARTIAL về quality của hai field “người đọc”.**

### 1.4 Sản phẩm bàn giao

| # | Deliverable | Verdict | Evidence |
|---|---|---|---|
| D1 | Security Analysis Agent hoạt động được | **PARTIAL** | Offline path với mock retrieve/model: tests xanh (`test_week3_aggregate_analysis.py:138-152`). Live path fail-closed khi thiếu key/tri thức (`week3_analysis.py:530-540`, `week-03.md:92-93`). Week-2 package cũ **không** chạy thẳng — thiếu `aggregate_sha256` (`week-03.md:78-81`). “Hoạt động được” có điều kiện demo. |
| D2 | System Prompt lưu trong kho mã nguồn | **PASS** | `agent/prompts/charter-system-prompt.md` |
| D3 | Một **báo cáo phân tích tự động** | **PARTIAL** | Có narrative `docs/reports/week-03.md` (báo cáo *về* agent, không phải output analysis). Claim “36 dòng offline” (`week-03.md:73-74`) **không** kèm artifact JSONL committed trong repo (không có `week3-report.jsonl` tracked). Mentor không mở được mẫu báo cáo thật. |
| D4 | ≥ ba tình huống kiểm thử cho Agent | **PASS** | Nhiều hơn 3: valid group, strict enrichment schema, empty/malformed/symlink/injection, model invention reject, CLI companions, v.v. (`test_week3_aggregate_analysis.py` full file). Bridge proposal: `test_charter_proposal.py:89-162`. |

### 1.5 Tiêu chí hoàn thành

| # | Completion criterion | Verdict | Evidence |
|---|---|---|---|
| T1 | Agent tạo được báo cáo từ dữ liệu tuần 1 và tuần 2 | **PARTIAL** | Contract đọc aggregate tuần 1 + retrieve tuần 2 (`week3_analysis.py:334-395`, `413-418`). Demo 36 records cần **vá manifest** (`week-03.md:73-81`). Không có artifact end-to-end committed. |
| T2 | Báo cáo không bịa endpoint / lỗ hổng ngoài dữ liệu | **PASS** | Model chỉ `enrichments` (`charter-system-prompt.md:8-13`); reject extra fields (`week3_analysis.py:430-437`, test invention `test_week3_aggregate_analysis.py:348-363`); facts từ typed aggregate only (`:549-560`). **Điểm mạnh nhất của tuần.** |
| T3 | Kết quả có định dạng ổn định | **PASS** | Pydantic `extra=forbid`, schema version cố định, atomic write 0600 (`:110-126`, `:561-562`; test `:148-152`). |
| T4 | Xử lý input trống hoặc không hợp lệ | **PASS** | `empty-input`, `malformed-input`, `invalid-record`, `metadata-mismatch` (`:339-354`, tests `:386-425` và nhiều case khác). Fail **trước** retrieval/model (`assert_stops_before_retrieval`, `:106-122`). |

---

## 2. Scorecard table (tóm tắt)

| Area | Items PASS | PARTIAL | FAIL |
|---|---:|---:|---:|
| Mục tiêu | 0 | 1 (M1) | 0 |
| Công việc | 3 (C1, C2a, C3a, C4*) | 3 (C2b, C3b, C3d) | 1 (C3c) |
| Định dạng gợi ý | 5 fields | 2 fields (F5, F6) | 0 |
| Sản phẩm bàn giao | 2 (D2, D4) | 2 (D1, D3) | 0 |
| Tiêu chí hoàn thành | 3 (T2, T3, T4) | 1 (T1) | 0 |

\*C4 counted under Công việc PASS.

**Blocking for honest “Tuần 3 done” claim:** **C3c FAIL** + **M1 PARTIAL** (product promise) + **D3 PARTIAL** (missing sample analysis artifact).

---

## 3. Gaps (ranked)

### Critical

1. **“Giải thích bằng ngôn ngữ đơn giản” không tồn tại (C3c / M1)**  
   - **Impact:** Mentor/VINUNI đọc report không nhận được phân tích bảo mật — chỉ echo title.  
   - **Root:** Renderer cố ý bỏ prose model; thay bằng template rỗng (`week3_analysis.py:555-556`). Anti-hallucination đúng hướng, nhưng **không thay thế** bằng grounded simple explanation.  
   - **Charter miss:** core of Week 3 goal.

2. **Kho tri thức tuần 2 không đóng góp nội dung báo cáo (C2b)**  
   - **Impact:** Trả tiền latency/N retrievals; report không dùng guidance. Provenance có (`knowledge_provenance`, digests) nhưng người đọc không thấy *học được gì* từ corpus.  
   - **Root:** Knowledge chỉ feed model (rồi bị schema siết còn `confidence`); renderer ignore content.

### High

3. **Thiếu artifact “báo cáo phân tích tự động” có thể nộp (D3 / T1)**  
   - `week-03.md` là status report, không phải analysis product.  
   - Không có `week3-report.jsonl` (hoặc sample redacted) trong tree để mentor chấm.  
   - Claim 36 lines là assertion narrative, không phải file bàn giao.

4. **Remediation generic (C3d)**  
   - “Review … then verify in sandbox” không phải “cách kiểm tra hoặc khắc phục” theo charter.  
   - Không có checklist kiểm tra an toàn (dù chỉ text, không gửi request — Week 4 mới gateway).

5. **End-to-end với gói Tuần 2 cũ gãy contract (D1 / T1)**  
   - `aggregate_sha256` bắt buộc (`AggregateManifest`, `week3_analysis.py:83`).  
   - Honest trong `week-03.md:78-81`, nhưng mentor demo “tuần 1+2 → tuần 3” sẽ fail-closed nếu không reissue manifest.

### Medium

6. **Severity “phân loại” chỉ pass-through (C3b)**  
   - Chấp nhận được nếu ghi rõ policy: *severity is scanner-authored; agent does not re-rate*.  
   - Hiện week report gộp chung “phân mức nghiêm trọng” như đã làm — **overclaim** nhẹ (`week-03.md:15`).

7. **“AI Agent” gần như confidence classifier**  
   - Live model chỉ chọn `low|medium|high` với modes cố định.  
   - Hợp lý về safety; dễ bị mentor hỏi “Agent phân tích gì?” — cần narrative + grounded prose để trả lời.

8. **Báo cáo tiếng Anh template, audience internship Việt**  
   - Charter không bắt buộc tiếng Việt, nhưng “dễ hiểu” trong context VINUNI nghiêng về prose mentor-readable (ít nhất bilingual hoặc VI).

### Low

9. **N+1 retrieval** mỗi grouped finding (`week3_analysis.py:503-504`) — không phải charter gap; chỉ performance smell nếu aggregate lớn.  
10. **Broad `except Exception`** quanh knowledge/model (`:527-528`, `:539-540`) — fail-closed OK; observability kém khi debug demo.

---

## 4. What is already strong (do **not** gold-plate)

Giữ nguyên; không yêu cầu viết lại kiến trúc:

| Strength | Why it matters for charter |
|---|---|
| **No invented findings/endpoints (T2)** | Đúng tiêu chí hoàn thành quan trọng nhất về tin cậy. |
| **Stable JSONL schema + atomic 0600 write (T3, C4)** | Định dạng ổn định, file report an toàn hơn write thô. |
| **Fail-closed empty/invalid/symlink/injection (T4)** | Vượt mức internship tối thiểu; tests dày. |
| **Duplicate grouping (C3a)** | Đúng “nhóm cảnh báo trùng”. |
| **System prompt in-repo (C1, D2)** | Đúng deliverable; trust labels operator vs target-derived. |
| **≥3 (thực tế >>3) tests (D4)** | Vượt “ít nhất ba tình huống”. |
| **Scope discipline** | Không nhét gateway/Week4 vào Week3 (`week-03.md:117-118`) — đúng. |
| **Honesty in week-03.md** | Thừa nhận template EN + contract `aggregate_sha256` — tốt hơn che giấu. |

**Không đòi:** free-form LLM viết facts; live API key trong CI; Kong/gateway; fuzz; UI dashboard; rewrite monorepo security stack.

---

## 5. Concrete improvement plan (ordered, YAGNI)

Dành cho **TTS Nguyễn Mạnh Quý**. Chỉ việc đóng charter gap; dừng khi mentor đọc hiểu report.

### P0 — đóng FAIL “giải thích đơn giản” (1–2 phiên)

1. **Grounded explanation renderer (code-owned, không free-form invent)**  
   - Input: typed fields (`name`, `severity`, `tool`, `scanner`, `location`, `scanner_evidence`) + **top-1 accepted knowledge snippet** đã guard.  
   - Output template (gợi ý VI hoặc VI+EN ngắn), ví dụ:  
     - *Máy quét {tool}/{scanner} báo “{name}” (mức {severity}) tại {location}. Bằng chứng: {evidence[0]}. Theo tài liệu [{provenance_title}]({url}): {≤2 câu từ knowledge đã retrieve}.*  
   - Vẫn **cấm** model thêm location/endpoint/vuln class mới.  
   - File: `agent/week3_analysis.py` (replace lines 555–556 only); optional small helper trong cùng module — **không** framework mới.

2. **Grounded remediation bullets**  
   - 2–4 bullets từ knowledge content (cắt bound) + luôn kết: *chỉ kiểm tra trong sandbox được phép*.  
   - Nếu knowledge empty → fail-closed hiện tại đã đúng; không bịa fix.

3. **Tests hành vi (không phantom)**  
   - Assert explanation chứa title **và** một đoạn/provenance từ mock retrieval (không chỉ schema keys).  
   - Assert model extra field `location` vẫn reject.  
   - Assert empty knowledge vẫn `knowledge-unavailable`.

### P1 — deliverable “báo cáo phân tích tự động” (nửa phiên)

4. **Commit sample artifact** (redacted nếu cần):  
   - `docs/reports/samples/week3-report.sample.jsonl` (3–10 dòng đủ đọc) **hoặc** full 36-line offline export.  
   - Link từ `docs/reports/week-03.md` § bằng chứng.  
   - Ghi command tái tạo + hash manifest sau khi gắn `aggregate_sha256`.

5. **Reissue / document Week-2 manifest**  
   - Script hoặc 3 dòng trong week-03: cách gắn `aggregate_sha256` để demo T1 một lệnh.  
   - Không silent-break old packages without a one-liner fix path.

### P2 — chỉnh claim cho khớp charter (30–60 phút)

6. **Sửa overclaim trong `week-03.md`**  
   - C3b: viết rõ *severity = scanner pass-through, agent không re-rate*.  
   - C2b: sau P0, đổi “tra cứu” → “tra cứu **và nhúng** guidance vào explanation/remediation”.  
   - Bỏ giọng bảng “đã làm” nếu field vẫn template rỗng.

7. **Severity policy one-liner** trong system prompt hoặc report schema comment:  
   - *Do not change scanner severity; confidence is the only model judgment.*  
   - Đủ để PARTIAL→PASS cho C3b mà không build severity engine.

### P3 — optional polish (chỉ nếu còn giờ)

8. Cho model chọn **template_id** enum (vd. `header-misconfig | dependency | sast-rule`) thay vì chỉ confidence — vẫn code render prose.  
9. Batch retrieval (1 query/tool) nếu demo chậm — **không** ưu tiên trước P0–P1.

### Explicit non-goals (YAGNI)

- Không mở model free-text facts.  
- Không xây UI.  
- Không làm Week 4 gateway trong “fix Week 3”.  
- Không thêm abstraction “AnalysisManager”.  
- Không đòi coverage %; tests hiện đã đủ nếu bổ sung 2–3 assert nội dung grounded.

---

## 6. Mapping improvement → charter criterion

| Plan step | Closes |
|---|---|
| P0 grounded explanation | C3c FAIL → PASS; M1 PARTIAL → gần PASS |
| P0 grounded remediation | C3d PARTIAL → PASS |
| P0 use knowledge in prose | C2b PARTIAL → PASS |
| P1 sample JSONL + reissue path | D3, T1 PARTIAL → PASS |
| P2 claim hygiene + severity policy | C3b PARTIAL → PASS |

Sau P0+P1+P2: **có thể claim Tuần 3 hoàn thành charter** mà không phá T2 (no invention).

---

## 7. Fact-check notes (week report vs code)

| Claim in `week-03.md` | Code reality |
|---|---|
| “phần chữ giải thích do renderer viết từ dữ liệu máy quét” | **Đúng kỹ thuật**, nhưng “từ dữ liệu” = **chỉ title** — oversell “giải thích”. |
| “Không bịa endpoint / lỗ hổng” | **Đúng** — enforced. |
| “Nối … kho tri thức” | **Nối retrieval** đúng; **không nối vào câu chữ report**. |
| “36 dòng offline PASS” | Narrative only; **không** verify được từ artifact trong repo tại thời điểm review. |
| “≥3 tình huống kiểm thử” | **Đúng**, vượt mức. |
| Fail-closed empty/invalid | **Đúng**, strong. |

---

## 8. Bottom line for mentor / self-grade

| Question | Answer |
|---|---|
| Có agent + prompt + JSONL + tests? | **Yes** |
| Có anti-hallucination đạt tiêu chí T2? | **Yes — excellent** |
| Có “báo cáo bảo mật dễ hiểu” như mục tiêu tuần? | **No — not yet** |
| Có dùng tri thức tuần 2 để giải thích/khắc phục? | **No — retrieval theater for prose** |
| Nộp được sample analysis report? | **Weak — missing committed product artifact** |
| Ship as “Tuần 3 done”? | **Not honestly — close after P0+P1** |

**Estimated effort to charter-complete:** 1–2 focused days for P0+P1+P2; architecture already supports it.

---

## 9. Reviewer checklist (internal)

- [x] Concurrency: N/A for charter (no shared mutable agent state in scope)  
- [x] Error boundaries: fail-closed paths reviewed  
- [x] API contracts: week3-analysis/v1 vs proposal bridge noted  
- [x] Input validation: empty/invalid covered  
- [x] Auth: N/A Week 3 charter  
- [x] Data leaks: prompt forbids secrets; report 0600 noted as strength  
- [x] Fact-checked week-03 claims against code  

---

Status: DONE  
Summary: Tuần 3 đạt khung kỹ thuật (JSONL ổn định, anti-bịa, tests dày, prompt trong repo) nhưng trượt lõi charter “giải thích đơn giản / báo cáo dễ hiểu” vì explanation–remediation là template rỗng và tri thức tuần 2 không vào prose; thiếu artifact báo cáo phân tích nộp được. P0 grounded renderer + P1 sample JSONL đủ để đóng gap mà không phá no-invention.
