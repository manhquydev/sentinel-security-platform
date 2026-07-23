# Quyết định chốt trước khi lập plan đầu tiên (Benchmark AI-SAST)

> Mục đích: khóa các quyết định treo để `/plan` không phải đoán. Định hướng: **chất lượng sản phẩm > tốc độ xây nhanh** (theo yêu cầu người dùng).
> Đọc kèm: `docs/ai-sast-gemini-flash-benchmark-proposal.md`, `docs/project-understanding-benchmark-to-sentinel.md`.

---

## Verdict sẵn sàng
Tầm nhìn + hướng kỹ thuật đã đủ rõ để plan. Sau khi khóa 3 quyết định dưới, **đủ điều kiện chạy `/plan`**. Chỉ còn 1 blocker *lúc execute* (API key), không chặn việc viết plan.

**Môi trường (đã kiểm tra 2026-07-21):** docker/git/jq/python3.12/node/curl ✅; **thiếu**: LLM API key (blocker execute), Java+Maven (chỉ cần cho scorecard gốc — có workaround Python).

---

## Quyết định 1 — Scope plan đầu tiên: **CHỈ Benchmark, nhưng "mối nối" đạt chuẩn production**

**Chốt:** plan đầu = benchmark AI-SAST đơn lẻ (chưa gồm dựng data lake).
**Lý do (chất lượng):** kỷ luật *đo trước, xây sau* — không dựng DefectDojo data lake trên một engine chưa được chứng minh. Số Precision defensible cần được tập trung, không pha loãng vào plumbing.
**Nhưng:** 3 output của benchmark phải làm dạng **tái dùng được cho Week 1**, không vứt đi:
1. schema `findings.jsonl` map thẳng DefectDojo (xem QĐ 2),
2. LiteLLM proxy = gateway thật của Sentinel,
3. bộ convert SARIF→jsonl + scorer tái dùng.
→ Vừa KISS (plan nhỏ) vừa chất lượng (mối nối chuẩn).

---

## Quyết định 2 — Schema `findings.jsonl`: **2 lớp (SARIF = gốc, JSONL chuẩn hóa = view làm việc)**

**Chốt:** KHÔNG chọn 1 format duy nhất. Layer:
- **SARIF = source-of-truth lưu trữ** (lossless, chuẩn công nghiệp, DefectDojo import sẵn, là thứ tool xuất ra).
- **`findings.jsonl` = view chuẩn hóa để chấm điểm/diff** (1 record/dòng), field set cố định căn theo **DefectDojo import model + OCSF Vulnerability Finding**, giữ con trỏ `sarif_ref` về bản gốc.

**Vì sao không chọn đơn lớp:** raw-SARIF-only khó chấm (nested, không per-line); OCSF-full quá nặng cho 1 benchmark; custom-lossy mất dữ liệu → hại data lake sau. 2 lớp = chuẩn + tiện chấm + nối data lake, không mất mát (DRY).

**Field set `findings.jsonl` (chốt):**
```
finding_id      # hash ổn định: tool+rule+file+start_line
run_id, timestamp
tool, tool_version, variant        # V0/V1/V2
model                              # gemini-2.5-flash / judge model nếu có
rule_id, title
cwe (int), owasp (optional)
severity                           # chuẩn hóa: critical|high|medium|low|info
file, start_line, end_line
message, code_snippet (optional)
stage_status                       # candidate | validated | rejected  (bắt 2 tầng detect→validate)
confidence                         # từ tầng validation
target                             # webgoat | owasp-benchmark
target_test_case                   # để map scorecard OWASP Benchmark
sarif_ref                          # trỏ về SARIF result gốc
```
→ Map 1-1 sang DefectDojo generic import; `stage_status` giữ được kiến trúc 2 tầng để phân tích FP.

---

## Quyết định 3 — Ngưỡng Precision + quy mô: **tiered stratified, có khoảng tin cậy**

**Chốt quy mô (chất lượng > tiết kiệm):**
- **V0 baseline → chạy FULL OWASP Benchmark 1 lần** (số định danh, defensible).
- **V1/V2 tuning → sample stratified theo CWE** (lặp rẻ khi tinh chỉnh).
- **Biến thể tốt nhất → xác nhận lại FULL.**
- Báo **Precision theo từng CWE** + tổng hợp, kèm **Wilson confidence interval** (vì là tỉ lệ, 1 con số trần trụi không defensible).

**Chốt ngưỡng "pass" (gắn với hệ quả quyết định, KHÔNG phải số ma thuật):**
| Precision (full, Recall ≥ 0.4) | Kết luận |
|--------------------------------|----------|
| ≥ 0.75 | flash-only **production-viable** → dùng cho Week 1 |
| 0.5 – 0.75 | viable **nếu tune validation** (V1) |
| < 0.5 | flash-only **không đủ** → cần judge mạnh (V2) hoặc đổi engine |
Điều kiện cứng kèm theo: phải trên đường random-guess của Benchmark (**Youden Index > 0**).

**Vì sao vậy:** ngưỡng buộc vào "dùng được cho Sentinel hay không", không phải điểm tùy tiện; per-CWE breakdown cho biết flash mạnh SQLi/yếu crypto → định hình thiết kế agent Sentinel sau này.

---

## Provider LLM (chốt 2026-07-21)
- **Trước mắt = DeepSeek** (`deepseek-chat` cho detection/validation — analog model rẻ). Route qua LiteLLM.
- **Sau = gemini-2.5-flash** khi có key — chỉ đổi config LiteLLM, không sửa code (đúng mục tiêu provider-swappable).
- Plan/scorer phải **provider-agnostic**; ghi rõ `model` trong mỗi record `findings.jsonl` để so sánh cross-provider về sau.

## Còn lại (default an toàn, không blocking plan)
- **Performance-boost:** core = V0 + V1 (cùng model rẻ); **V2 (ghép judge Opus/Sonnet) = stretch**, luôn nhãn "cheap-model+judge", không báo như năng lực model rẻ.
- **"Done" capstone:** coi là capstone học thuật → ưu tiên *chứng minh + đo được*, không cần độ bóng production.
- **Air-gapped:** không (dùng API OpenAI-compatible qua LiteLLM).

---

## Blocker để execute (không chặn viết plan)
1. **LLM API key** — cần `GEMINI_API_KEY` (hoặc key OpenAI-compatible bất kỳ + route qua LiteLLM). Chỉ người dùng cấp được.
2. **Java+Maven** — chỉ cần nếu chạy scorecard Java gốc của OWASP Benchmark; plan sẽ có bước "cài JDK (tùy chọn)" + fallback scorer Python từ `expectedresults.csv`.

## Câu hỏi chưa giải quyết
- Sẽ cấp key Gemini trực tiếp hay key OpenAI-compatible khác (DeepSeek...) để LiteLLM route? — ảnh hưởng cấu hình proxy.
- Chấp nhận cài JDK để dùng scorecard gốc, hay ưu tiên scorer Python thuần (đỡ phụ thuộc)?
