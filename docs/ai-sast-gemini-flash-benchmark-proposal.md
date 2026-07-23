# AI-SAST Benchmark (gemini-2.5-flash) — Phân tích & Phương án đề xuất

> Trạng thái: đề xuất phương án benchmark (chưa code). Ngữ cảnh: Project Sentinel Week 1 (SAST/DAST baseline).
> Ràng buộc đã chốt: target = **WebGoat + OWASP Benchmark** · metric = **Precision-first** · model = **gemini-2.5-flash** · scan offline · output = `findings.jsonl`.

---

## 1. Phát biểu bài toán

Benchmark các AI-native SAST tool: dùng **gemini-2.5-flash** quét target, chuẩn hóa kết quả về **`findings.jsonl`**, đo **time + token + Precision**, xếp hạng **Precision-first**, và thử **nâng performance** bằng prompt/harness/skill.

**2 điều chỉnh bắt buộc (brutal honesty) đã áp vào phương án:**
- **Bỏ metric "nhiều vulns nhất".** Đếm raw count thưởng cho false positive → mâu thuẫn trực tiếp với Precision-first. Metric chính thức = Precision, phụ = Recall + cost.
- **Tách vai 2 target.** WebGoat là target kiểu **DAST/interactive** (khai thác lesson trên app chạy), không có ground-truth SARIF sạch cho SAST → chỉ dùng **định tính + Recall sanity**. **OWASP Benchmark** (Java, sinh ra để chấm SAST, có scorecard TP/FP/TN/FN) → **nguồn số Precision thật, defensible**.

---

## 2. Insight quyết định hướng đi

**Với model yếu như flash, lever Precision mạnh nhất KHÔNG phải chọn tool — mà là kiến trúc detection→validation 2 tầng.**

- Tầng 1 (detection): flash quét rộng, recall cao, **nhiều FP** (bản chất model rẻ).
- Tầng 2 (validation): 1 lần gọi model thứ 2 xác nhận từng candidate (đọc lại code context, phán TP/FP) → **cắt FP = tăng Precision**.

→ **Datadog SAIST làm sẵn tầng 2 này** (separate detection & validation models). Đó là lý do SAIST là engine chính, không phải vì "nhiều sao" mà vì kiến trúc của nó khớp mục tiêu Precision-first. Tầng validation cũng chính là **chỗ để nâng performance** (đổi prompt, đổi model validate, thêm agent-skill verify).

---

## 3. Các phương án đã cân nhắc

| # | Hướng | Ưu | Nhược | Verdict |
|---|-------|-----|-------|---------|
| A | 1 tool CLI đơn (vd Vulnhuntr) | Đơn giản | Vulnhuntr Python-only → **sai với WebGoat/Benchmark (Java)**; không có validation tầng 2 | Loại |
| B | Quét cả 9 tool | "Đầy đủ" | Tốn công, nhiều tool sai ngôn ngữ/không hợp Gemini → nhiễu; so sánh bất công vì output khác nhau | Loại |
| C | **SAIST engine chính + biến thể validation + Metis đối chứng** | Kiến trúc khớp Precision-first; validation = điểm tune; có cross-check chống bias 1-tool | Cần dựng harness đo chung | **Chọn** |
| D | Tự viết harness LLM từ đầu | Kiểm soát tối đa | Vi phạm "study leaders, assemble parts"; tốn thời gian; kém SAIST | Loại |

---

## 4. Phương án đề xuất (C) — thiết kế benchmark

### 4.1 Engine & biến thể

**Engine chính: Datadog SAIST** (native detection/validation split, Tree-sitter, cross-file, SARIF, support Gemini). Chạy 3 biến thể để trả lời "model rẻ có đủ tốt không" và "nâng được bao nhiêu":

| Biến thể | Detection | Validation | Mục đích |
|----------|-----------|------------|----------|
| **V0 Baseline** | flash | flash (default prompt) | Điểm chuẩn công bằng của model rẻ |
| **V1 Tuned-prompt** | flash | flash + prompt giàu CWE context, siết ngưỡng | Nâng Precision *không đổi model* |
| **V2 Harness-boosted** | flash | **Sonnet/Opus 4.8** validate (hoặc agent-skill verify pass) | Trần Precision khi ghép judge mạnh |

**Đối chứng: Arm Metis** (Tree-sitter + code-flow, cách tiếp cận khác) chạy V0 trên cùng target → chống bias "kết luận phụ thuộc 1 tool".

> ⚠️ **Nhãn trung thực bắt buộc:** V2 dùng Opus validate thì kết quả là *"flash detect + Opus judge pipeline"*, KHÔNG phải "flash". Không được report V2 như năng lực của flash. Đây đúng bẫy false-positive/judge trong research Sentinel (Week 10): judge dính "master-key" FP → Precision từ judge là ước lượng, không phải ground truth.

### 4.2 Pipeline dữ liệu (KISS — không vibe code lại)

```
target ──► SAIST/Metis (gemini-2.5-flash) ──► SARIF
                          │                     │
                    LiteLLM proxy          jq convert
                 (token+cost+latency)      SARIF→JSONL (schema chuẩn hóa)
                          │                     │
                          └──────► stats ◄──────┴──► findings.jsonl
                                                          │
                       ┌──────────────────────────────────┤
              OWASP Benchmark scorecard            WebGoat GT map + Opus judge
              (TP/FP/TN/FN → Precision/Recall)     (Recall sanity + demo định tính)
```

- **findings.jsonl**: mọi tool xuất SARIF → `jq` map sang JSONL. Schema chuẩn hóa: `{tool, variant, rule_id, cwe, file, line, severity, message, target}`. ~10 dòng jq, không custom engine.
- **Token/time (giải cho "không có thì vibe code vào")**: route flash **qua LiteLLM proxy** → tự log `prompt_tokens/completion_tokens/cost/latency` mỗi call. Wall-clock = `time`. Không phải chế biến thủ công.
- **Scan offline**: SAST thuần static, không gọi ngoài → hợp ràng buộc "không internet" lúc chạy. Chỉ setup (clone repo, kéo rule/GT) cần mạng.

### 4.3 Chấm điểm (Precision-first)

- **OWASP Benchmark = nguồn số chính.** Dùng chính **scorecard generator** của nó: map finding→expected result theo CWE/test-case → TP/FP/TN/FN → Precision/Recall/F-score/Youden **tự động, deterministic**. Đây là số defensible.
- **WebGoat = phụ.** Không có GT sạch → tự dựng **GT map nhẹ từ lesson→CWE** (WebGoat có tài liệu lesson), dùng cho **Recall sanity + demo**, kèm **Opus 4.8 làm LLM-judge triage FP** — báo rõ là *ước lượng*.
- **Ranking**: sắp theo **Precision trên OWASP Benchmark**, tie-break bằng **cost-per-TP** (đúng tinh thần "model rẻ đủ tốt không").

---

## 5. Rủi ro & giảm thiểu

| Rủi ro | Mức | Giảm thiểu |
|--------|-----|-----------|
| OWASP Benchmark ~2740 test-case × flash → token đắt | Cao | Sample **stratified theo CWE** (vd 20-30%/CWE) cho V1/V2; chạy full chỉ 1 lần cho V0. Cost đo sẵn qua LiteLLM. |
| SAIST đang "preview" → rough, hay lỗi | Trung | Budget thời gian setup; Metis là fallback engine nếu SAIST kẹt. |
| V2 làm Precision đẹp giả tạo (Opus judge) | Cao | Nhãn rõ "flash+judge pipeline"; luôn báo V0 flash-only cạnh bên. |
| WebGoat Precision bị hiểu nhầm là số thật | Trung | Tách bảng: OWASP Benchmark = "hard number", WebGoat = "approximate/demo". |
| Prompt tune mỗi tool → so sánh bất công | Trung | V0 giữ prompt default cho MỌI tool; chỉ V1/V2 tune, và tune áp đồng nhất. |
| flash weak → Recall thấp trên Benchmark | Thấp (chấp nhận) | Đúng mục tiêu benchmark; Recall là metric phụ, không phải fail. |

---

## 6. Success metrics

- **Chính**: Precision trên OWASP Benchmark (V0/V1/V2 + Metis đối chứng).
- **Phụ**: Recall/F-score (Benchmark scorecard); Recall sanity trên WebGoat GT map.
- **Vận hành**: token + cost + latency mỗi run (LiteLLM); wall-clock time; **cost-per-TP**.
- **Câu trả lời cuối cùng**: (a) tool nào Precision cao nhất; (b) flash-only đạt Precision bao nhiêu; (c) tune prompt (V1) và harness/judge (V2) nâng thêm bao nhiêu điểm.

---

## 7. Bước tiếp theo

1. Chốt sample size OWASP Benchmark (full V0 vs stratified V1/V2) — cân token budget.
2. Dựng LiteLLM proxy + jq SARIF→JSONL converter (2 mảnh hạ tầng chung, làm trước).
3. Setup SAIST + Metis, chạy V0 trên cả 2 target.
4. (Tùy chọn) `/plan` bung thành plan thực thi từng bước với acceptance criteria per biến thể.

---

## Câu hỏi chưa giải quyết
- Ngân sách token/cost cho lần chạy full OWASP Benchmark bằng flash là bao nhiêu? (quyết định full vs sample)
- "Nâng performance" muốn giữ trong khung *cùng model flash* (V1) hay cho phép ghép model mạnh làm judge (V2)? — ảnh hưởng cách report Precision.
- WebGoat: chấp nhận GT map thủ công tự dựng, hay bỏ hẳn số Precision trên WebGoat và chỉ để demo định tính?
- Có cần SARIF→JSONL theo schema chuẩn nào có sẵn (vd OCSF, DefectDojo import format) để nối thẳng vào data lake Sentinel Week 1 không?
