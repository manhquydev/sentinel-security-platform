# Hiểu sâu dự án: từ viên gạch Benchmark tới toàn cảnh Sentinel

> Mục đích: làm rõ **bản chất** dự án cần triển khai, ở mọi khía cạnh (What/Why · How · Metric · Rủi ro), và **sợi dây nối** giữa task benchmark trước mắt và Project Sentinel toàn cục.
> Đọc kèm: `docs/project-sentinel-architecture-proposal.md` (kiến trúc) + `docs/ai-sast-gemini-flash-benchmark-proposal.md` (phương án benchmark).

---

## 0. Mô hình tư duy: quan hệ giữa 2 "dự án"

Đây KHÔNG phải 2 việc rời. Là quan hệ **zoom**:

```
PROJECT SENTINEL (toà nhà 12 tuần)
   └─ Phase 1 · Week 1: SAST/DAST baseline + data lake
         └─ Task benchmark AI-SAST  ← "viên gạch đầu tiên" bạn triển khai NGAY
               (gemini-2.5-flash quét WebGoat/OWASP Benchmark → findings.jsonl + Precision)
```

Viên gạch benchmark không phải bài tập vứt đi. Nó **gieo mầm 3 năng lực lõi** mà cả Sentinel dùng lại về sau (xem §3). Hiểu benchmark = hiểu Sentinel ở dạng thu nhỏ, chạy được, đo được.

Một câu tóm tắt mỗi dự án:
- **Benchmark** = *một thí nghiệm đo lường*: chạy tool AI-SAST rẻ trên target có đáp án sẵn, ra bảng điểm Precision. Sản phẩm là **con số + `findings.jsonl`**, không phải phần mềm.
- **Sentinel** = *một hệ multi-agent tự vận hành*: AI vừa tự tấn công web-app, vừa tự bảo vệ mình khỏi bị AI khác thao túng. Sản phẩm là **hệ thống + PRD/ROI**.

---

## 1. VIÊN GẠCH — Task Benchmark AI-SAST

### 1.1 What/Why — bản chất & mục tiêu
- **Là gì:** một *phép đo*, không phải sản phẩm. Cho tool AI-SAST đọc source code target → nó báo danh sách lỗ hổng → so với đáp án đã biết → tính đúng/sai.
- **Vì sao tồn tại (3 lý do thật):**
  1. **Chọn engine cho Week 1.** Sentinel cần 1 SAST engine nạp vào data lake DefectDojo. Không thể chọn bằng cảm tính — phải có số Precision.
  2. **Chứng minh model rẻ có đủ tốt không.** Nếu flash đạt Precision chấp nhận được → cả Sentinel tiết kiệm cost khổng lồ (đây là đòn bẩy tài chính cho toàn dự án).
  3. **Rèn "cơ evaluation".** Kỹ năng chấm điểm chính xác (Precision/ground truth) là thứ Sentinel cần lặp lại ở Week 5 và Week 10.
- **Output cuối trông như thế nào:** 1 file `findings.jsonl` (mỗi dòng 1 finding chuẩn hóa) + 1 bảng thống kê `{tool, variant → time, token, cost, Precision, Recall}`.
- **Ai dùng:** chính team, để ra quyết định "dùng SAIST hay Metis cho Week 1" và "flash-only đủ chưa hay phải ghép judge".

### 1.2 How — luồng kỹ thuật
```
target (WebGoat / OWASP Benchmark)
   → SAIST (flash: detect → validate 2 tầng)  → SARIF
        │ mọi call LLM qua LiteLLM proxy (log token/cost/latency)
        ↓
   jq: SARIF → findings.jsonl (schema chuẩn)
        ↓
   chấm: OWASP Benchmark scorecard (đáp án sẵn) → Precision/Recall
         WebGoat: GT map thủ công + Opus judge → ước lượng
```
Lõi kỹ thuật = **kiến trúc detection→validation 2 tầng** (flash quét rộng nhiều FP → 1 pass validate cắt FP → tăng Precision). Đây là lý do chọn SAIST và là chỗ để "nâng performance".

### 1.3 Metric — đo thế nào là thành công
- **Chính: Precision** (đúng/tổng báo cáo) trên OWASP Benchmark — *con số cứng, deterministic*.
- **Phụ:** Recall, F-score, **cost-per-TP** (mỗi lỗ hổng đúng tốn bao nhiêu $).
- **WebGoat:** chỉ Recall sanity + demo, số Precision là *ước lượng* (nói rõ).

### 1.4 Rủi ro & ranh giới
- **Bẫy "nhiều vulns nhất"** → thưởng FP, ngược Precision-first. Đã bỏ.
- **WebGoat là DAST-target, tool là SAST** → không có ground-truth sạch. OWASP Benchmark gánh số thật.
- **Judge mạnh (Opus) làm Precision đẹp giả** → phải nhãn "flash+judge", không phải "flash".
- **Ranh giới KHÔNG làm:** không tự viết SAST engine; không benchmark cả 9 tool; không dùng internet lúc scan.

---

## 2. TOÀN CẢNH — Project Sentinel

### 2.1 What/Why — bản chất & mục tiêu
- **Là gì:** hệ **multi-agent** tự động hoá pentest web-app, có luận điểm kép: **AI là vũ khí** (tự recon→fuzz→exploit) **và là mục tiêu** (phải chống prompt injection/data poisoning tấn công chính nó).
- **Vì sao tồn tại / khác biệt:** XBOW/Strix đã làm offense giỏi rồi. Giá trị Sentinel = **tích hợp offense + tự-phòng-thủ (Security-FOR-AI) + LLMOps** — khoảng trống chỉ CAI chạm tới. **Phase 3 mới là luận điểm, không phải Phase 2.**
- **Output cuối:** hệ thống chạy được qua 4 phase + PRD + business case ROI so với pentest thủ công, demo cho stakeholder non-tech.
- **Ai dùng:** đội security/SOC (chạy pentest liên tục trên staging), và ban lãnh đạo (đọc ROI).

### 2.2 How — luồng kỹ thuật (tóm; chi tiết ở doc kiến trúc)
```
Staging app → API Gateway ← scoped token ← Agent IAM
   SAST/DAST → Data Lake (DefectDojo) → Threat-Intel RAG (GraphRAG)
        → Multi-Agent Syndicate (Supervisor · Recon · Fuzz · Exploit)
              qua Guardrails + PII redaction + HITL gate
        → Eval (LLM-judge + FP rate) → vLLM prod + FinOps
```
Xương sống: **LiteLLM** (mọi LLM OpenAI-compatible, 1 điểm kiểm soát cost/PII/guardrail) + **LangGraph** (orchestration + HITL `interrupt()`).

### 2.3 Metric — đo thế nào là thành công
- **Offense:** % sub-task hoàn thành; số vuln thật trên staging.
- **Defense (thesis):** **ASR** prompt injection trước/sau guardrail; % state-changing action bị HITL chặn đúng; % PII được redact.
- **LLMOps:** **false-positive rate** (headline — chưa ai report), cost-per-run, latency.
- **Business:** ROI (speed × cost) vs pentest thủ công.

### 2.4 Rủi ro & ranh giới
- **Agent IAM (MCP/A2A) chưa chín** → fallback Kong scoped-key.
- **Prompt injection provably-unsolved** → guardrail là giảm rủi ro xác suất, KHÔNG hứa 0%.
- **GraphRAG đắt + có poisoning surface mới.**
- **Token cost bùng nổ** → đo từ ngày đầu.
- **Ranh giới:** chỉ test staging của chính team; HITL cho mọi hành động state-changing; không đấu engineering với XBOW/Strix mà lắp ghép OSS.

---

## 3. SỢI DÂY NỐI — vì sao viên gạch không vứt đi

Benchmark gieo đúng **3 năng lực lõi** Sentinel tái dùng. Đây là phần "hiểu sâu" quan trọng nhất:

| Thứ sinh ra ở Benchmark | Tái dùng ở Sentinel | Ý nghĩa |
|--------------------------|---------------------|---------|
| **`findings.jsonl` schema chuẩn hóa** | → nạp thẳng vào **DefectDojo data lake (Week 1)** → nuôi **Threat-Intel RAG (Week 3)** → **Recon agent (Week 4)** đọc | Output benchmark là **node đầu tiên của cả pipeline dữ liệu** Sentinel. Chọn schema tốt bây giờ = đỡ refactor sau. |
| **LiteLLM proxy đo token/cost** | → chính là **LLM Gateway xương sống** của Sentinel | "Cost discipline từ ngày đầu" (bài học Week 11) bắt đầu ngay ở viên gạch. |
| **Kỷ luật deterministic scoring** (Precision từ đáp án sẵn, không tin LLM đếm) | → trả lời trực tiếp mục tiêu **"no false positive" (Week 10)**: LLM *tìm*, validator *xác nhận* | Đây là insight của XBOW. Rèn ở benchmark = giải sẵn bài khó nhất của Phase 4. |

**Pattern lặp lại 3 lần trong Sentinel** (nên hiểu 1 lần cho kỹ): *target có đáp án → chạy agent → chấm bằng oracle deterministic → ra Precision/FP rate*.
- Week 1: chọn SAST tool (← chính là benchmark này).
- Week 5: đánh giá fuzzing agent tìm đúng edge case.
- Week 10: eval pipeline LLM-as-judge + đo FP rate.

→ Làm chủ viên gạch = xây sẵn "cơ đánh giá" de-risk cả 3 mốc trên.

---

## 4. Thứ tự triển khai đề xuất (nối mạch)

1. **Benchmark trước** — vì nó nhỏ, chạy được, và ép ra 3 quyết định nền: schema `findings.jsonl`, LiteLLM gateway, engine SAST cho Week 1.
2. Kết quả benchmark → **chốt engine + schema** → dựng **DefectDojo data lake (Week 1)**.
3. Từ data lake → mở rộng lên **RAG (Week 3)** rồi **agents (Week 4+)** theo đúng dependency ở doc kiến trúc.

Nói cách khác: **benchmark là Week 1 thu nhỏ**; làm xong nó, bạn có sẵn schema dữ liệu + gateway + baseline để bung ra toàn Sentinel mà không phải làm lại.

---

## Câu hỏi chưa giải quyết
- `findings.jsonl` schema nên theo chuẩn có sẵn nào để nối thẳng data lake? (native DefectDojo import? SARIF giữ nguyên? OCSF?) — quyết định ở benchmark ảnh hưởng cả Week 1.
- Staging app của Sentinel = WebGoat/Juice Shop hay replica thật? — ảnh hưởng attack surface & ground truth về sau.
- "Model rẻ đủ tốt" đo ở benchmark với ngưỡng Precision bao nhiêu thì coi là "pass" để dùng cho cả Sentinel?
- Có yêu cầu air-gapped/on-prem không? — nếu có, LiteLLM phải trỏ vLLM ngay, không dùng API OpenAI/DeepSeek.
