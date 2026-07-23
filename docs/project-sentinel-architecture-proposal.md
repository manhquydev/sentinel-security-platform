# Project Sentinel — Phân tích bài toán & Kiến trúc đề xuất

> Trạng thái: đề xuất kiến trúc (chưa code). Nguồn: `docs/Project_Sentinel_VinUni_x_VinSOC_12-week.md` + 2 bản research trong `docs/research/`.
> Ràng buộc đã chốt: team lớn chạy song song · LLM qua API OpenAI-compatible (OpenAI/DeepSeek/vLLM) · output = kế hoạch kiến trúc.

---

## 1. Phát biểu bài toán

Sentinel = **hệ multi-agent tự động hóa an ninh web-app**, với luận điểm kép:
AI vừa là **vũ khí** (LLM tự recon → fuzz → exploit web app qua API Gateway) vừa là **mục tiêu** (chính agent phải chống prompt injection / data poisoning).

**Điểm khác biệt thật = Phase 3 (Security FOR AI).** XBOW/Strix/PentAGI đã làm phần tấn công rất mạnh; chỉ CAI làm cả tấn công + tự phòng thủ. Vậy giá trị của Sentinel nằm ở **tích hợp offense + self-hardening + LLMOps**, không phải ở việc build lại một pentest agent.

**Nguyên tắc nền (không thương lượng):**
- Study leaders, assemble parts — KHÔNG đấu engineering với XBOW/Strix. Fork/nghiên cứu **Strix** (topology), **CAI** (thesis Phase 3), **DefectDojo** (data lake).
- LLM *tìm* bug, **deterministic validator** *xác nhận* bug (bí quyết "no false positive" của XBOW).
- Guardrails chống prompt injection là **giảm rủi ro xác suất**, KHÔNG phải đảm bảo (paper "Attacker Moves Second" bẻ 12 defense với ASR >90%).
- Chỉ test **staging replica của chính team**, HITL gate cho mọi hành động state-changing.
- Wire cost-tracking từ **ngày đầu**, không đợi Phase 4 (multi-agent loop đốt token khủng khiếp).

---

## 2. Kiến trúc hệ thống (logic)

```
                         ┌──────────────────────────────────────────────┐
                         │  LLM GATEWAY (LiteLLM proxy) — OpenAI-compat   │
   mọi lời gọi LLM  ───► │  routing · cost/token · PII mask · guardrail   │ ──► OpenAI / DeepSeek / vLLM
                         │  hook · key mgmt · audit log                   │
                         └──────────────────────────────────────────────┘
                                          ▲ (mọi agent chỉ nói OpenAI format)
                                          │
[Staging web app] ──traffic──► [API Gateway Kong/Tyk] ◄── scoped token ── [Agent IAM  (MCP OAuth2.1)]
       │  SAST/DAST scans                                                        │
       ▼                                                                         │
[Vuln Data Lake DefectDojo] ─┐                                                   ▼
                             ├─► [Threat-Intel RAG]        ┌──── Multi-Agent Syndicate (LangGraph) ────┐
[CVE / OWASP / pentest]  ────┘   (Hybrid + GraphRAG)  ──►  │  Supervisor                                │
                                                           │   ├─ Recon    → Attack Surface Map         │
                                                           │   ├─ Fuzzing  → sinh/mutate payload        │
                                                           │   └─ Exploit  → [HITL gate] → validator    │
                                                           └────────────────────────────────────────────┘
                                                                     │
                        Observability (LangSmith/Phoenix/Langfuse) ──┤── Eval (LLM-as-Judge + FP rate)
                                                                     │
                                                      [vLLM prod + KEDA autoscale + FinOps]
```

**Xương sống 2 lớp (quyết định kiến trúc cốt lõi):**

| Lớp | Chọn | Vì sao |
|-----|------|--------|
| **LLM Gateway** | **LiteLLM proxy** | Vì tất cả LLM là OpenAI-compatible → 1 router duy nhất gộp: cost-tracking (T11), PII masking hook (T9), guardrail hook (T7), model swap OpenAI↔DeepSeek↔vLLM (T11). Giảm 4 yêu cầu rải rác về 1 điểm kiểm soát. |
| **Orchestration** | **LangGraph** | Durable checkpointing + `interrupt()` cho HITL (T8) + supervisor pattern (T6). Là default production trong cả 2 bản research. |

> Hệ quả của "chỉ dùng API OpenAI-compatible": **vLLM (T11) chỉ là một backend thay thế phía sau LiteLLM.** Prototype toàn bộ trên OpenAI/DeepSeek; đến demo cuối swap sang vLLM + open model (Qwen3) để chứng minh self-host + FinOps — không phải viết lại gì.

---

## 3. Stack đề xuất theo tuần

| Tuần | Khối | Build/OSS chọn | Ghi chú rủi ro |
|------|------|----------------|----------------|
| T1 | SAST/DAST + Data Lake | **DefectDojo** (gộp Semgrep/ZAP/Nuclei/Trivy, dedup theo CWE+endpoint) | Fit số 1 cho "unified data lake". |
| T2 | API Gateway + Agent IAM | **Kong/Tyk** + **AGNTCY identity** (MCP OAuth2.1, RFC 9728) | **Vùng non nhất.** Fallback: Kong scoped API-key + OAuth2, ghi MCP là future work. A2A "security out-of-scope" → phải tự thêm authz. |
| T3 | Threat-Intel RAG | **CVE-KGRAG** / Microsoft GraphRAG (Hybrid + GraphRAG) trên CVE/OWASP/pentest | GraphRAG index đắt → bắt đầu nhỏ; hybrid vector+BM25 (RRF) là fallback. GraphRAG tạo **poisoning surface mới** → nối vào threat model P3. |
| T4 | Recon Agent | LangGraph agent + wrap OWASP Amass/nmap/nuclei qua **MCP tool server** (mcp-security-hub) | Output = "Attack Surface Map" có cấu trúc (JSON schema cố định). |
| T5 | Fuzzing engine | Custom Python tool (LLM sinh payload, mutate theo 500/stack trace) + **FuzzyAI/LLMFuzzer** làm tham chiếu | Gửi request qua API Gateway (không bypass). |
| T6 | Multi-Agent Syndicate | **LangGraph supervisor** (topology tham chiếu **Strix**) + observability Phoenix/Langfuse | Đây là nơi ghép offensive lại; wire cost tracking Ở ĐÂY. |
| T7 | Guardrails / anti-injection | **LlamaFirewall** (PromptGuard2 + AlignmentCheck) + **CaMeL** capability-gating + Spotlighting baseline | Framing = probabilistic. Đo **ASR** trên staging; nếu >~10% → escalate CaMeL provenance tainting. |
| T8 | HITL approval gate | LangGraph `interrupt()` + Slack/Teams bot (propose→approve/reject, có idempotency + TTL + audit) | Gate 100% state-changing (SQLi, cmd injection). Tham chiếu GitLab Duo tool-approval. |
| T9 | PII redaction | **Presidio** cắm vào **LiteLLM hook** (mask trong log/memory/RAG trước khi ghi) | Regex (structured) + ML NER (unstructured) + secret scan. |
| T10 | Eval / LLM-as-Judge | **RAGAS/DeepEval** + benchmark endpoint đã biết vuln | **Đo false-positive rate** (chưa ai report → đây là differentiator). Judge bị "master-key" attack → structured rubric + evidence span + multi-pass. Confirm vuln bằng **deterministic validator**, không bằng LLM. |
| T11 | Prod deploy + FinOps | **vLLM** (behind LiteLLM) + **KEDA** (trigger `vllm:num_requests_waiting`) + DCGM + **cost-per-token recording rule** | Copy recipe vLLM+KEDA nguyên bản. `minReplica:1`, `cooldown:300`. |
| T12 | PRD + Business Case | ROI vs manual pentest | Anchor: XBOW ~85× speed; Xint $3k/scan; RunSybil $40M; Channel 4 giảm 60→80% chi phí pentest. Position differentiator = lớp Security-FOR-AI. |

---

## 4. Phân rã workstream cho team lớn (điểm quan trọng nhất với bạn)

Vì chạy song song, thứ quyết định thành/bại là **hợp đồng dữ liệu giữa các stream**, không phải lịch. Đề xuất 6 stream:

| Stream | Sở hữu (tuần) | Deliverable chính | Không được đụng |
|--------|----------------|-------------------|-----------------|
| **A — Data & Intel** | T1, T3 | DefectDojo data lake + Threat-Intel RAG | Không tự viết agent |
| **B — Gateway & Identity** | T2 | API Gateway + Agent IAM scoped-per-agent | Không viết business logic agent |
| **C — Offensive agents** | T4, T5, T6 | Recon/Fuzz/Exploit + Supervisor | Không tự dựng guardrail (dùng của D) |
| **D — Security-FOR-AI (thesis)** | T7, T8, T9 | Guardrails + HITL + PII redaction | Sở hữu toàn bộ input/output boundary |
| **E — LLMOps platform (cross-cutting, START DAY 1)** | LiteLLM router, observability, eval, vLLM, FinOps | Nền tảng cho mọi stream khác | Là "hạ tầng chung", không sở hữu logic domain |
| **F — Product/PRD (liên tục)** | Threat model, ROI, PRD, demo | Business case + trình bày stakeholder | — |

**Thứ tự phụ thuộc (dependency, KHÔNG bỏ được dù "vô hạn thời gian"):**
- E (LLM Gateway + observability) phải xong **trước tiên** — mọi stream khác gọi qua nó.
- A (data lake + RAG) phải xong trước C (Recon agent cần data để phân tích).
- B (Agent IAM) phải xong trước khi C gọi tool qua Gateway.
- D bọc quanh C — D cần C có interface I/O ổn định để chèn guardrail.

**Hợp đồng interface phải chốt sớm (viết trước khi code):**
1. Schema "Attack Surface Map" (A/C ↔ Recon output).
2. Schema tool-call qua MCP (B ↔ C): mỗi agent khai token scope, fail-closed khi out-of-scope.
3. Guardrail hook signature (D ↔ E): mọi data agent đọc từ target đi qua sanitizer của D.
4. Eval record schema (E/T10): mỗi finding có evidence span + validator result để tính FP rate.

---

## 5. Risk register + fallback

| Rủi ro | Mức | Fallback / ngưỡng đổi hướng |
|--------|-----|------------------------------|
| Agent IAM (MCP/A2A) chưa chín | Cao | → Kong scoped API-key + OAuth2, MCP = future work. Benchmark: mọi agent fail-closed khi token out-of-scope. |
| Prompt injection không giải được | Cao (bản chất) | Frame probabilistic; layer 3 guardrail; ASR >10% → CaMeL provenance tainting. KHÔNG hứa "an toàn tuyệt đối" khi demo. |
| GraphRAG index đắt + poisoning surface | Trung | → hybrid vector+BM25 (RRF); index nhỏ trước; poisoning nối vào threat model P3. |
| Token cost bùng nổ ($200+/run) | Trung-cao | Cost recording rule từ T6; budget alert per-run; ưu tiên DeepSeek cho tác vụ rẻ, model mạnh chỉ cho reasoning. |
| False positive từ LLM judge | Trung | Deterministic validator cho "confirmed vuln"; judge chỉ triage. Harden judge chống master-key. |
| "Thời gian vô hạn" → scope creep | Trung | Dependency ép thứ tự; chốt interface contract trước; mỗi stream có acceptance criteria đo được. |

---

## 6. Success metrics đề xuất

- **Offense:** % sub-task hoàn thành trên benchmark (tham chiếu xOffense 79%); số vuln thật tìm được trên staging.
- **Defense (thesis):** ASR prompt injection trước/sau guardrail (mục tiêu giảm mạnh, KHÔNG hứa 0%); % state-changing action bị HITL chặn đúng; % PII bị redact trước khi vào log/RAG.
- **LLMOps:** false-positive rate (headline metric), cost-per-pentest-run, TTFT p95, latency.
- **Business:** ROI vs manual pentest (speed × chi phí), PRD được stakeholder non-tech hiểu.

---

## 7. Đề xuất bước tiếp theo

Report này là "bản đồ kiến trúc". Với team lớn, việc đáng làm ngay:
1. **Chốt 4 interface contract** ở §4 (trước khi bất kỳ stream nào code).
2. Dựng **Stream E (LiteLLM + observability)** làm hạ tầng chung đầu tiên.
3. Fork + đọc **Strix / CAI / DefectDojo** để lấy làm reference architecture cho C / D / A.
4. (Tùy chọn) chạy `/plan` để bung thành plan chi tiết theo phase với acceptance criteria per-stream.

---

## Câu hỏi chưa giải quyết
- Staging web app cụ thể là gì? (Juice Shop/DVWA/WebGoat hay replica app thật của VinSOC?) — ảnh hưởng attack surface & schema data lake.
- Có yêu cầu air-gapped / on-prem không? — nếu có thì DeepSeek/OpenAI API không dùng được cho production, phải vLLM ngay từ đầu thay vì cuối.
- Model nào cho tác vụ nào (routing policy trong LiteLLM)? — cần bảng phân bổ model↔task để tối ưu cost.
- Định nghĩa "confirmed vuln" của deterministic validator do stream nào sở hữu (C hay E)?
