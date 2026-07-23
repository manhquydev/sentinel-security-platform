# The Capstone Product: "Project Sentinel"

**Goal:** Build an autonomous, multi-agent system that continuously analyzes web applications, integrates SAST/DAST findings, conducts LLM-guided fuzzing through an API Gateway, and is itself hardened against AI-specific attacks (Prompt Injection, Data Poisoning).

---

## Phase 1: Infrastructure & Cyber Security Baseline (Weeks 1–3)

**Focus:** Setting up the target environments, traditional security tooling, and secure access.

### Week 1: SAST/DAST CI/CD Integration & Baseline Analysis
- **Context (S7, S10):** The team uses their CI/CD and vibe-coding skills to set up the foundation.
- **Deliverable:** Deploy a replica of a company web application into a staging environment. Integrate enterprise SAST and DAST tools into the CI/CD pipeline.
- **Practical Task:** Automate the execution of SAST/DAST scans. Aggregate the raw JSON/XML outputs into a unified data lake. Perform an initial manual web application analysis to understand the attack surface.

### Week 2: API Gateway & Agent IAM Implementation
- **Context (S4):** AI agents need secure ways to interact with systems.
- **Deliverable:** Route all staging application traffic through an API Gateway (e.g., Kong, Tyk).
- **Practical Task:** Design and implement Agent IAM. Instead of standard user tokens, create a robust identity and access management system specifically for AI Agents (using MCP/A2A protocols). Ensure that an Agent has strictly scoped permissions (e.g., allowed to query `/api/users` but not `/api/admin`).

### Week 3: Threat Intelligence RAG Pipeline
- **Context (S3):** High-accuracy RAG is required for the AI to understand vulnerabilities.
- **Deliverable:** A highly accurate, continuously updating RAG pipeline (utilizing Hybrid Search & GraphRAG).
- **Practical Task:** Ingest CVE databases, OWASP guidelines, and the company's past pentest reports into the RAG system. Measure retrieval accuracy to ensure the upcoming agents get precise context regarding web app vulnerabilities.

---

## Phase 2: AI for Security — LLM-Guided Pentest & Fuzzing (Weeks 4–6)

**Focus:** Using AI to attack and analyze the staging environment.

### Week 4: Building the "Recon & Analysis" Agent
- **Context (S1, S5):** Context engineering and basic agent building.
- **Deliverable:** A specialized Recon Agent connected to the SAST/DAST data lake and Threat Intel RAG.
- **Practical Task:** Craft the system prompt and manage the token budget so this agent can ingest massive SAST/DAST logs. The agent must analyze these logs, cross-reference them with the RAG pipeline, and output a structured "Attack Surface Map" of the staging web app.

### Week 5: LLM-Guided Fuzzing via Custom Tools
- **Context (S4, S10):** Writing custom tools and wrappers.
- **Deliverable:** An intelligent fuzzing engine.
- **Practical Task:** Write custom Python tools (API wrappers) that allow an LLM to send malformed requests through the API Gateway. The LLM must dynamically generate fuzzing payloads based on the Recon Agent's map, analyze the HTTP responses (e.g., 500 Internal Server Error, stack traces), and mutate the payload to dig deeper.

### Week 6: The Multi-Agent Pentest Syndicate
- **Context (S2):** Multi-agent coordination and observability.
- **Deliverable:** A fully coordinated Multi-Agent system (Supervisor, Recon Agent, Fuzzing Agent, Exploit Agent).
- **Practical Task:** Implement the communication flow. The Supervisor dictates the strategy, Recon gathers data, Fuzzing finds edge cases, and Exploit attempts safe, simulated breaches. Implement observability tools (like LangSmith or Arize) to trace the exact reasoning and communication flow between these agents.

---

## Phase 3: Security FOR AI — Hardening the System (Weeks 7–9)

**Focus:** Ensuring the AI system cannot be hijacked, manipulated, or leak data.

### Week 7: Advanced Guardrails & Indirect Prompt Injection Defense
- **Context (S8):** Guardrails and filtering.
- **Deliverable:** A secure input/output boundary for the agentic system.
- **Practical Task — The Trap:** Introduce a vulnerability in the staging app that returns a malicious payload designed to hijack the LLM (Indirect Prompt Injection). The grads must implement robust guardrails (e.g., NeMo Guardrails) to sanitize all data the agent reads from the target app, preventing the agent from executing rogue commands.

### Week 8: Human-in-the-Loop (HITL) for High-Risk Actions
- **Context (S8, S4):** HITL workflows.
- **Deliverable:** Approval gates for the Exploit Agent.
- **Practical Task:** Enforce a strict policy where the Exploit Agent cannot execute state-changing payloads (e.g., SQLi, Command Injection) without human approval. Build an integration (e.g., a Slack/Teams bot) where the agent presents its intended payload, the justification, and waits for a human security engineer to click "Approve" or "Reject".

### Week 9: Data Privacy & PII Redaction
- **Context (S5, S8):** Protecting sensitive data.
- **Deliverable:** Real-time data masking.
- **Practical Task:** Ensure that if the LLM-guided pentest successfully dumps a database containing mock user data, the PII (emails, passwords, SSNs) is instantly redacted from the agent's memory and logs before it hits the central logging server or the RAG database, maintaining strict data compliance.

---

## Phase 4: LLMOps & Production Rollout (Weeks 10–12)

**Focus:** Taking the system from a working prototype to a reliable, monitored production tool.

### Week 10: Eval Pipeline & Benchmarking (LLM-as-a-Judge)
- **Context (S9):** Automated evaluation.
- **Deliverable:** A continuous evaluation pipeline for the pentest agents.
- **Practical Task:** Build a benchmark suite using known vulnerable endpoints. Use an LLM-as-a-Judge framework (like RAGAS or a custom implementation) to evaluate if the Fuzzing/Exploit agents correctly identified the vulnerabilities without triggering false positives. Analyze failure cases and adjust system prompts accordingly.

### Week 11: Production Deployment & GPU FinOps
- **Context (S6, S7):** Deploying with vLLM, monitoring, and scaling.
- **Deliverable:** Containerized, auto-scaling deployment.
- **Practical Task:** Package the multi-agent system into containers. Deploy the underlying open-source models using vLLM for high throughput. Set up comprehensive monitoring: track latency, error rates, and token costs per pentest run. Implement alerting for model drift or unexpected cost spikes.

### Week 12: Business Case, PRD, & Stakeholder Handover
- **Context (S11):** Soft skills, ROI analysis, and presentation.
- **Deliverable:** A finalized PRD and a live demonstration to company leadership.
- **Practical Task:** The grads must write a business case comparing the ROI of their new automated AI-SOC tool against traditional manual pentesting. They will present a live demo to non-tech stakeholders (e.g., Product Managers, Execs), explaining complex concepts like Agent IAM and Fuzzing in business terms, proving they are ready to integrate into the company's fast-paced environment.

---

## How It Works

1. **Respects your baseline:** apply what you learn to solving real-world problems
2. **Contextualizes Security:** think of AI as both the weapon (LLM-guided pentest) and the target (Securing the Agent with IAM and Guardrails)
3. **Real-world pressures:** mind the token costs, latency, false positives, and stakeholder buy-in

---

## References

| Mã | Bloom's | Kỹ năng | Chuẩn kỹ năng — học viên độc lập thực hiện được |
|----|---------|---------|---------------------------------------------------|
| S1 | Analyze | Thiết kế & xây dựng AI Agent | Build agent cơ bản hoàn chỉnh: chọn đúng design pattern, cấu hình system prompt, kết nối tools, triển khai memory. Agent hoạt động ổn định. |
| S2 | Create | Xây dựng Multi-Agent | Thiết kế hệ thống nhiều agent phối hợp: phân vai (Supervisor, Router), quản lý communication flow, xử lý conflict. Trace bằng observability tools. |
| S3 | Create | RAG Pipeline chính xác cao | Xây RAG vượt mức cơ bản: hybrid search, re-ranking, query transformation, GraphRAG. Đo lường và cải tiến liên tục. |
| S4 | Apply | Custom Tools & MCP/A2A | Viết custom tools (API wrapper, database query, file processing). Kết nối agent với hệ thống ngoài qua MCP và A2A Protocol. |
| S5 | Apply | Context Engineering | Quản lý token budget, thiết kế memory hierarchy, nén context. Craft system prompt, few-shot examples sao cho agent hiểu đúng ý định. |
| S6 | Apply | Deploy Agent Production | Đóng gói container, expose API, deploy cloud với vLLM. Monitoring: latency/error rate/cost + Data Observability. Alerting và auto-scaling. |
| S7 | Create | CI/CD Pipeline & LLMOps | CI/CD cho AI: automated testing, eval pipeline, model versioning. LLMOps: prompt versioning, guardrails, model drift detection, GPU FinOps. |
| S8 | Apply | Guardrails & HITL | Guardrails chống prompt injection, lọc nội dung độc hại, phát hiện PII. HITL workflow (approval gates, human review) cho tác vụ quan trọng. |
| S9 | Create | Eval Pipeline & Benchmark | Tạo benchmark phù hợp domain, dựng eval pipeline tự động (LLM-as-Judge, RAGAS). Phân tích failure cases → action items. |
| S10 | Apply | Vibe Coding | Sử dụng thành thạo AI coding assistant. Biết khi nào nên tin AI, khi nào phải tự viết — đặc biệt logic bảo mật và business rules. |
| S11 | Apply | Phân tích bài toán & PRD | Viết Business Case, PRD, phân tích ROI. Phối hợp team đa vai trò. Trình bày thuyết phục cho stakeholder non-tech. |
