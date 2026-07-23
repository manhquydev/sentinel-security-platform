# Prior Art & Learning-Resource Survey for "Project Sentinel" (VinUni × VinSOC AI Security Capstone)

## TL;DR
- **Yes — much of Project Sentinel already exists in pieces, and at least one product does nearly the whole offensive scope.** Autonomous LLM multi-agent web-app pentesting is a crowded, fast-moving field: commercial leaders (XBOW, Strix) and open-source multi-agent frameworks (PentAGI, CAI, VulnBot, HackSynth, AutoPentest) already implement the Recon→Fuzz→Exploit "syndicate" pattern. But **no single public project combines the full offensive stack AND the "Security-FOR-AI" self-hardening dimension** the way Sentinel proposes — CAI is the closest, making Sentinel's integrated framing genuinely differentiated as a learning exercise.
- **Every one of the 12 weekly components maps to mature, studyable open-source repos** — DefectDojo (SAST/DAST aggregation), Kong/AGNTCY Identity (Agent IAM/MCP), Microsoft GraphRAG + CVE-KGRAG (threat-intel RAG), LangGraph-Supervisor (multi-agent), FuzzyAI/ChatAFL (LLM fuzzing), NeMo Guardrails (prompt-injection defense), Microsoft Presidio (PII redaction), RAGAS + Arize Phoenix (eval), and the vLLM production-stack + OpenCost (GPU FinOps).
- **The novelty and the value of the capstone is integration and the "Security FOR AI" hardening (Phase 3), not the individual parts** — treat XBOW/Strix as the north-star product benchmark, PentAGI/CAI as reference architectures to study, and the per-week repos below as building blocks to assemble and harden.

## Key Findings

**1. The overall concept is proven and commercially live.** In June 2025, XBOW — a fully autonomous AI penetration tester — became the #1-ranked researcher on HackerOne's US leaderboard, submitting nearly 1,060 vulnerability reports (132 officially confirmed/resolved, 303 triaged, 125 under review), impacting targets including Disney, AT&T, Ford and Epic Games (per XBOW's "How XBOW Ranked #1" blog and CO/AI reporting). The company raised a $75M Series B led by Apoorv Agrawal of Altimeter (with Sequoia and Nat Friedman participating), bringing total funding to $117M (XBOW's June 24 2025 "XBOW Raises Series B" post); it subsequently raised a $120M Series C at a $1B+ valuation led by DFJ Growth & Northzone (March 18 2026), for $237M total (SecurityWeek). This is the single strongest signal that the Sentinel concept is viable. XBOW is closed-source but its engineering blog is a rich design reference, and it notably uses **deterministic validators (not LLMs) to confirm findings** — directly relevant to Sentinel's Week-10 false-positive goal.

**2. Open-source equivalents are abundant and increasingly mature.** Strix (usestrix/strix, ~36k GitHub stars) is the most production-ready open-source analog: a multi-agent system (recon/exploitation/validation/post-exploitation agents) that runs in a Docker sandbox, validates with real PoCs, and integrates with CI/CD, Slack, and Jira. PentAGI (~15.5k stars, MIT) and CAI (~9.4k stars, MIT) are full multi-agent frameworks. Academic frameworks (VulnBot, HackSynth, AutoPentest, xOffense) come with papers and code, ideal for studying architecture.

**3. The "Security FOR AI" self-hardening dimension (Phase 3) is Sentinel's real differentiator.** Most offensive tools do not defend *themselves* against prompt injection/data poisoning. CAI (aliasrobotics/cai) is the one open-source framework that explicitly does both, shipping built-in prompt-injection guardrails and a companion paper "Hacking the AI Hackers via Prompt Injection" (arXiv:2508.21669). This confirms the threat is real and gives Sentinel a template — but the combination remains sparsely populated, so Sentinel's Phase 3 is well-justified.

**4. Every skill S1–S11 has canonical open-source tooling**, listed per-week below. The team will spend most effort on *integration and orchestration* (LangGraph/LangSmith), and on the genuinely hard/novel parts: Agent IAM via MCP/A2A (still an immature standard), GraphRAG over security data, and the Phase-3 hardening.

## Details — Reference Material by Phase / Week

### Comparable full-scope products & research prototypes (survey for context)

| Project | Type | Maturity | Link | Relevance to Sentinel |
|---|---|---|---|---|
| **XBOW** | Commercial, closed | Production; #1 HackerOne US 2025; $237M total funding | xbow.com/blog | North-star benchmark for the *whole* offensive product; deterministic validators; Week-12 ROI comparison |
| **Strix** | Open-source | ~36k stars; CLI + hosted; CI/CD | github.com/usestrix/strix | Closest studyable analog to full Sentinel offensive scope; multi-agent + Docker sandbox + PoC validation |
| **PentAGI** | Open-source (MIT) | ~15.5k stars; 20+ tools (nmap/metasploit/sqlmap) | github.com/vxcontrol/pentagi | Reference multi-agent architecture (Orchestrator→Researcher/Developer/Executor); Langfuse observability; pgvector + Neo4j memory |
| **CAI (Cybersecurity AI)** | Open-source (MIT/research) | ~9.4k stars; Alias Robotics | github.com/aliasrobotics/cai | **Only OSS framework doing offensive + self-hardening**; built-in prompt-injection guardrails; 8 pillars incl. Guardrails + HITL; vendor claims (3,600× vs humans) are self-reported, treat with caution |
| **VulnBot** | Academic + code | Paper arXiv:2501.13411 | github.com/KHenryAegis/VulnBot | Multi-agent (Recon/Scan/Exploit) with Penetration Task Graph; RAG via Langchain-Chatchat + Milvus |
| **HackSynth** | Academic + code | Paper; CTF benchmarks | github.com/aielte-research/HackSynth | Planner+Summarizer dual-module agent; PicoCTF/OverTheWire benchmarks — useful for Week-10 eval design |
| **AutoPentest** | Academic + code | Paper arXiv:2505.10321 | github.com/JuliusHenke/autopentest | Black-box LLM pentest on LangChain — clean reference for tool wiring |
| **xOffense** | Academic | Paper arXiv:2509.13021 (Sep 16 2025) | arXiv | Fine-tuned Qwen3-32B multi-agent framework; **79.17% sub-task completion rate, "decisively surpassing leading systems such as VulnBot and PentestGPT"** on AutoPenBench and AI-Pentest-Benchmark (beating Llama3.1-405B's 69.05%) — supports Sentinel's open-model/vLLM choice |
| **hardenedlinux/agentic-ai-pentest** | Curated eval | Benchmarks OSS agents vs WebGoat | github.com/hardenedlinux/agentic-ai-pentest | Notes token-cost blowups of ReAct agents — relevant to Week-11 FinOps |

### Phase 1 — Infrastructure & Cyber Security Baseline

**Week 1 — SAST/DAST integration + unified data lake (S7, S10)**
- **DefectDojo** (github.com/DefectDojo/django-DefectDojo) — OWASP Flagship vulnerability-management platform; parses 200+ tools (Semgrep, Bandit, CodeQL, ZAP, Burp, Nuclei, Trivy) into one deduplicated store with CWE/endpoint-based dedup. This is the single best fit for Sentinel's "aggregate raw JSON/XML into a unified data lake" requirement. BSD-3, Docker/K8s deploy. Has an official skill for agent integration (AgentSecOps/SecOpsAgentKit).
- **Semgrep** and **OWASP ZAP** / **Nuclei** (projectdiscovery/nuclei) — the canonical free SAST and DAST/scanner engines to feed DefectDojo. Nuclei outputs JSONL and is CI/CD-native.
- Reference pipeline: 0xCoolSAM's "End-to-End DevSecOps CI/CD Pipeline" blog shows GitLeaks+SAST+Trivy+DAST → DefectDojo via API — a concrete blueprint.
- Background: Microsoft MSRC "Scaling DAST" blog (agentic DAST proxy architecture) for design ideas on orchestrating DAST at scale.

**Week 2 — API Gateway + Agent IAM via MCP/A2A (S4)**
- **Kong** and **Tyk** — the named gateways; both open-source, both now market MCP/AI-gateway features. Route the staging app and all agent tool traffic through them.
- **AGNTCY Identity** (github.com/agntcy/identity) — onboards/verifies identities for Agents, MCP servers, and multi-agent systems using Verifiable Credentials + "Agent Badges"; integrates with Okta/IdPs (BYOID). This is the best open-source implementation of "Agent IAM with scoped permissions per agent."
- **MCP background**: Anthropic's Model Context Protocol; the academic landscape/security paper (Hou et al., "MCP: Landscape, Security Threats, and Future Research Directions", xinyi-hou.github.io) documents the auth/authorization gaps Sentinel must solve. **nisalgunawardhana/MCP-Security-101** and **Puliczek/awesome-mcp-security** catalog concrete MCP threats (tool poisoning, confused deputy, session hijack) and defenses.
- **A2A protocol**: Google's Agent2Agent spec (announced April 9 2025, donated to Linux Foundation June 2025); uses Agent Cards, OAuth 2.0/JWT, RBAC via JWT claims. Security analyses: arXiv:2505.12490 ("Improving Google A2A… Protecting Sensitive Data") and arXiv:2511.03841 (comparative protocol security).
- **lastmile-ai/mcp-agent** — build agents on MCP with lifecycle management; good starter for scoped tool access.

**Week 3 — Threat-Intel RAG (Hybrid Search + GraphRAG) (S3)**
- **Microsoft GraphRAG** (github.com/microsoft/graphrag) — the canonical modular graph-based RAG pipeline; note MSFT's own warning that indexing is expensive (start small).
- **CVE-KGRAG** (github.com/Yuning-J/CVE-KGRAG) — a purpose-built hybrid Knowledge-Graph + RAG platform for CVE analytics: nodes for CVE/Product/Vendor/CWE/CAPEC/MITRE ATT&CK, NetworkX graph + vector DB, Llama3-integrated. Almost exactly Sentinel's Week-3 spec.
- **CyberScienceLab/Threat_Intelligence_Rag** — CTI RAG with Qdrant + LLaMA3 over AlienVault OTX indicators; simpler starting point.
- Background: "Beyond RAG for Cyber Threat Intelligence" (systematic eval of vector vs graph vs hybrid vs agentic retrieval on CTI corpora; hybrid graph-text improves multi-hop answer quality by up to 35%) and AgCyRAG (CEUR Vol-4079) — an agentic KG-RAG that combines Neo4j Cypher + vector search and exposes SPARQL queries over a cybersecurity KG via MCP. **GraphRAG under Fire** (arXiv:2501.14050) is essential reading — it shows GraphRAG's poisoning attack surface, directly relevant to Sentinel's data-poisoning threat model.

### Phase 2 — AI for Security (LLM-guided pentest & fuzzing)

**Week 4 — Recon & Analysis agent → Attack Surface Map (S1, S5)**
- Study VulnBot's Recon agent and Strix's recon/fingerprinting agents (subdomain enum, tech fingerprint, endpoint discovery). AutoPentest and HackSynth show clean recon→analysis→plan loops on LangChain.
- **cyproxio/mcp-for-security** and **FuzzingLabs/mcp-security-hub** — MCP servers wrapping nmap, nuclei, sqlmap, ffuf, whatweb, masscan, etc. These let the Recon agent call real recon tools through a standardized interface — a direct implementation of Sentinel's tool-wrapping approach.

**Week 5 — LLM-guided fuzzing engine (S4, S10)**
- **cyberark/FuzzyAI** (github.com/cyberark/FuzzyAI) — automated LLM fuzzing framework; dynamically generates adversarial/mutated payloads through model APIs. Closest to Sentinel's "LLM sends malformed requests, analyzes responses, mutates payloads."
- **mnns/LLMFuzzer** — the first OSS fuzzing framework for LLM integrations via HTTP-API, with configurable JSON query/response attributes and header/cookie injection — a near-literal template for "send malformed requests through the API Gateway."
- **ChatAFL** (github.com/ChatAFLndss/ChatAFL, NDSS'24) — LLM-guided *protocol* fuzzing (extracts grammar, mutates via LLM); **google/oss-fuzz-gen** — LLM-generated fuzz targets (160 C/C++ projects, up to 29% coverage gain, 30 new bugs); **eth-sri/ToolFuzz** — fuzzes LLM *agent tools* (finds runtime crashes & wrong outputs) — directly useful for Sentinel's own tool robustness. **PromptFuzz** and **ProphetFuzz** (CCS'24) round out the survey. Overview: "LLM-Based Fuzzing Techniques: A Survey" (arXiv:2402.00350).

**Week 6 — Multi-agent "Pentest Syndicate" + observability (S2, S6)**
- **langchain-ai/langgraph-supervisor-py** — prebuilt supervisor pattern with tool-based handoffs, hierarchical supervisors, memory/checkpointer support. This is the reference for Sentinel's Supervisor→Recon/Fuzz/Exploit topology.
- **LangGraph** core (github.com/langchain-ai/langgraph) + example repos (langgraphjs agent_supervisor notebook, extrawest/multi_agent_workflow_demo, cgoncalves94/multi_agent_system) show the exact patterns.
- Observability: **LangSmith** (LangChain-native tracing/eval) and **Arize Phoenix** (github.com/Arize-ai/phoenix, open-source, OpenTelemetry/OpenInference, ~9k stars, first-class LangGraph support) — both named-appropriate for Week-6 tracing. Phoenix is the free self-hostable choice; PentAGI itself uses Langfuse.

### Phase 3 — Security FOR AI (hardening the agentic system)

**Week 7 — Indirect prompt-injection defense + guardrails (S8)**
- **NVIDIA NeMo Guardrails** (github.com/NVIDIA-NeMo/Guardrails, Apache-2.0, ~6.5k stars) — the named tool; programmable input/dialog/retrieval/execution/output rails to sanitize agent-read data. Works with LangChain/LangGraph. Its LLM-Vulnerability-Scanning docs and the ABC-bot example are direct study material.
- Complementary defenses: **protectai/llm-guard**, **Meta Prompt Guard** / **ProtectAI DeBERTa prompt-injection** classifiers, **Rebuff** (canary tokens). Catalog: **tldrsec/prompt-injection-defenses** (every practical & proposed defense, incl. Task Shield & action guards).
- Deliberately-vulnerable staging targets that return malicious payloads: **OWASP Juice Shop** (bkimminich/juice-shop, modern JS/REST), **DVWA**, **WebGoat**, and multi-app bootstrap **irvinlim/vulnerability-testbeds**. For AI-specific injection targets, see the MCP tool-poisoning experiments (invariantlabs-ai) and **NVIDIA Garak** (github.com/NVIDIA/garak — LLM vuln scanner / "nmap for LLMs," Apache-2.0, ~8.5k stars; probes for prompt injection, jailbreaks, data leakage, toxicity) to red-team Sentinel's own guardrails.
- Background benchmark: "Adversarial Prompt Evaluation" (arXiv:2502.15427) benchmarks guardrails (NeMo, DeBERTa, Llama-Guard, etc.) with F1/recall tables — use to pick a guardrail.

**Week 8 — HITL approval gates via Slack/Teams (S8)**
- **LangGraph Human-in-the-Loop middleware** — `interrupt()` + checkpointer pattern (approve/edit/reject/respond) gating high-risk tools like `execute_sql`; official docs (docs.langchain.com/oss/python/langchain/human-in-the-loop) show gating `write_file`/`execute_sql` while auto-approving `read_data`. This is the exact mechanism for Sentinel's SQLi/command-injection approval gates.
- Slack/Teams pattern: LangGraph JS guide and multiple blogs (matheuspalma.com, abstractalgorithms.dev) detail the "propose→commit" flow — graph pauses, Slack message with approve/reject buttons hits your API (not the model), resumes graph; with idempotency keys, TTL/expiry, and audit logging. Best-practice framing: ml4devs and LiveKit HITL guides (gate 100% of high-risk, sample 5–20% of low-risk; avoid rubber-stamping).

**Week 9 — Real-time PII redaction/masking (S8)**
- **Microsoft Presidio** (github.com/data-privacy-stack/presidio) — the open-source standard for PII detection/redaction across text/image/structured data (NER + regex + checksums, custom recognizers). Directly fits "redact emails/passwords/SSNs from agent memory/logs before RAG/logging."
- **LiteLLM + Presidio** — documented gateway pattern with `mode: "logging_only"` to mask PII *only* in logs before hitting Langfuse/RAG — precisely Sentinel's Week-9 requirement. Also `pre_mcp_call` mode for MCP traffic.
- Reference implementations: **lotharschulz/pii-redaction-guard** (input sanitize + output sweep + audit log, catches hallucinated PII) and **chandika/pii-redactor** (layered regex→Presidio→custom, session-scoped vault, rehydrate on return). Enterprise architecture patterns paper: IJAIBDCMS "Enterprise-Scale PII De-Identification with Presidio."

### Phase 4 — LLMOps & Production Rollout

**Week 10 — Eval pipeline / LLM-as-Judge (S9)**
- **RAGAS** (github.com/explodinggradients/ragas; also vibrantlabsai/ragas mirror) — the named framework; faithfulness/answer-relevancy/context-precision metrics + synthetic test-set generation; integrates with LangChain and observability tools. Use to measure whether fuzzing/exploit agents correctly ID vulns without false positives.
- **shpaz/llm-as-a-judge** (RAGAS + GPT judge, deterministic eval + stats) and **Arize Phoenix evals** (`llm_classify`, 50+ built-in metrics) are ready templates. Mistral cookbook RAG_evaluation.ipynb shows RAG-Triad.
- Caveats to design around: multiple papers (arXiv:2506.20128, CALM/RIKER arXiv:2601.08847) document LLM-judge biases (position, verbosity, self-enhancement) and note RAGAS-vs-human correlation can be as low as ~0.55 — use structured rubrics and, like XBOW, deterministic validators for exploit confirmation.
- CTF-style benchmarks for security-agent eval: HackSynth's PicoCTF/OverTheWire sets; AutoPenBench / AI-Pentest-Benchmark (referenced by xOffense).

**Week 11 — Production deployment: vLLM + GPU FinOps (S6, S7)**
- **vLLM** (github.com/vllm-project/vllm) + **vllm-project/production-stack** — the named serving engine and its official K8s-native reference deployment with a Grafana dashboard (TTFT, running/pending requests, GPU KV-cache usage/hit-rate). Directly implements Sentinel's "containerized, auto-scaling vLLM serving with latency monitoring."
- Autoscaling/monitoring: KEDA on `DCGM_FI_DEV_GPU_UTIL` (NVIDIA DCGM exporter) + Prometheus/Grafana; guides (scaleops.com, markaicode, Oracle OKE tutorial) give worked GKE/EKS examples incl. cold-start and GPU-stockout failure modes.
- **GPU FinOps**: **opencost/opencost** (CNCF, Apache-2.0) — real-time K8s cost allocation with explicit **vLLM AI-inference cost tracking (cost per million tokens, KV-cache-corrected pricing)** and Prometheus export. This is the concrete tool for Sentinel's "drift/cost alerting (GPU FinOps)."

**Week 12 — Business case / PRD / ROI vs manual pentesting (S11)**
- Use XBOW's public metrics as the ROI anchor: per XBOW's Aug 5 2025 blog "XBOW now matches the capabilities of a top human pentester," XBOW and principal pentester Federico Muttis (20+ years, multiple CVEs) each solved 85% of 104 novel benchmarks — Muttis in 40 hours, XBOW in 28 minutes; other human testers scored ≤59%. This ~85× speed differential is your headline ROI figure.
- Include the honest caveat: "Around 25% of [XBOW's] findings are marked 'informative' or 'not applicable'" (uprootsecurity.com, Dec 2025), and its benchmark was built by third-party firms from PortSwigger/PentesterLab/CTF sources (github.com/xbow-engineering/validation-benchmarks).
- Strix testimonials (Chegg) and XBOW customer quotes contrast automated continuous testing vs point-in-time manual pentests. For a vendor-quantified budget case, cite Channel 4 CISO Brian Brackenborough in Invicti's Channel 4 case study: "the budget we were spending every year on penetration testing decreased by approximately 60% almost immediately and went down even more the following year, to about 20% of our initial spending."

## Recommendations

1. **Adopt a "study the leaders, assemble the parts" strategy.** Do *not* try to out-engineer XBOW/Strix. Instead: (a) read XBOW's blog + Strix's architecture as your product spec; (b) fork/study PentAGI and CAI as end-to-end reference implementations; (c) build Sentinel by wiring the per-week OSS blocks above on a LangGraph backbone.

2. **Stage the build to de-risk the hard parts early.** Weeks 1–3 (DefectDojo + Kong/AGNTCY + GraphRAG/CVE-KGRAG) are the foundation — get the data lake and Agent IAM working before agents. The genuinely immature areas (MCP/A2A Agent IAM, GraphRAG poisoning defense) deserve extra time and a fallback (e.g., simple scoped API keys if AGNTCY proves too heavy).

3. **Make Phase 3 the thesis.** Because self-hardening an offensive agent is the least-solved part of the field, lead your demo and PRD with it. Study CAI's guardrails + arXiv:2508.21669, red-team your own agent with Garak, and use Juice Shop/DVWA to serve indirect-injection payloads back to your agents.

4. **Use deterministic validators for exploit confirmation (Week 10).** XBOW's key insight is that LLMs find bugs but *deterministic checks* confirm them — this is how you hit the "no false positives" bar. Build RAGAS/LLM-judge for triage but gate final "confirmed vuln" status behind scripted verification.

5. **Instrument cost from Day 1.** ReAct/multi-agent security loops are notoriously token-expensive (hardenedlinux notes this explicitly). Wire Phoenix/LangSmith tracing + OpenCost token accounting in Week 6, not Week 11, so you have baseline data for the Week-12 ROI story.

**Thresholds that would change the plan:** If AGNTCY/MCP identity proves unstable, fall back to Kong-scoped API keys + OAuth2 and document MCP as future work. If GraphRAG indexing cost is prohibitive on your GPU budget, use hybrid vector+BM25 retrieval (RRF) over CVE-KGRAG's simpler JSON-KG mode instead of full GraphRAG. If self-hosted vLLM latency/cost is unmanageable, prototype on a hosted API and reserve vLLM for the final production demo.

## Caveats
- **Vendor and self-reported metrics.** XBOW's leaderboard/speed numbers come from XBOW and press; CAI's "3,600× vs humans" and alias1-beats-GPT-5 claims are self-published by Alias Robotics and not independently verified. Treat all such figures as directional, not proven.
- **GitHub star counts are point-in-time** (captured mid-2026) and change continuously; several counts (Strix ~36k, PentAGI ~15.5k, CAI ~9.4k, Garak ~8.5k, Phoenix ~9k, NeMo Guardrails ~6.5k) are approximate.
- **Legal/ethical scope.** Every tool here is dual-use. Sentinel must only ever test the team's own staging replica, with HITL gates on state-changing actions — exactly as the brief specifies. Do not point these tools at third-party systems without written authorization.
- **Fast-moving field.** MCP/A2A specs, NeMo Guardrails, vLLM, and RAGAS all ship breaking changes frequently; pin versions and check changelogs (e.g., Presidio's June-2026 release notes, A2A v1.0 Signed Agent Cards) before building.
- **The "full Sentinel" gap is real but narrow.** No public project unifies the entire offensive + self-hardening + LLMOps scope; CAI is the nearest. That gap is the capstone's opportunity — but also means integration risk is on the team, since there is no single blueprint to copy.