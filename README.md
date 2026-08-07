# Project Sentinel

**Sentinel** là đồ án / lab nghiên cứu–giáo dục (capstone) về **phân tích bảo mật ứng dụng web có AI**, chạy **chỉ trên lab local** (loopback). Mục tiêu không phải “AI tự khai thác Internet”, mà là:

1. **Đưa kết quả quét (SAST/DAST/SCA) về một dạng thống nhất, đã che secret.**
2. **Để AI hỗ trợ phân tích trên bằng chứng máy quét** — không bịa endpoint hay lỗ hổng.
3. **Bọc an toàn quanh AI**: prompt injection fail-closed, PII/redaction, phê duyệt người (HITL), request chỉ qua API Gateway và catalog cho phép.

**Bối cảnh:** VinUni × VinSOC · TTS Nguyễn Mạnh Quý.  
**Site báo cáo tuần (mentor):** [https://vinsoc.manhquy.id.vn](https://vinsoc.manhquy.id.vn) · [`/llms.txt`](https://vinsoc.manhquy.id.vn/llms.txt)

---

## Đây là (và không phải) gì?

| Là | Không phải |
|---|---|
| Lab an toàn, có bằng chứng, có ranh giới tin cậy | Sản phẩm SaaS / pentest agent tự do trên Internet |
| Hệ thống hỗ trợ AppSec / thực tập sinh trên target cố ý lỗ | Công cụ “AI tìm bug nhiều hơn con người” không kiểm chứng |
| Hai product riêng: **Charter** và **Workbench** | Một product duy nhất; trộn bằng chứng hai bên là sai |

**Hợp đồng sản phẩm công bố (Charter):**  
[docs/product/sentinel-charter-brief.md](docs/product/sentinel-charter-brief.md)  
**Bản đồ as-built:**  
[docs/sentinel-six-week-as-built-architecture.md](docs/sentinel-six-week-as-built-architecture.md)

---

## Hai product — không trộn bằng chứng

| Product | Là gì | Không phải |
|---|---|---|
| **Charter** | Luồng 6 tuần lab Juice Shop local: quét → che secret → báo cáo bám bằng chứng → HITL ký → một request catalog qua Kong | Workbench; corpus so sánh; “nghiệm thu” bằng UI research |
| **Workbench** | UI/broker research local: fixture scanner, chuẩn bị corpus host-local, gate readiness | Hoàn thành Charter; bằng chứng approve/audit Charter |

- Charter: [charter brief](docs/product/sentinel-charter-brief.md)
- Workbench: [workbench brief](docs/product/sentinel-security-research-workbench.md)
- Runbook live Charter: [live acceptance](docs/operations/sentinel-live-acceptance-runbook.md)
- Demo Workbench: [workbench demo](docs/operations/sentinel-workbench-demo.md)
- **Báo cáo tuần (mentor):** [docs/reports/](docs/reports/index.md) · site [website/](website/README.md)

Image pin (không secret): [`scanners/image-pins.env`](scanners/image-pins.env).

---

## Ý tưởng cốt lõi (WHY)

Quét bảo mật sinh ra rất nhiều cảnh báo theo từng tool; team muốn LLM “đọc giúp”. LLM ngây thơ sẽ:

- **bịa** finding / endpoint,
- **làm theo** chỉ dẫn độc trong response (prompt injection),
- **rò** secret/PII vào prompt và log.

Sentinel tách rõ:

| Vai trò | Ai làm |
|---|---|
| Tìm / quan sát | Máy quét deterministic (Semgrep, Trivy, Nuclei, …) |
| Chuẩn hóa + che secret | Pipeline scanners / adapter |
| Giải thích / đề xuất (bám field đã typed) | Agent + renderer — model **không** được invent fact |
| Hành động state-changing | Chỉ sau HITL + Gateway + allowlist/catalog |

Chi tiết hợp đồng và ranh giới: charter brief + as-built + [docs/decisions/](docs/decisions/).

---

## Ranh giới an toàn (Charter)

- **Target:** Juice Shop lab tại `http://127.0.0.1:13000` — không target ngoài, redirect ra ngoài bị từ chối.
- **An toàn dữ liệu:** report thô che trước khi lưu; nội dung từ target coi là **không tin cậy**; PII / injection fail-closed.
- **Request chủ động:** chỉ catalog cố định qua Kong (GET/POST predeclared); POST cần HITL ký; không payload tùy ý.
- **Ngoài phạm vi 6 tuần tối thiểu:** multi-agent phức tạp, GraphRAG, MCP/A2A đầy đủ, vLLM/GPU, LLM-as-a-Judge phức tạp (có thể có code lịch sử — không phải tiêu chí hoàn thành hiện tại).

Owner thực thi: [scanners/](scanners/README.md), [infra/kong/](infra/kong/README.md), [`scripts/sentinel-demo.sh`](scripts/sentinel-demo.sh).

---

## Mức độ chín (tóm tắt)

- **Charter:** ledger [charter closure](docs/plans/completed/2026-08-04-sentinel-charter-literal-closure.md); offline contract + live lab theo runbook.
- **Tuần 1–3 (mentor reports):** [docs/reports/](docs/reports/index.md) — quét nền, chuẩn hóa + tri thức offline, agent phân tích JSONL (prose tiếng Việt bám bằng chứng). Sample: [docs/reports/artifacts/](docs/reports/artifacts/README.md).
- **Workbench:** product riêng; fixture/B0 readiness — xem workbench brief, **không** dùng làm bằng chứng Charter.

---

## Bắt đầu từ đúng cửa

### Charter (live)

| Nhu cầu | Điểm vào |
|---|---|
| Hợp đồng sản phẩm | [Charter brief](docs/product/sentinel-charter-brief.md), [as-built](docs/sentinel-six-week-as-built-architecture.md) |
| Thủ tục nghiệm thu live | [Live acceptance runbook](docs/operations/sentinel-live-acceptance-runbook.md) |
| Preflight không secret | [`scripts/sentinel-live-preflight.sh`](scripts/sentinel-live-preflight.sh) |
| Bật topology Compose | [`scripts/sentinel-charter-up.sh`](scripts/sentinel-charter-up.sh) (chỉ up, không phải một lần chạy Charter) |
| Chạy / resume / verify | [`scripts/sentinel-demo.sh`](scripts/sentinel-demo.sh) — `run`/`resume` cần credential + approval riêng máy operator |

### Workbench (riêng)

| Nhu cầu | Điểm vào |
|---|---|
| Ranh giới product | [Workbench brief](docs/product/sentinel-security-research-workbench.md) |
| UI + broker local | [`scripts/workbench-up.sh`](scripts/workbench-up.sh) |
| Preflight scanner fixture | [`scripts/workbench-scanner-preflight.sh`](scripts/workbench-scanner-preflight.sh) |
| Corpus host-local | [`scripts/workbench-corpus-acquire.py`](scripts/workbench-corpus-acquire.py), [`scripts/workbench-corpus-inventory.py`](scripts/workbench-corpus-inventory.py) |
| Demo / viability | [demo](docs/operations/sentinel-workbench-demo.md), [scanner viability](docs/operations/workbench-scanner-viability.md) |

### Lab dùng chung

| Nhu cầu | Điểm vào |
|---|---|
| Pin image | [`scanners/image-pins.env`](scanners/image-pins.env) |
| Scanner / redaction / lake | [scanners/README.md](scanners/README.md), [DefectDojo](infra/defectdojo/README.md) |
| RAG | [rag/README.md](rag/README.md) |
| Tài liệu & plan | [docs/README.md](docs/README.md), [plans/active](docs/plans/active/) |
| Site docs mentor | [website/README.md](website/README.md), smoke [`scripts/website-smoke-check.sh`](scripts/website-smoke-check.sh) |

---

## Proof nhanh: quét → che secret (không cần DefectDojo)

Cần Docker, `jq`, image pin public. **Không** cần credential lake.

```bash
(
  set -euo pipefail
  command -v jq >/dev/null || { echo "jq is required for redaction" >&2; exit 1; }
  workspace="$(mktemp -d)"
  trap 'rm -rf "$workspace"' EXIT
  source scanners/image-pins.env
  export IMAGE="$JUICE_SHOP_IMAGE" TRIVY_SCANNERS="secret,misconfig"
  sanitized_report="$(mktemp -t trivy.sanitized.XXXXXX.json)"
  ./scanners/run-trivy.sh "$workspace/trivy.raw.json"
  ./scanners/redact-report.sh trivy "$workspace/trivy.raw.json" "$sanitized_report"
  rm -rf "$workspace"
  trap - EXIT
  printf 'sanitized report: %s\n' "$sanitized_report"
)
```

`TRIVY_SCANNERS=secret,misconfig` tránh tải DB CVE. File raw chỉ nằm workspace tạm.

Import DefectDojo / `verify-lake.sh` là thao tác **có provision** — xem [infra/defectdojo/README.md](infra/defectdojo/README.md).

RAG store: schema tracked trong `infra/rag-store/`; volume rỗng khởi tạo từ schema — xem [rag/README.md](rag/README.md).

---

## Báo cáo tuần & agent

| Tuần | Báo cáo | Ý chính |
|---|---|---|
| 1 | [week-01](docs/reports/week-01.md) | App lab, quét đa tool, che secret, endpoint |
| 2 | [week-02](docs/reports/week-02.md) | Chuẩn hóa findings + tri thức offline |
| 3 | [week-03](docs/reports/week-03.md) | Agent JSONL; prose tiếng Việt từ field typed + knowledge |
| Sample | [artifacts](docs/reports/artifacts/README.md) | Aggregate + report mẫu (không secret) |

Site: https://vinsoc.manhquy.id.vn — HTML / Markdown / raw / [`llms.txt`](https://vinsoc.manhquy.id.vn/llms.txt).

Agent phân tích: `agent/week3_analysis.py` · prompt `agent/prompts/charter-system-prompt.md`.

---

## Tài liệu & lịch sử

Bản đồ đầy đủ: **[docs/README.md](docs/README.md)**.

- `docs/decisions/` — quyết định bền  
- `docs/plans/` — plan active/completed  
- `docs/journal/` — nhật ký kỹ thuật (không thay authority)  
- Chương trình 12 tuần / research cũ: **ngữ cảnh**, không phải contract hoàn thành 6 tuần hiện tại  

Quy trình agent trong repo: [docs/WORKFLOW.md](docs/WORKFLOW.md), [AGENTS.md](AGENTS.md).

---

## Đóng góp / agent

1. Đọc map product (README này + docs/README).  
2. Không trộn bằng chứng Charter ↔ Workbench.  
3. Không commit secret, raw scan, `infra/.env`.  
4. Thay đổi hợp đồng / an toàn → cập nhật brief + decision/tests tương ứng.  
5. Site docs: sửa `docs/reports/*` rồi `bash scripts/website-sync-docs.sh` (xem `website/README.md`).
