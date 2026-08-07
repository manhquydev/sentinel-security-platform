# Bản đồ tài liệu — Project Sentinel

Bắt đầu từ map nhỏ nhất. Chỉ mở material lịch sử / tương thích khi task thật sự cần.

Root [`README.md`](../README.md) là **cửa vào tiếng Việt** mô tả dự án và bảng điểm vào operator. File này là **mục lục docs** (WHERE), không lặp lại toàn bộ contract.

---

## Hai product

**Charter** và **Workbench** là hai product.  
Không dùng artifact Workbench làm bằng chứng nghiệm thu Charter; không dùng run Juice Shop Charter làm kết quả so sánh Workbench.

| Product | Authority | Điểm vào live / local |
|---|---|---|
| **Charter** | [Charter brief](product/sentinel-charter-brief.md), [as-built](sentinel-six-week-as-built-architecture.md) | `scripts/sentinel-live-preflight.sh` → `scripts/sentinel-charter-up.sh` → `scripts/sentinel-demo.sh` · [runbook live](operations/sentinel-live-acceptance-runbook.md) |
| **Workbench** | [Workbench brief](product/sentinel-security-research-workbench.md) | `scripts/workbench-up.sh`, preflight scanner, corpus acquire/inventory · [demo](operations/sentinel-workbench-demo.md), [viability](operations/workbench-scanner-viability.md) |

Pin scanner: [`scanners/image-pins.env`](../scanners/image-pins.env).

---

## Sentinel — đọc theo nhu cầu

### Hiểu dự án (WHY / ranh giới)

- [README gốc](../README.md) — mô tả đầy đủ bằng tiếng Việt  
- [Charter brief](product/sentinel-charter-brief.md) — hợp đồng sản phẩm công bố  
- [Kiến trúc as-built sáu tuần](sentinel-six-week-as-built-architecture.md) — luồng, tin cậy, giới hạn bằng chứng  
- [decisions/](decisions/) — quyết định bền  
- Charter assignment đầy đủ 6 tuần: local-only (`Project_Sentinel_6-week.md`, gitignore) — **không** nằm trên map public  

### Báo cáo tuần (mentor)

- [Mục lục báo cáo](reports/index.md) — Tuần 1–3  
- [Tuần 1](reports/week-01.md) · [Tuần 2](reports/week-02.md) · [Tuần 3](reports/week-03.md)  
- [Sample artifacts Tuần 3](reports/artifacts/README.md)  
- Site Starlight: [website/](../website/README.md) · https://vinsoc.manhquy.id.vn · [`/llms.txt`](https://vinsoc.manhquy.id.vn/llms.txt)  

### Vận hành

- [Runbook nghiệm thu live Charter](operations/sentinel-live-acceptance-runbook.md)  
- [Workbench demo](operations/sentinel-workbench-demo.md)  
- [Scanner viability (B0)](operations/workbench-scanner-viability.md)  
- [Claim checklist Workbench](operations/sentinel-workbench-claim-checklist.md)  

### Research / protocol (khi cần)

- [research-protocol.md](research-protocol.md)  
- [Workbench B3 preregistration](research/workbench-b3-preregistration.md)  
- [ai-sast-research-log.md](ai-sast-research-log.md) — lab notebook (stateful)  

### Plan & journal (stateful, không thay authority)

- [plans/active/](plans/active/) · [plans/completed/](plans/completed/) · [plans/reports/](plans/reports/)  
- [journal/](journal/) — nhật ký sai lầm / tiến trình  
- Templates: [decision](templates/decision.md), [exec-plan](templates/exec-plan.md)  

### Harness / workflow agent

- [WORKFLOW.md](WORKFLOW.md) — request → plan → validate → complete  
- [git-workflow.md](git-workflow.md) — ghi chú git lab  

---

## Cấu trúc lõi (Harness)

Các thư mục sau là khung làm việc agent/con người; **không** thay README product hay code:

| Thư mục / file | Vai trò |
|---|---|
| `product/` | Hành vi product đã chấp nhận |
| `decisions/` | Quyết định lâu dài |
| `plans/` | Kế hoạch và báo cáo thực thi |
| `journal/` | Lịch sử cách làm (không phải status hiện tại) |
| `operations/` | Runbook / demo / viability |
| `reports/` | Báo cáo tuần mentor |
| `templates/` | Mẫu decision / plan |

Truth thực thi: code, tests, CI, runtime. Docs chỉ trỏ và giữ WHY.

---

## Index upstream (không cài mặc định)

Material tương thích / lịch sử Harness nằm ngoài cài đặt mặc định — xem repo [repository-harness](https://github.com/hoangnb24/repository-harness) khi làm CLI/control-plane tùy chọn.

---

## Cập nhật docs

- Sửa **authority** nhỏ nhất bị ảnh hưởng.  
- Không copy inventory/command list từ script vào nhiều file — link owner.  
- Báo cáo tuần: sửa `docs/reports/*` rồi sync site (`scripts/website-sync-docs.sh`).  
- Không đưa secret / raw scan / assignment cá nhân lên map public.  
