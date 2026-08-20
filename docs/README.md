# Bản đồ tài liệu — Project Sentinel

Bắt đầu từ map nhỏ nhất. Chỉ mở material lịch sử / tương thích khi task thật sự cần.

Root [`README.md`](../README.md) là **cửa vào dự án** (vấn đề, luồng, cách chạy). File này là **mục lục docs** (WHERE), không lặp lại README.

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

- [README gốc](../README.md) — giới thiệu, luồng, quick start  
- [Charter brief](product/sentinel-charter-brief.md) — hợp đồng sản phẩm công bố  
- [Kiến trúc as-built sáu tuần](sentinel-six-week-as-built-architecture.md) — luồng, tin cậy, giới hạn bằng chứng  
- [decisions/](decisions/) — quyết định bền  
- Charter assignment đầy đủ 6 tuần: local-only (`Project_Sentinel_6-week.md`, gitignore) — **không** nằm trên map public  

### Báo cáo tuần (mentor)

- [Mục lục báo cáo](reports/index.md) — Tuần 1–6
- [Tuần 1](reports/week-01.md) · [Tuần 2](reports/week-02.md) · [Tuần 3](reports/week-03.md) · [Tuần 4](reports/week-04.md) · [Tuần 5](reports/week-05.md) · [Tuần 6](reports/week-06.md)
- [Sample artifacts Tuần 3](reports/artifacts/README.md)  
- Site Starlight: [website/](../website/README.md) · https://vinsoc.manhquy.io.vn · https://vinsoc.manhquy.id.vn · [`/llms.txt`](https://vinsoc.manhquy.io.vn/llms.txt)  
- App live (DefectDojo, sau Cloudflare Access): https://app.vinsoc.manhquy.io.vn — xem [hướng dẫn dùng](operations/live-deployment-guide.md)  

### Vận hành

- [**Hướng dẫn dùng & test bản deploy production**](operations/live-deployment-guide.md) — bắt đầu ở đây nếu mở `app.vinsoc` mà chưa rõ cách dùng  
- [Trạng thái deploy (Worker + GCP VM)](deployment.md)  
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

- Grader install là `requirements.txt` ở root qua `.venv`; báo cáo tuần sync site qua `scripts/website-sync-docs.sh`.
- Sửa **authority** nhỏ nhất bị ảnh hưởng.  
- Không copy inventory/command list từ script vào nhiều file — link owner.  
- Báo cáo tuần: sửa `docs/reports/*` rồi sync site (`scripts/website-sync-docs.sh`).  
- Không đưa secret / raw scan / assignment cá nhân lên map public.  
