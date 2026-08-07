---
title: "Báo cáo tuần — nguồn Markdown"
description: "Nguồn Markdown đầy đủ — đọc / sao chép"
---

Trang HTML: [Báo cáo tuần](/reports/) · [Tải raw](/raw/reports/index.md) · [llms.txt](https://vinsoc.manhquy.id.vn/llms.txt)

Nội dung dưới đây là **toàn bộ file Markdown** trong monorepo (`docs/reports/index.md`), không qua bước render HTML.

````markdown
# Báo cáo tuần — Project Sentinel

Đây là bộ **báo cáo theo tuần** của đồ án 6 tuần Project Sentinel (VinUni × VinSOC),
lưu trong monorepo và hiển thị trên site mentor.

Đọc lần lượt theo tuần. Mỗi báo cáo gồm: mục tiêu đã làm, sơ đồ kiến trúc, số liệu
đo được, lệnh chạy lại, và phần **phạm vi có chủ đích** (nói rõ việc gì cố ý không
làm).

| Tuần | HTML | Markdown | Raw |
|---|---|---|---|
| 1 | [Quét bảo mật nền](/reports/week-01/) | [xem MD](/reports/week-01/markdown/) | [raw](/raw/reports/week-01.md) |
| 2 | [Chuẩn hóa và kho tri thức](/reports/week-02/) | [xem MD](/reports/week-02/markdown/) | [raw](/raw/reports/week-02.md) |
| 3 | [Agent phân tích bảo mật](/reports/week-03/) | [xem MD](/reports/week-03/markdown/) | [raw](/raw/reports/week-03.md) |

**Tiến độ hiện tại:** đã có báo cáo **3 / 6** tuần (Tuần 1–3). Tuần 4–6 (gateway,
guardrails, demo cuối) chưa thuộc phạm vi bộ báo cáo này.

**Agent / máy đọc:** dùng [`/llms.txt`](/llms.txt) để lấy mục lục HTML + Markdown + raw.

**Cách đọc bằng chứng:** chỉ tin đường dẫn file và mã băm (digest) được ghi trong
từng báo cáo. File quét thô (`.raw.*`) không được đưa lên site. Văn bản assignment
đầy đủ và kịch bản trình bày cá nhân chỉ giữ local, không đăng public.
````
