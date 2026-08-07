---
title: "Tuần 2 — Chuẩn hóa và kho tri thức"
description: "Báo cáo Tuần 2: gộp cảnh báo và tra cứu offline"
---


Monorepo Sentinel. Bước tiếp sau Tuần 1: lấy file quét đã che secret, **chuẩn hóa**
về một cấu trúc chung có nguồn gốc (provenance) kiểm chứng được, và dựng **kho tri
thức** OWASP/công cụ để tra cứu **offline** (không gọi mạng, không gọi LLM).

> Nguồn narrative gốc: gói nộp Tuần 2 (2026-07-31).
> Adapter monorepo: `agent/normalize_week1_artifacts.py`.

## 1. Mục tiêu Tuần 2 em đã làm

Theo yêu cầu đồ án, Tuần 2 có hai phần: (a) gộp kết quả quét Tuần 1 thành định dạng
thống nhất, và (b) dựng kho tri thức bảo mật tra cứu được, có ví dụ SQL Injection và
XSS. Em làm đúng hai phần, giữ kỷ luật an toàn Tuần 1 — chỉ đọc bản đã che, che thêm
khi ghi ra, không đưa raw report vào gói bàn giao.

Điểm kỷ luật: adapter Tuần 2 **tách** khỏi normalizer Charter đầy đủ của đồ án lớn.
Nó chỉ nhận đúng ba file baseline Tuần 1, không nới lỏng đường Charter/CI “cho tiện”.

## 2. Kiến trúc

```
Artifact đã sanitize của Tuần 1
  ├── nuclei.san.jsonl (21)  ─┐
  ├── trivy.san.json   (4)   ─┼─► normalize_week1_artifacts.py ─► week1.aggregate.jsonl (36)
  └── semgrep.san.json (11)  ─┘     (+ manifest SHA-256)         week1.aggregate.manifest.json

Kho tri thức (offline)
  ├── corpus / examples (OWASP + tool docs + SQLi/XSS)  ─┐
  └── search-knowledge / retrieve path                    ─┴─► content + source + sha256
```

## 3. Kết quả chuẩn hóa (aggregate)

| Công cụ | Baseline Tuần 1 | Nhận (admitted) | Từ chối |
|---|---|---|---|
| Nuclei | 21 | 21 | 0 |
| Trivy | 4 | 4 | 0 |
| Semgrep | 11 | 11 | 0 |

**Tổng: 36 bản ghi** schema `week1-submission/v1`. Mỗi bản ghi giữ `finding_id` /
`source_id` truy ngược file gốc + digest, ví dụ:

```json
{
  "schema_version": "week1-submission/v1",
  "tool": "nuclei",
  "scanner": "DAST",
  "title": "Public Swagger API - Detect",
  "severity": "Info",
  "location": "path:/api-docs/swagger.json",
  "source_id": "week1-submission:nuclei:sha256:749fcb54…:item:1"
}
```

Digest input khớp monorepo `scanners/out` (Nuclei/Trivy/Semgrep như báo cáo Tuần 1).
Aggregate submission-era: SHA-256 file aggregate
`d7717e70088762525cfcc1708bd60d83bc0564da3828f0cf7a83b3a464f77094`.

## 4. Kho tri thức và tìm kiếm offline

Corpus cam kết OWASP Top 10 + tài liệu tool + ví dụ SQLi/XSS. Tra cứu offline trả
`source_ref` + `sha256` — không bịa nguồn, không sinh văn bản LLM.

Monorepo: corpus / retrieve under `rag/` (và test suite liên quan). Gói nộp Tuần 2
từng có `scripts/search-knowledge.py` — monorepo **không** ship script đó; dùng
adapter + tests dưới đây.

## 5. Cách chạy lại (monorepo)

```bash
# Adapter chuẩn hóa artifact Tuần 1 (flags xem --help)
python3 -m agent.normalize_week1_artifacts --help

# Kiểm chứng liên quan (khi deps/env sẵn)
python3 -m pytest tests/test_week3_aggregate_analysis.py -q
# hoặc suite agent/normalize tùy runner hiện hành
```

Gói nộp lịch sử có `run-week2-checks.sh` / `search-knowledge.py` — chỉ để đối chiếu
số liệu, **không** phải entrypoint monorepo.

## 6. Cấu trúc gói bàn giao (monorepo mapping)

| Thành phần | Path |
|---|---|
| Adapter + schema | `agent/normalize_week1_artifacts.py`, `agent/pii.py` |
| Input san | `scanners/out/*.san.*` |
| Aggregate (submission) | `artifacts/week1.aggregate.*` (gói Tuần 2) |
| Knowledge | `rag/` / charter corpus |
| Tests | `tests/` (aggregate / week2 / week3 related) |

Gói **không** chứa secret, raw scan, cấu hình LLM, hay claim “RAG live”.

## 7. Phạm vi và lựa chọn có chủ đích

- Adapter tách Charter: không nới normalizer lớn chỉ để gộp nhanh.
- Offline keyword search, không vector DB / LLM live.
- Giữ baseline 36 — không trộn scan mới (trôi theo thời điểm).

Đây là bằng chứng phạm vi **Tuần 2**, không phải xong chương trình sáu tuần.
