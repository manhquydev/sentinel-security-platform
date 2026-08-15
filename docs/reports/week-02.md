# Project Sentinel: Báo cáo Tuần 2

Tuần 2 em lấy bản quét đã che secret, gộp một schema, rồi dựng kho tri thức
tra offline (không mạng, không gọi LLM).

Gói nộp 2026-07-31. Code gộp: `agent/normalize_week1_artifacts.py`.

## 1. Việc em đã làm

1. Gộp Nuclei / Trivy / Semgrep tuần 1 thành aggregate có provenance.
2. Corpus OWASP + ví dụ SQLi/XSS, search offline.

Vẫn chỉ đọc file `.san.*`, không đưa raw vào gói bàn giao. Adapter tuần 2 không
đi qua normalizer Charter lớn; chỉ ba file baseline tuần 1.

## 2. Luồng

```
Artifact sanitized tuần 1
  ├── nuclei.san.jsonl (21)
  ├── trivy.san.json   (4)
  └── semgrep.san.json (11)
           │
           ▼
  normalize_week1_artifacts.py
           │
           ├── week1.aggregate.jsonl (36)
           └── week1.aggregate.manifest.json (SHA-256)

Kho tri thức offline
  corpus / examples  →  content + source + sha256
```

## 3. Kết quả gộp

| Công cụ | Baseline tuần 1 | Nhận | Từ chối |
|---|---|---|---|
| Nuclei | 21 | 21 | 0 |
| Trivy | 4 | 4 | 0 |
| Semgrep | 11 | 11 | 0 |

Tổng **36** bản ghi schema `week1-submission/v1`. Mỗi dòng có `finding_id` /
`source_id` truy ngược file + digest. Ví dụ:

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

Digest input khớp `scanners/out` như báo cáo tuần 1. SHA-256 file aggregate
(submission-era):
`d7717e70088762525cfcc1708bd60d83bc0564da3828f0cf7a83b3a464f77094`.

## 4. Kho tri thức

Corpus: OWASP Top 10, docs tool, ví dụ SQLi/XSS. Kết quả search có `source_ref`
và `sha256`.

Trong monorepo: `rag/` + test liên quan. Gói tuần 2 từng có
`scripts/search-knowledge.py`; monorepo hiện không ship script đó, dùng adapter
và test.

## 5. Chạy lại

```bash
python3 -m agent.normalize_week1_artifacts --help

# khi env đủ deps
python3 -m pytest tests/test_week3_aggregate_analysis.py -q
```

`run-week2-checks.sh` / `search-knowledge.py` trong gói cũ chỉ để đối chiếu số
liệu, không phải entrypoint monorepo hiện tại.

## 6. Map file trong monorepo

| Thành phần | Path |
|---|---|
| Adapter + schema | `agent/normalize_week1_artifacts.py`, `agent/pii.py` |
| Input san | `scanners/out/*.san.*` |
| Aggregate (gói nộp) | `artifacts/week1.aggregate.*` |
| Knowledge | `rag/` |
| Tests | `tests/` (aggregate / week2 / week3) |

Gói không chứa secret, raw scan, hay cấu hình LLM.

## 7. Việc em chưa làm tuần này

- Chưa gộp qua normalizer Charter lớn.
- Chưa vector DB hay LLM live.
- Giữ 36 finding baseline; không trộn scan mới (số sẽ trôi theo ngày quét).
