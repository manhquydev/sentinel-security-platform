# Public demo fixtures

Static mentor-facing demo data for the Week 3 Security Analysis Agent.

## Layout

| Path | Source |
|------|--------|
| `week-03/aggregate.jsonl` | `docs/reports/artifacts/week3-sample.aggregate.jsonl` |
| `week-03/manifest.json` | `docs/reports/artifacts/week3-sample.aggregate.manifest.json` |
| `week-03/report.jsonl` | `docs/reports/artifacts/week3-sample-report.jsonl` |
| `week-03/fail-closed.json` | Hand-authored CLI shape (`status`/`failure`) |
| `week-03/meta.json` | Counts, honesty copy, sha256 pins |

## Refresh

```bash
# After regenerating samples at repo root:
PYTHONPATH=. python3 scripts/generate-week3-sample-artifacts.py
cp docs/reports/artifacts/week3-sample.aggregate.jsonl website/public/demo/week-03/aggregate.jsonl
cp docs/reports/artifacts/week3-sample.aggregate.manifest.json website/public/demo/week-03/manifest.json
cp docs/reports/artifacts/week3-sample-report.jsonl website/public/demo/week-03/report.jsonl
# Recompute sha256 fields in meta.json
```

These files are **not** wiped by `website-sync-docs.py`. Do not put secrets or raw `.raw.*` scanner dumps here.

## Integrity

`meta.json` holds `sha256` pins for `aggregate.jsonl`, `report.jsonl`, and `manifest.json`.  
The browser demo verifies pins when Web Crypto is available.  
`scripts/website-smoke-check.sh` re-checks pins via curl against the live base URL.

## Mentor UI (Week 3)

- Group map: before (aggregate rows) / after (findings, “Gộp N→1”)
- Detail: primary fields first; digests under “Bằng chứng kỹ thuật”
- Fail-closed: empty findings list + CLI `status`/`failure`
- Modes: “Chạy thành công” | “Fail-closed”
