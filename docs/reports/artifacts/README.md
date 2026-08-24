# Sample artifacts: Week 3 analysis

Sample synthetic, không secret, dùng cho demo/report tuần 3.

| File | Role |
|------|------|
| `week3-sample.aggregate.jsonl` | 4 typed findings (2 nuclei dup + trivy + semgrep) |
| `week3-sample.aggregate.manifest.json` | Manifest with `aggregate_sha256` |
| `week3-sample-report.jsonl` | Agent output `week3-analysis/v1` (3 rows after grouping) |

Regenerate:

```bash
python3 scripts/generate-week3-sample-artifacts.py
```

Lab samples only, not live Juice Shop output.

## Week-1 aggregate → report (handover)

Offline deterministic report from the committed 36-finding aggregate.
Not a live LiteLLM score.

| File | Role |
|------|------|
| `week1-aggregate-report.jsonl` | `week3-analysis/v1` rows from `artifacts/week1.aggregate.jsonl` |
| `week1-aggregate-report.manifest.json` | Input/output digests, `live_run: false` |

```bash
PYTHONPATH=. .venv/bin/python scripts/analyze-week1-aggregate.py
```
