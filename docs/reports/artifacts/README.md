# Sample artifacts — Week 3 analysis

Synthetic, secret-free sample for the Security Analysis Agent.

| File | Role |
|------|------|
| `week3-sample.aggregate.jsonl` | 4 typed findings (2 nuclei dup + trivy + semgrep) |
| `week3-sample.aggregate.manifest.json` | Manifest with `aggregate_sha256` |
| `week3-sample-report.jsonl` | Agent output `week3-analysis/v1` (3 rows after grouping) |

Regenerate:

```bash
python3 scripts/generate-week3-sample-artifacts.py
```

Lab samples only — not live Juice Shop output.
