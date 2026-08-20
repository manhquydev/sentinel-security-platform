# Week-2 aggregate

This directory is the committed home of the Week-2 deliverable ("tệp dữ liệu
tổng hợp"):

- `week1.aggregate.jsonl` — 36 normalized findings (nuclei 21 / trivy 4 /
  semgrep 11), schema `week1-submission/v1`.
- `week1.aggregate.manifest.json` — binds the aggregate + its canonical inputs
  by SHA-256.

These files **are committed** and are the durable Week-2 evidence a grader can
open. The aggregate SHA-256 is
`d7717e70088762525cfcc1708bd60d83bc0564da3828f0cf7a83b3a464f77094`, matching
`docs/reports/week-02.md`.

## Regenerating

The `.san.*` scanner inputs are **local, gitignored working files** under
`scanners/out/` (see `.gitignore`), not committed — only this aggregate is. To
reproduce the aggregate you need those sanitized scans present locally plus
`pydantic` (in the full overlay `requirements-full.txt`, not the slim grader
`requirements.txt`), then run from the repository root:

```bash
.venv/bin/python -m agent.normalize_week1_artifacts \
  --submission-dir . \
  --output artifacts/week1.aggregate.jsonl \
  --manifest artifacts/week1.aggregate.manifest.json
```

`--submission-dir` is the repository root so the importer can read the canonical
paths `scanners/out/nuclei.san.jsonl`, `scanners/out/trivy.san.json`, and
`scanners/out/semgrep.san.json`. Re-running on the same inputs is deterministic
(identical SHA-256).
