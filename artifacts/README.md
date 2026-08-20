# Week-2 aggregate

This directory is the committed home of the Week-2 deliverable:

- `week1.aggregate.jsonl`
- `week1.aggregate.manifest.json`

Those files are **not** present yet. Generation was blocked because
`.venv/bin/python -m agent.normalize_week1_artifacts --help` failed with
`ModuleNotFoundError: No module named 'pydantic'`. Do not invent the 36
records by hand.

After `pydantic` is available in `.venv`, generate from the committed
sanitized Week-1 scans (`scanners/out/*.san.*`) with:

```bash
.venv/bin/python -m agent.normalize_week1_artifacts \
  --submission-dir . \
  --output artifacts/week1.aggregate.jsonl \
  --manifest artifacts/week1.aggregate.manifest.json
```

`--submission-dir` is the repository root so the importer can read the
canonical paths `scanners/out/nuclei.san.jsonl`,
`scanners/out/trivy.san.json`, and `scanners/out/semgrep.san.json`.
