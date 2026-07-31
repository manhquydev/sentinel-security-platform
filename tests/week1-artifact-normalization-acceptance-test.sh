#!/usr/bin/env bash
# Direct, content-safe acceptance against a separately supplied Week-1 submission.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/rag/.venv/bin/python"

if [[ -z "${WEEK1_SUBMISSION_DIR:-}" ]]; then
  echo "WEEK1_SUBMISSION_DIR must name the Week-1 submission directory" >&2
  exit 2
fi
if [[ ! -d "$WEEK1_SUBMISSION_DIR" ]]; then
  echo "WEEK1_SUBMISSION_DIR is not a directory" >&2
  exit 2
fi
if [[ ! -x "$PY" ]]; then
  echo "missing venv at $PY" >&2
  exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
OUTPUT="$WORK/week1.aggregate.jsonl"
MANIFEST="$WORK/week1.aggregate.manifest.json"

PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" "$PY" -m agent.normalize_week1_artifacts \
  --submission-dir "$WEEK1_SUBMISSION_DIR" \
  --output "$OUTPUT" \
  --manifest-output "$MANIFEST"

PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" "$PY" - "$WEEK1_SUBMISSION_DIR" "$OUTPUT" "$MANIFEST" <<'PY'
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

from pydantic import ValidationError

from agent.charter_contracts import NormalizedFinding

submission, output, manifest_path = map(Path, sys.argv[1:])
required = (
    ("scanners/out/nuclei.san.jsonl", "nuclei", 21),
    ("scanners/out/trivy.san.json", "trivy", 4),
    ("scanners/out/semgrep.san.json", "semgrep", 11),
)
assert output.is_file() and manifest_path.is_file()
assert stat.S_IMODE(output.stat().st_mode) == 0o600
assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o600
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
assert manifest["schema_version"] == "week1-submission/v1"
assert manifest["source_kind"] == "week1-submission"
assert manifest["aggregate_count"] == 36
assert [entry["filename"] for entry in manifest["inputs"]] == [item[0] for item in required]
by_name = {entry["filename"]: entry for entry in manifest["inputs"]}
for filename, tool, count in required:
    source = submission / filename
    assert source.is_file() and not source.is_symlink()
    entry = by_name[filename]
    assert entry["source_kind"] == "week1-submission"
    assert entry["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert (entry["input_count"], entry["admitted_count"], entry["refused_count"]) == (count, count, 0)

records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
assert len(records) == 36
counts = {tool: sum(record["tool"] == tool for record in records) for _, tool, _ in required}
assert counts == {tool: count for _, tool, count in required}
source_ids = set()
for record in records:
    assert record["schema_version"] == "week1-submission/v1"
    assert record["provenance_kind"] == "week1-submission"
    assert len(record["source_ids"]) == 1
    source_id = record["source_ids"][0]
    assert source_id.startswith(f"week1-submission:{record['tool']}:sha256:")
    assert ":item:" in source_id
    assert source_id not in source_ids
    source_ids.add(source_id)
    assert "127.0.0.1" not in record["location"]
    assert "?" not in record["location"]
    assert "#" not in record["location"]
    try:
        NormalizedFinding.model_validate(record)
    except ValidationError:
        pass
    else:
        raise AssertionError("Week-1 compatibility record was accepted as a Charter finding")

assert len(source_ids) == 36
PY

echo "week1 artifact normalization acceptance: PASS"
