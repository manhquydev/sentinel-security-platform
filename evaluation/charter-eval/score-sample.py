#!/usr/bin/env python3
"""Score committed Week-3 sample artifacts against Charter gold. Not a live run.

``result-report.py evaluate --run-dir`` needs a private 0600 current-run directory
(manifest, typed 1.0 JSONL, request outcome, artifact-bindings). The committed
Week-3 sample is ``week3-analysis/v1`` / ``week1-submission/v1`` and has no
request or manifest, so the official evaluator cannot consume it.

This script reuses the official ``_matches`` / TP-FP-FN-TN rules and writes a
labeled sample / dry-run scorecard. A live scored run remains operator-gated
(``scripts/sentinel-demo.sh`` + ``result-report.py evaluate``).
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SAMPLE_REPORT = ROOT / "docs/reports/artifacts/week3-sample-report.jsonl"
SAMPLE_NORMALIZED = ROOT / "docs/reports/artifacts/week3-sample.aggregate.jsonl"
CASES = HERE / "cases.json"
GOLD = HERE / "gold.json"
OUTPUT = HERE / "charter-evaluation.json"
OFFICIAL = HERE / "result-report.py"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_official():
    spec = importlib.util.spec_from_file_location("charter_result_report", OFFICIAL)
    if spec is None or spec.loader is None:
        raise SystemExit("could not load evaluation/charter-eval/result-report.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise SystemExit(f"sample line is not an object: {path.name}")
        records.append(value)
    if not records:
        raise SystemExit(f"sample is empty: {path}")
    return records


def _score(official: Any, cases: list[dict[str, Any]], gold: dict[str, Any],
           normalized: list[dict[str, Any]], report: list[dict[str, Any]],
           request: dict[str, Any]) -> tuple[dict[str, int], list[dict[str, Any]]]:
    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    analyses: list[dict[str, Any]] = []
    for case in cases:
        expected = gold["expected"][case["case_id"]]
        matched = official._case_match(case, expected, {}, request, normalized, report)
        if case["truth"] == "positive":
            bucket = "TP" if matched else "FN"
        else:
            bucket = "FP" if matched else "TN"
        counts[bucket.lower()] += 1
        analyses.append({
            "case_id": case["case_id"],
            "artifact": case["artifact"],
            "truth": case["truth"],
            "outcome": bucket,
            "correct": bucket in {"TP", "TN"},
            "analysis": (
                "reviewer expectation matched the committed sample"
                if matched else
                "reviewer expectation did not match the committed sample"
            ),
            "expected": expected,
        })
    return counts, analyses


def main() -> int:
    official = _load_official()
    cases, gold = official._review_inputs(CASES, GOLD)
    normalized = _jsonl(SAMPLE_NORMALIZED)
    report = _jsonl(SAMPLE_REPORT)
    counts, analyses = _score(official, cases, gold, normalized, report, {})
    payload = {
        "case_analysis": analyses,
        "confusion": counts,
        "improvement_proposals": gold["improvement_proposals"],
        "inputs": {
            "cases_sha256": _sha256(CASES),
            "gold_sha256": _sha256(GOLD),
            "normalized": str(SAMPLE_NORMALIZED.relative_to(ROOT)),
            "normalized_sha256": _sha256(SAMPLE_NORMALIZED),
            "report": str(SAMPLE_REPORT.relative_to(ROOT)),
            "report_sha256": _sha256(SAMPLE_REPORT),
            "request": None,
        },
        "limitations": [
            "NOT A GRADE / NOT LIVE ACCEPTANCE: confusion counts are a "
            "sample-dry-run of committed week-3 artifacts against reviewer-owned "
            "gold IDs that do not match those artifacts. Official live scorer was "
            "not run. Do not read this table as AI quality.",
        ] + list(gold["limitations"]) + [
            "This file is a sample / dry-run scorecard, not a live Charter acceptance result.",
            "A live scored run is operator-gated: complete scripts/sentinel-demo.sh then "
            "evaluation/charter-eval/result-report.py evaluate --run-dir RUN.",
        ],
        "live_run": False,
        "mentor_summary": (
            "This file is a sample-dry-run (live_run=false), not a live AI quality "
            "or Charter acceptance score. Gold IDs do not match the committed week-3 "
            "sample; official result-report.py evaluate was not run."
        ),
        "mode": "sample-dry-run",
        "official_evaluator": "evaluation/charter-eval/result-report.py",
        "official_evaluator_status": "not-run-operator-gated",
        "reason_official_evaluator_not_used": (
            "result-report.py evaluate requires a private 0600 current-run directory "
            "with a completed charter manifest, typed 1.0 normalized/report JSONL, "
            "request outcome, and artifact-bindings. The committed Week-3 sample is "
            "week3-analysis/v1 and has no request or manifest."
        ),
        "reproduce": ".venv/bin/python evaluation/charter-eval/score-sample.py",
        "reviewer": gold["reviewer"],
        "schema_version": "charter-eval-sample-dry-run/v1",
    }
    OUTPUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("SAMPLE-DRY-RUN: written JSON is not live Charter acceptance.", file=sys.stderr)
    print(json.dumps({"confusion": counts, "output": str(OUTPUT.relative_to(ROOT))}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
