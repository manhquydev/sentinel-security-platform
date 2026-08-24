#!/usr/bin/env python3
"""Publish a Week-3 report from the committed Week-1 aggregate.

Offline and deterministic: stub retrieve + stub model (confidence only).
Does not call LiteLLM, Kong, or Docker. Not a live AI-quality score.

    PYTHONPATH=. .venv/bin/python scripts/analyze-week1-aggregate.py
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent.report import KnowledgeItem
from agent.week3_analysis import Retrieval, analyze

ROOT = Path(__file__).resolve().parents[1]
AGG = ROOT / "artifacts" / "week1.aggregate.jsonl"
MAN = ROOT / "artifacts" / "week1.aggregate.manifest.json"
OUT = ROOT / "docs" / "reports" / "artifacts" / "week1-aggregate-report.jsonl"
META = ROOT / "docs" / "reports" / "artifacts" / "week1-aggregate-report.manifest.json"


def retrieval(query: str) -> Retrieval:
    q = query.lower()
    if "trivy" in q:
        content = (
            "SCA: cap nhat goi phu thuoc, kiem tra advisory CVE va go bo ban de ton."
        )
        ref = "OWASP | https://owasp.org/www-community/vulnerabilities/ | sha256:" + "e" * 64
    elif "semgrep" in q:
        content = (
            "SAST: dung parameterized query/ORM, khong noi chuoi SQL/user input."
        )
        ref = "OWASP | https://owasp.org/www-community/attacks/SQL_Injection | sha256:" + "e" * 64
    else:
        content = (
            "DAST: them header bao mat phu hop (CSP, X-Content-Type-Options) "
            "va ra soat cau hinh HTTP."
        )
        ref = "OWASP | https://owasp.org/www-project-secure-headers/ | sha256:" + "e" * 64
    return Retrieval(
        "d" * 64,
        hashlib.sha256(query.encode()).hexdigest(),
        (KnowledgeItem(content, ref),),
    )


def model(facts: list[dict], _knowledge: list[dict]) -> str:
    return json.dumps(
        {
            "enrichments": [
                {
                    "finding_id": fact["finding_id"],
                    "explanation_mode": "scanner-observation",
                    "remediation_mode": "review-documented-fix",
                    "confidence": "medium",
                }
                for fact in facts
            ]
        }
    )


def main() -> None:
    if not AGG.is_file() or not MAN.is_file():
        raise SystemExit("committed week-1 aggregate/manifest missing")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    if OUT.exists():
        OUT.unlink()
    result = analyze(AGG, MAN, OUT, retrieve=retrieval, model_call=model)
    if result.failure is not None:
        raise SystemExit(f"analyze failed: {result.failure}")
    OUT.chmod(0o644)
    rows = OUT.read_text(encoding="utf-8").splitlines()
    META.write_text(
        json.dumps(
            {
                "schema_version": "week1-aggregate-report/v1",
                "mode": "offline-deterministic",
                "live_run": False,
                "input_aggregate": "artifacts/week1.aggregate.jsonl",
                "input_manifest": "artifacts/week1.aggregate.manifest.json",
                "input_aggregate_sha256": hashlib.sha256(AGG.read_bytes()).hexdigest(),
                "report": "docs/reports/artifacts/week1-aggregate-report.jsonl",
                "report_sha256": hashlib.sha256(OUT.read_bytes()).hexdigest(),
                "report_rows": len(rows),
                "note": (
                    "Prose is code-owned from typed Week-1 fields; model stub "
                    "only supplies confidence. Not a live LiteLLM score."
                ),
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    print("report_rows", len(rows))
    print("report", OUT.relative_to(ROOT))
    print("ok")


if __name__ == "__main__":
    main()
