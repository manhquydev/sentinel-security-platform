#!/usr/bin/env python3
"""Generate secret-free Week-3 sample aggregate + report for mentor docs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent.report import KnowledgeItem
from agent.week3_analysis import AggregateFinding, Retrieval, _canonical_finding_id, analyze

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "reports" / "artifacts"


def source(tool: str, digest: str, item: int) -> str:
    return f"week1-submission:{tool}:sha256:{digest}:item:{item}"


def record(
    tool: str,
    digest: str,
    item: int,
    *,
    title: str,
    scanner: str,
    location: str,
    severity: str = "Medium",
    evidence: list[str] | None = None,
) -> dict:
    value = {
        "schema_version": "week1-submission/v1",
        "provenance_kind": "week1-submission",
        "finding_id": "week1-finding:" + ("0" * 64),
        "source_id": source(tool, digest, item),
        "source_ids": [source(tool, digest, item)],
        "tool": tool,
        "scanner": scanner,
        "title": title,
        "severity": severity,
        "location": location,
        "evidence": evidence or [f"rule={tool}-{item}"],
    }
    typed = AggregateFinding.model_validate(value)
    value["finding_id"] = _canonical_finding_id(typed)
    return value


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    nuclei_d = "a" * 64
    trivy_d = "b" * 64
    semgrep_d = "c" * 64
    records = [
        record(
            "nuclei",
            nuclei_d,
            1,
            title="Missing Security Header",
            scanner="DAST",
            location="path:/rest/products",
            evidence=["template-id=header"],
        ),
        record(
            "nuclei",
            nuclei_d,
            2,
            title="Missing Security Header",
            scanner="DAST",
            location="path:/rest/products",
            evidence=["template-id=header"],
        ),
        record(
            "trivy",
            trivy_d,
            1,
            title="Known Dependency Issue",
            scanner="SCA",
            location=f"trivy:{trivy_d[:16]}:item:1",
        ),
        record(
            "semgrep",
            semgrep_d,
            1,
            title="Unsafe Query Rule",
            scanner="SAST",
            location=f"semgrep:{semgrep_d[:16]}:item:1",
        ),
    ]

    agg = OUT / "week3-sample.aggregate.jsonl"
    data = b"".join(
        json.dumps(row, sort_keys=True, ensure_ascii=False).encode() + b"\n" for row in records
    )
    agg.write_bytes(data)

    filenames = {
        "nuclei": "scanners/out/nuclei.san.jsonl",
        "trivy": "scanners/out/trivy.san.json",
        "semgrep": "scanners/out/semgrep.san.json",
    }
    inputs = []
    per_tool = {}
    for tool in ("nuclei", "trivy", "semgrep"):
        own = [row for row in records if row["tool"] == tool]
        digest = own[0]["source_id"].split(":")[3]
        count = len(own)
        counts = {"input": count, "admitted": count, "refused": 0}
        per_tool[tool] = counts
        inputs.append(
            {
                "tool": tool,
                "filename": filenames[tool],
                "sha256": digest,
                "source_kind": "week1-submission",
                "input_count": count,
                "admitted_count": count,
                "refused_count": 0,
                "counts": counts,
            }
        )
    total = len(records)
    manifest = {
        "schema_version": "week1-submission/v1",
        "source_kind": "week1-submission",
        "aggregate_count": total,
        "aggregate_sha256": hashlib.sha256(data).hexdigest(),
        "inputs": inputs,
        "counts": {"input": total, "admitted": total, "refused": 0, "per_tool": per_tool},
    }
    man_path = OUT / "week3-sample.aggregate.manifest.json"
    man_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def retrieval(query: str) -> Retrieval:
        q = query.lower()
        if "trivy" in q or "dependency" in q:
            content = (
                "SCA: cap nhat goi phu thuoc, kiem tra advisory CVE va go bo ban de ton."
            )
            ref = "OWASP | https://owasp.org/www-community/vulnerabilities/ | sha256:" + "e" * 64
        elif "semgrep" in q or "query" in q:
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

    out = OUT / "week3-sample-report.jsonl"
    if out.exists():
        out.unlink()
    result = analyze(agg, man_path, out, retrieve=retrieval, model_call=model)
    if result.failure is not None:
        raise SystemExit(f"analyze failed: {result.failure}")
    out.chmod(0o644)

    (OUT / "README.md").write_text(
        "# Sample artifacts — Week 3 analysis\n\n"
        "Synthetic, secret-free sample for the Security Analysis Agent.\n\n"
        "| File | Role |\n"
        "|------|------|\n"
        "| `week3-sample.aggregate.jsonl` | 4 typed findings (2 nuclei dup + trivy + semgrep) |\n"
        "| `week3-sample.aggregate.manifest.json` | Manifest with `aggregate_sha256` |\n"
        "| `week3-sample-report.jsonl` | Agent output `week3-analysis/v1` (3 rows after grouping) |\n\n"
        "Regenerate:\n\n```bash\npython3 scripts/generate-week3-sample-artifacts.py\n```\n\n"
        "Lab samples only — not live Juice Shop output.\n",
        encoding="utf-8",
    )

    first = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
    print("report_lines", sum(1 for _ in out.open(encoding="utf-8")))
    print("explanation_prefix", first["explanation"][:100])
    print("ok")


if __name__ == "__main__":
    main()
