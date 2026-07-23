"""Per-test-case (category-based) scorer for OWASP BenchmarkJava, per
docs/benchmark-pre-plan-decisions.md + plan.md red-team finding #3: each
test-case is ONE unit (not one per finding), and a hit is decided by whether
the reported category matches the test-case's expected category - not by raw
CWE-int equality. Reports both a CWE-scoped and a CWE-agnostic variant so a
finding missing a machine-readable CWE doesn't silently become an invisible FN
(plan.md red-team finding #17/schema caveat)."""
from __future__ import annotations

import csv
import json
import logging
from dataclasses import dataclass, field

from .cwe_category_map import cwe_to_category
from .stats import ConfusionMatrix

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ExpectedCase:
    category: str
    real: bool
    cwe: int


def load_expectedresults(path: str) -> dict[str, ExpectedCase]:
    """Parses the real OWASP BenchmarkJava expectedresults CSV: a '#'-prefixed
    header comment line, then rows 'test name,category,real vulnerability,cwe'."""
    cases: dict[str, ExpectedCase] = {}
    with open(path, newline="") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            name, category, real_str, cwe_str = row[0], row[1], row[2], row[3]
            cases[name] = ExpectedCase(category=category, real=real_str.strip().lower() == "true", cwe=int(cwe_str))
    return cases


def load_findings_jsonl(path: str) -> list[dict]:
    findings = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                findings.append(json.loads(line))
    return findings


@dataclass
class ScoreResult:
    cwe_scoped: dict[str, ConfusionMatrix]  # key: category, plus "__overall__"
    cwe_agnostic: dict[str, ConfusionMatrix]
    unmatched_test_cases: list[str] = field(default_factory=list)  # findings on a test_case not in expectedresults


def score_per_test_case(expected: dict[str, ExpectedCase], findings: list[dict]) -> ScoreResult:
    findings_by_test_case: dict[str, list[dict]] = {}
    for f in findings:
        test_case = f.get("target_test_case")
        if test_case is None:
            continue
        if test_case not in expected:
            logger.warning("finding references unknown test case %r, skipping", test_case)
            continue
        findings_by_test_case.setdefault(test_case, []).append(f)

    scoped_counts: dict[str, dict[str, int]] = {}
    agnostic_counts: dict[str, dict[str, int]] = {}

    def bump(counts: dict[str, dict[str, int]], category: str, bucket: str) -> None:
        for key in (category, "__overall__"):
            counts.setdefault(key, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
            counts[key][bucket] += 1

    for test_case, expected_case in expected.items():
        case_findings = findings_by_test_case.get(test_case, [])

        # CWE-agnostic: any finding at all on this test case counts as "reported".
        reported_agnostic = len(case_findings) > 0

        # CWE-scoped: only counts if at least one finding's cwe maps to this test
        # case's expected category (matching by category, not raw cwe equality).
        reported_scoped = any(cwe_to_category(f.get("cwe")) == expected_case.category for f in case_findings)

        if expected_case.real:
            bump(scoped_counts, expected_case.category, "tp" if reported_scoped else "fn")
            bump(agnostic_counts, expected_case.category, "tp" if reported_agnostic else "fn")
        else:
            bump(scoped_counts, expected_case.category, "fp" if reported_scoped else "tn")
            bump(agnostic_counts, expected_case.category, "fp" if reported_agnostic else "tn")

    unmatched = sorted(
        {f["target_test_case"] for f in findings if f.get("target_test_case") and f["target_test_case"] not in expected}
    )

    def to_matrices(counts: dict[str, dict[str, int]]) -> dict[str, ConfusionMatrix]:
        return {k: ConfusionMatrix(tp=v["tp"], fp=v["fp"], fn=v["fn"], tn=v["tn"]) for k, v in counts.items()}

    return ScoreResult(
        cwe_scoped=to_matrices(scoped_counts),
        cwe_agnostic=to_matrices(agnostic_counts),
        unmatched_test_cases=unmatched,
    )
