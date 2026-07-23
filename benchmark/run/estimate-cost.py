#!/usr/bin/env python3
"""Phase 4 pre-flight: scan a 50-test-case sample of OWASP Benchmark with Metis,
measure real cost/time via LiteLLM's per-key spend tracking, and extrapolate to a
FULL (2740 test case) x3 run at x1.5 safety margin, per the plan's validated
cost-approval gate (docs -- Validation Session 1, Q2). Does not run the full
benchmark; only measures and reports the estimate for user sign-off.

Run WITHOUT Metis indexing (--tools none): no working embeddings provider is
available this round (see runs/spike-engine-endpoint.md addendum). This changes
the underlying capability being measured (no cross-file context) but not the
per-file cost order of magnitude enough to invalidate a rough estimate - noted
in the report.
"""
from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import time
from pathlib import Path

BENCHMARK_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BENCHMARK_DIR.parent
TESTCODE_DIR = BENCHMARK_DIR / "targets/owasp-benchmark/src/main/java/org/owasp/benchmark/testcode"
EXPECTEDRESULTS = BENCHMARK_DIR / "targets/owasp-benchmark/expectedresults-1.2beta.csv"
METIS_BIN = BENCHMARK_DIR / "tools/arm-metis/.venv/bin/metis"
METIS_CONFIG = REPO_ROOT / "runs/spike-metis-config.yaml"  # reuses the Step-0 spike config (cheap-sast alias)

SAMPLE_SIZE = 50
FULL_SIZE_MULTIPLIER = 1.5  # per Validation Session 1: hard-stop ~= 1.5x extrapolation


def load_sample_test_cases(n: int) -> list[str]:
    names = []
    with open(EXPECTEDRESULTS, newline="") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            names.append(row[0])
            if len(names) >= n:
                break
    return names


def run_metis_on_file(java_path: Path, sarif_out: Path) -> tuple[float, bool]:
    start = time.time()
    result = subprocess.run(
        [
            str(METIS_BIN),
            "--config", str(METIS_CONFIG),
            "--codebase-path", str(TESTCODE_DIR),
            "--non-interactive",
            "--command", f"review_file {java_path}",
            "--tools", "none",
            "--output-file", str(sarif_out),
            "-q",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    elapsed = time.time() - start
    return elapsed, result.returncode == 0


def get_run_spend(base_url: str, virtual_key: str) -> float:
    """Spend for `virtual_key`, asked for by the key itself.

    /key/info with no query parameter reports on the key presenting the request, so
    the credential travels in the Authorization header only. Passing it as `?key=...`
    writes it verbatim into proxy access logs, which are themselves read during
    debugging - that is how a credential escapes an otherwise-contained harness.
    """
    import urllib.request

    req = urllib.request.Request(
        f"{base_url}/key/info",
        headers={"Authorization": f"Bearer {virtual_key}"},
    )
    with urllib.request.urlopen(req) as resp:
        payload = json.load(resp)
    info = payload.get("info", payload)
    return float(info.get("spend") or 0.0)


def main() -> int:
    # No master key needed: /key/info is asked by the virtual key itself, so the
    # admin credential never enters this process.
    virtual_key = os.environ.get("COST_ESTIMATE_VIRTUAL_KEY")
    if not virtual_key:
        print("Set COST_ESTIMATE_VIRTUAL_KEY (generate via scripts/generate-virtual-key.sh first)", file=sys.stderr)
        return 1
    base_url = os.environ.get("LITELLM_BASE_URL", "http://localhost:4000")

    spend_before = get_run_spend(base_url, virtual_key)

    test_cases = load_sample_test_cases(SAMPLE_SIZE)
    run_dir = REPO_ROOT / "runs" / "cost-estimate-50case"
    sarif_dir = run_dir / "sarif"
    sarif_dir.mkdir(parents=True, exist_ok=True)

    per_file_seconds: list[float] = []
    failures: list[str] = []
    wall_start = time.time()

    for name in test_cases:
        java_path = TESTCODE_DIR / f"{name}.java"
        sarif_out = sarif_dir / f"{name}.sarif"
        elapsed, ok = run_metis_on_file(java_path, sarif_out)
        per_file_seconds.append(elapsed)
        if not ok:
            failures.append(name)
        print(f"  {name}: {elapsed:.1f}s {'OK' if ok else 'FAILED'}", file=sys.stderr)

    wall_elapsed = time.time() - wall_start
    # LiteLLM's /key/info spend field is written asynchronously (background queue);
    # querying immediately after the last call can race ahead of the DB flush and
    # silently read a stale value (observed: read back 0.0 delta for a run that
    # really cost $0.014, confirmed only by re-querying minutes later). Poll with
    # a bounded wait for the value to change instead of trusting a single read.
    spend_after = spend_before
    for _ in range(30):
        spend_after = get_run_spend(base_url, virtual_key)
        if spend_after > spend_before:
            break
        time.sleep(2)
    sample_spend = spend_after - spend_before

    n = len(test_cases)
    full_n = 2740  # real row count in expectedresults-1.2beta.csv, x3 planned runs
    extrapolated_cost_1run = (sample_spend / n) * full_n if n else 0.0
    extrapolated_cost_3run = extrapolated_cost_1run * 3
    extrapolated_cost_with_margin = extrapolated_cost_3run * FULL_SIZE_MULTIPLIER
    extrapolated_wall_1run_seconds = (wall_elapsed / n) * full_n if n else 0.0

    report = {
        "sample_size": n,
        "failures": failures,
        "sample_spend_usd": sample_spend,
        "sample_wall_seconds": wall_elapsed,
        "avg_seconds_per_file": sum(per_file_seconds) / len(per_file_seconds) if per_file_seconds else 0,
        "extrapolated_full_2740_x3_runs_cost_usd": extrapolated_cost_3run,
        "extrapolated_full_2740_x3_runs_cost_with_1.5x_margin_usd": extrapolated_cost_with_margin,
        "extrapolated_full_1run_wall_seconds": extrapolated_wall_1run_seconds,
        "extrapolated_full_3run_wall_hours": extrapolated_wall_1run_seconds * 3 / 3600,
        "note": "Run WITHOUT Metis indexing (--tools none); no working embeddings provider this round.",
    }

    report_path = run_dir / "estimate-report.json"
    report_path.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
