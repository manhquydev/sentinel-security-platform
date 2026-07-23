#!/usr/bin/env python3
"""Qualitative WebGoat scan — no ground truth, no scoring.

OWASP Benchmark is synthetic: 2740 near-identical templated cases. WebGoat is
hand-written deliberately-vulnerable lessons that read like real application code,
and it ships fixed variants of several lessons beside the vulnerable ones
(ProfileUpload vs ProfileUploadFix, etc). That makes it a qualitative check the
benchmark cannot give: does the winning tier flag the vulnerable lesson and leave
its fixed sibling alone, on code that is not templated?

There is no expectedresults file, so this collects findings for narrative review
rather than computing precision/recall. Reuses the same Metis invocation and the
same per-scan usage accounting as the benchmark runner.

Usage: python3 scan-webgoat-qualitative.py --model sol --concurrency 5
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import os
from pathlib import Path

BENCHMARK_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BENCHMARK_DIR.parent
WEBGOAT_MAIN = BENCHMARK_DIR / "targets/webgoat-src/src/main/java/org/owasp/webgoat/lessons"
RESULTS_DIR = BENCHMARK_DIR / "results"

# Reuse the benchmark runner's scan primitives rather than re-implementing them, so
# the Metis invocation, redaction, per-scan usage dir and stall behavior are identical.
_spec = importlib.util.spec_from_file_location(
    "run_full_benchmark", Path(__file__).with_name("run-full-benchmark.py")
)
runner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runner)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("scan-webgoat")


def lesson_files() -> list[Path]:
    """Main (non-test) lesson .java files — the actual vulnerable/fixed code."""
    files = []
    for path in sorted(WEBGOAT_MAIN.rglob("*.java")):
        name = path.name
        if name.endswith(("Test.java", "package-info.java")):
            continue
        files.append(path)
    return files


def scan_lesson(path: Path, sarif_dir: Path, metis_env: dict) -> tuple[str, bool, str, dict]:
    """Scan one WebGoat file. Metis's --codebase-path is the lessons root so its
    relative anchors resolve; the SARIF name encodes the lesson-relative path."""
    rel = path.relative_to(WEBGOAT_MAIN)
    stem = str(rel.with_suffix("")).replace("/", "__")
    usage_dir = Path(metis_env["BENCHMARK_USAGE_ROOT"]) / stem
    usage_dir.mkdir(parents=True, exist_ok=True)
    env = {**metis_env, "METIS_USAGE_DIR": str(usage_dir)}
    sarif_out = sarif_dir / f"{stem}.sarif"
    import subprocess
    try:
        result = subprocess.run(
            [str(runner.METIS_BIN), "--config", metis_env["BENCHMARK_METIS_CONFIG"],
             "--codebase-path", str(WEBGOAT_MAIN), "--non-interactive",
             "--command", f"review_file {path}", "--tools", "none",
             "--output-file", str(sarif_out), "-q"],
            capture_output=True, text=True, timeout=180, cwd=str(BENCHMARK_DIR), env=env,
        )
        if result.returncode == 0 and sarif_out.exists():
            return (stem, True, "ok", runner.read_usage_tokens(usage_dir))
        err = runner.redact(result.stderr)[-300:] if result.stderr else f"exit={result.returncode}"
        return (stem, False, err, runner.read_usage_tokens(usage_dir))
    except Exception as e:  # noqa: BLE001 - record, never crash the whole pass
        return (stem, False, runner.redact(f"{type(e).__name__}: {e}"), {})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True, choices=runner.MODEL_TIERS)
    parser.add_argument("--concurrency", type=int, default=5)
    args = parser.parse_args()

    key_var = f"V0_{args.model.upper()}_RUN1_VIRTUAL_KEY"  # reuse the tier's run-1 key
    if key_var not in os.environ:
        logger.error("%s not set", key_var)
        return 2

    run_id = f"webgoat-{args.model}"
    metis_env = dict(os.environ)
    metis_env["METIS_VIRTUAL_KEY"] = os.environ[key_var]
    metis_env["BENCHMARK_METIS_CONFIG"] = str(BENCHMARK_DIR / "configs" / f"metis-{args.model}.yaml")
    metis_env["BENCHMARK_USAGE_ROOT"] = str(RESULTS_DIR / "usage" / run_id)

    out_dir = REPO_ROOT / "runs" / run_id
    sarif_dir = out_dir / "sarif"
    sarif_dir.mkdir(parents=True, exist_ok=True)

    files = lesson_files()
    logger.info("scanning %d WebGoat lesson files with %s", len(files), args.model)

    from concurrent.futures import ThreadPoolExecutor, as_completed
    findings_index, failed, tokens = {}, [], 0
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futs = {pool.submit(scan_lesson, f, sarif_dir, metis_env): f for f in files}
        for i, fut in enumerate(as_completed(futs), 1):
            stem, ok, info, tok = fut.result()
            tokens += tok.get("total_tokens", 0)
            if not ok:
                failed.append((stem, info))
                continue
            doc = json.loads((sarif_dir / f"{stem}.sarif").read_text())
            res = doc["runs"][0]["results"]
            findings_index[stem] = [
                {"cwe": r.get("properties", {}).get("cwe"),
                 "sev": r.get("properties", {}).get("severity"),
                 "msg": r["message"]["text"][:200]} for r in res
            ]
            if i % 25 == 0:
                logger.info("[%d/%d] %d tokens", i, len(files), tokens)

    summary = {
        "run_id": run_id, "model": args.model, "files_scanned": len(findings_index),
        "failed": failed, "total_tokens": tokens,
        "files_with_findings": sum(1 for v in findings_index.values() if v),
        "total_findings": sum(len(v) for v in findings_index.values()),
        "findings_by_file": findings_index,
    }
    (out_dir / "webgoat-findings.json").write_text(json.dumps(summary, indent=2))
    logger.info("done: %d/%d files flagged, %d findings, %d tokens, %d failed",
                summary["files_with_findings"], len(findings_index),
                summary["total_findings"], tokens, len(failed))
    print(json.dumps({k: summary[k] for k in
                      ("files_scanned", "files_with_findings", "total_findings", "total_tokens", "failed")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
