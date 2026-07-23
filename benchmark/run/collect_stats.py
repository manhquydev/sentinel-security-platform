#!/usr/bin/env python3
"""Aggregate one or more completed V0 runs into a scorecard: per-run + mean±std
Precision/Recall/F1 (LLM output isn't deterministic even at temp=0 - plan.md
decision #6 treats run-to-run variance as the primary uncertainty measure, with
Wilson CI as a secondary/per-run measure), per-category breakdown, and
CWE-scoped vs CWE-agnostic comparison. Refuses to call a run "FULL" if its
manifest doesn't show scanned_count == total_expected (completeness gate).

Scores either a router tier (--model sol|terra|gpt55) or the frozen DeepSeek
comparison arm (--model deepseek, the default, which reads the original
v0-metis-owasp-benchmark-run{N} directories and must keep reproducing
runs/scorecard-v0-final.json).

Usage: python3 collect_stats.py --model sol --runs 1 2 3
"""
from __future__ import annotations

import argparse
import datetime
import json
import math
import statistics
import sys
from pathlib import Path

BENCHMARK_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BENCHMARK_DIR.parent
EXPECTEDRESULTS = BENCHMARK_DIR / "targets/owasp-benchmark/expectedresults-1.2beta.csv"

sys.path.insert(0, str(BENCHMARK_DIR))
from findings.sarif_to_jsonl import convert_sarif_to_findings  # noqa: E402
from scoring.scorer import load_expectedresults, score_per_test_case  # noqa: E402
from scoring.stats import ConfusionMatrix, f1, precision, precision_wilson_ci, recall, recall_wilson_ci, youden_j  # noqa: E402


# The frozen DeepSeek arm predates the model dimension, so its directories and its
# recorded model string are hardcoded here rather than derived. Changing either would
# make runs/scorecard-v0-final.json unreproducible.
FROZEN_ARM = "deepseek"
ARM_MODEL_STRING = {FROZEN_ARM: "deepseek/deepseek-chat"}


def run_id_for(model: str, run_number: int) -> str:
    if model == FROZEN_ARM:
        return f"v0-metis-owasp-benchmark-run{run_number}"
    return f"v0-metis-owasp-{model}-run{run_number}"


def model_string_for(model: str) -> str:
    return ARM_MODEL_STRING.get(model, f"router:{model}")


def score_one_run(run_number: int, model: str) -> dict:
    run_dir = REPO_ROOT / "runs" / run_id_for(model, run_number)
    manifest_path = run_dir / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text())

    expected = load_expectedresults(str(EXPECTEDRESULTS))
    if not manifest["complete"]:
        raise RuntimeError(f"run {run_number} is not complete per its manifest - refusing a FULL verdict")
    if manifest["scanned_count"] != len(expected):
        raise RuntimeError(
            f"run {run_number}: scanned {manifest['scanned_count']} != expected {len(expected)} - completeness gate failed"
        )

    sarif_dir = run_dir / "sarif"
    all_findings = []
    for sarif_file in sorted(sarif_dir.glob("*.sarif")):
        sarif = json.loads(sarif_file.read_text())
        findings = convert_sarif_to_findings(
            sarif,
            sarif_ref=str(sarif_file),
            run_id=f"v0-metis-owasp-benchmark-run{run_number}",
            timestamp=manifest["recorded_at"],
            variant="V0",
            model=model_string_for(model),
            target="owasp-benchmark",
        )
        all_findings.extend(f.to_dict() for f in findings)

    result = score_per_test_case(expected, all_findings)

    def matrix_stats(cm: ConfusionMatrix) -> dict:
        return {
            "tp": cm.tp, "fp": cm.fp, "fn": cm.fn, "tn": cm.tn,
            "precision": precision(cm), "recall": recall(cm), "f1": f1(cm),
            "youden_j": youden_j(cm),
            "precision_wilson_ci": list(precision_wilson_ci(cm)),
            "recall_wilson_ci": list(recall_wilson_ci(cm)),
        }

    return {
        "run": run_number,
        "model": model,
        "manifest": manifest,
        "total_findings": len(all_findings),
        "unmatched_test_cases": result.unmatched_test_cases,
        "cwe_scoped": {cat: matrix_stats(cm) for cat, cm in result.cwe_scoped.items()},
        "cwe_agnostic": {cat: matrix_stats(cm) for cat, cm in result.cwe_agnostic.items()},
    }


def mean_std(values: list[float]) -> tuple[float, float]:
    if not values:
        return (float("nan"), float("nan"))
    if len(values) == 1:
        return (values[0], float("nan"))
    return (statistics.mean(values), statistics.stdev(values))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=FROZEN_ARM,
                        choices=[FROZEN_ARM, "sol", "terra", "gpt55"],
                        help="model tier to score; defaults to the frozen DeepSeek arm")
    parser.add_argument("--runs", type=int, nargs="+", required=True)
    args = parser.parse_args()

    per_run = [score_one_run(r, args.model) for r in args.runs]

    overall_precisions = [r["cwe_scoped"]["__overall__"]["precision"] for r in per_run]
    overall_recalls = [r["cwe_scoped"]["__overall__"]["recall"] for r in per_run]
    agnostic_precisions = [r["cwe_agnostic"]["__overall__"]["precision"] for r in per_run]

    p_mean, p_std = mean_std(overall_precisions)
    r_mean, r_std = mean_std(overall_recalls)
    ap_mean, ap_std = mean_std(agnostic_precisions)

    if p_mean >= 0.75:
        verdict = "production-viable (>=0.75)"
    elif p_mean >= 0.5:
        verdict = "viable if validation tuned (0.5-0.75, V1 candidate)"
    else:
        verdict = "not sufficient (<0.5, needs stronger judge or different engine)"

    scorecard = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "engine": "Metis",
        "model": model_string_for(args.model),
        "model_tier": args.model,
        "indexing": False,
        "indexing_caveat": "No working embeddings provider this round - Precision/Recall reflect Metis WITHOUT cross-file context, not its full capability.",
        "runs_included": args.runs,
        "cwe_scoped_precision_mean": p_mean,
        "cwe_scoped_precision_std": p_std,
        "cwe_scoped_recall_mean": r_mean,
        "cwe_scoped_recall_std": r_std,
        "cwe_agnostic_precision_mean": ap_mean,
        "cwe_agnostic_precision_std": ap_std,
        "precision_collapse_from_missing_cwe": ap_mean - p_mean if not (math.isnan(ap_mean) or math.isnan(p_mean)) else None,
        "verdict_precision_threshold": verdict,
        "per_run": per_run,
    }

    if args.model != FROZEN_ARM:
        # Measured through the proxy on all three tiers, 2026-07-22 (see
        # runs/spike-router-endpoint.md). Roughly two thirds of a typical per-file
        # request is the gateway's own prompt rather than the code under test.
        scorecard["gateway_prompt_caveat"] = (
            "Requests pass through the clawcmc router, which injects a fixed 3231-token "
            "system prompt into every call and is not under our control. These results "
            "measure the model PLUS that prompt; they are not attributable to the base "
            "model and are not comparable to a direct-API measurement of it."
        )
        scorecard["backing_model"] = "not observable"
        scorecard["backing_model_caveat"] = (
            "LiteLLM rewrites the response model field to the local alias, and Metis's "
            "totals.by_model records that alias too, so the provider's actual model never "
            "reaches us. Backing-model drift during a run cannot be detected - stated as a "
            "blind spot rather than covered by a check that would always pass."
        )
        scorecard["spend_usd"] = None
        scorecard["spend_unavailable_reason"] = (
            "LiteLLM has no pricing entry for the router's models and the router returns "
            "usage.cost: null. Cost is not comparable across arms; compare on P/R only."
        )
        scorecard["tokens"] = {
            key: sum((r["manifest"].get("tokens") or {}).get(key, 0) for r in per_run)
            for key in ("input_tokens", "output_tokens", "total_tokens")
        }

    out_dir = REPO_ROOT / "runs"
    out_path = out_dir / f"scorecard-{args.model}-runs-{'-'.join(map(str, args.runs))}.json"
    out_path.write_text(json.dumps(scorecard, indent=2, default=str))

    print(f"CWE-scoped Precision: {p_mean:.3f} ± {p_std if p_std==p_std else 0:.3f} (n={len(args.runs)} runs)")
    print(f"CWE-scoped Recall:    {r_mean:.3f} ± {r_std if r_std==r_std else 0:.3f}")
    print(f"CWE-agnostic Precision: {ap_mean:.3f} ± {ap_std if ap_std==ap_std else 0:.3f}")
    print(f"Verdict: {verdict}")
    print(f"Written to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
