#!/usr/bin/env python3
"""FULL run: scan all 2740 real OWASP Benchmark test cases with Metis through
LiteLLM, one of 3 independent runs per model tier (LLM output isn't deterministic
even at temp=0). Resumable: a test case whose SARIF is already on disk and carries
evidence of a real LLM call is skipped, so an interrupted run can restart and pick
up where it left off.

Run identity is (model tier, run number), and that pair reaches the run directory,
the Metis config, and the virtual key. Two tiers at the same run number must never
share a credential: per-key attribution is the only per-arm accounting available,
since LiteLLM cannot price the router's models and the router reports cost: null.

Enforces a completeness gate before scoring: never emits a "FULL" scorecard from a
truncated run.

Usage: python3 run-full-benchmark.py --model sol --run 1 --concurrency 5
"""
from __future__ import annotations

import argparse
import csv
import datetime
import json
import logging
import os
import re
import subprocess
import sys
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

BENCHMARK_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BENCHMARK_DIR.parent
TESTCODE_DIR = BENCHMARK_DIR / "targets/owasp-benchmark/src/main/java/org/owasp/benchmark/testcode"
EXPECTEDRESULTS = BENCHMARK_DIR / "targets/owasp-benchmark/expectedresults-1.2beta.csv"
METIS_BIN = BENCHMARK_DIR / "tools/arm-metis/.venv/bin/metis"
RESULTS_DIR = BENCHMARK_DIR / "results"

MODEL_TIERS = ("sol", "terra", "gpt55")

MAX_RETRIES = 2
RETRY_BACKOFF_SECONDS = 5

# In-flight futures per worker. Submitting all 2740 tasks upfront makes a run
# unabortable: ThreadPoolExecutor drains its whole queue on shutdown, so nothing
# raised while collecting results can stop the remaining work.
INFLIGHT_PER_WORKER = 2

# Mid-run guard: abort after this many consecutive scans that consumed zero tokens.
#
# The signal is tokens, not findings. A zero-FINDINGS window is normal and expected —
# expectedresults-1.2beta.csv contains a 41-long run of consecutive `false` cases, and a
# model that correctly declines to flag them looks exactly like a dead provider to a
# findings-based guard. A zero-TOKEN window has no benign explanation: every successful
# call bills at least the router's ~3.2k-token gateway prompt. That makes the threshold
# safe to keep small, and immune to how well-calibrated the model is.
ZERO_TOKEN_ABORT_WINDOW = 10

# Stall watchdog. Observed on sol run 1 (2026-07-22): every worker blocked in a network
# read for 49.6 minutes with zero scans completing, then recovered on its own. The
# per-scan subprocess timeout did not bound it - the workers were inside a call that
# never returned and never tripped it - so the only reliable signal is the absence of
# completions at the loop level.
#
# SCOPE, precisely: this stops further SUBMISSION and cancels queued work. It cannot
# unblock a thread already inside a hung syscall - those are still joined when the pool
# shuts down, so a hang of duration D still costs D of wall time. What it bounds is
# additional spend and the size of the blast radius, not elapsed time. Anything needing
# a hard wall-clock bound has to kill the subprocess, which subprocess.run's own timeout
# is supposed to do and demonstrably did not here.
#
# A healthy scan takes ~12s median and ~38s at the observed maximum, so several minutes
# of total silence across every worker is already far outside normal operation.
STALL_TIMEOUT_SECONDS = 300
STALL_ABORT_AFTER = 3

SPEND_UNAVAILABLE_REASON = (
    "LiteLLM has no pricing entry for the router's models and the router itself returns "
    "usage.cost: null, so /key/info spend is structurally 0. Recorded as null rather than "
    "0.0 because a real zero-spend run is the exact signature of the run-3 silent-failure "
    "incident, and the two must not be indistinguishable."
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("run-full-benchmark")


def load_all_test_cases() -> list[str]:
    names = []
    with open(EXPECTEDRESULTS, newline="") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            names.append(row[0])
    return names


SECRET_PATTERN = re.compile(r"sk-[A-Za-z0-9_\-]{8,}")


def redact(text: str) -> str:
    """Strip credential-shaped tokens before any tool output reaches an artifact.

    failed_cases is written verbatim into run-manifest.json, and Metis surfaces
    upstream auth errors that can quote the key that was rejected.
    """
    return SECRET_PATTERN.sub("sk-<redacted>", text)


def sarif_findings(path: Path) -> list | None:
    """Findings from a Metis SARIF, or None if the file is not one.

    Structural validity means more than "parses as JSON": the old check accepted
    any parseable file, which is how a directory of provider-failure artifacts
    passed resume as completed work.
    """
    try:
        doc = json.loads(path.read_text())
        run = doc["runs"][0]
        results = run["results"]
        if not isinstance(results, list) or not run["tool"]["driver"]["name"]:
            return None
        return results
    except (json.JSONDecodeError, OSError, KeyError, IndexError, TypeError):
        return None


def trustworthy_prior_scans(sarif_dir: Path, usage_root: Path | None = None) -> set[str]:
    """Names whose existing SARIF may be accepted as already scanned.

    An individual zero-finding SARIF carries no evidence either way: a correct scan of
    a benign test case and a scan whose LLM call failed produce the same document. In
    the DeepSeek round, run 1 legitimately produced 131 zero-finding files while run 3
    produced 2740 of them after the provider stopped answering.

    The reliable evidence is per-scan TOKEN spend, not the findings. Every successful
    call bills at least the router's gateway prompt, so a scan with a usage record
    showing nonzero tokens provably reached the provider whatever its findings say.

    A directory-level rule ("one finding vouches for the batch") was tried and is
    wrong: when a provider dies mid-run, the zero-finding files written afterwards sit
    beside earlier files that do carry findings, so every poisoned artifact is
    vouched for by its healthy predecessors - and the harness's own abort path leaves
    exactly that mixture on disk. That is the run-3 failure with extra steps.

    Falls back to the directory-level heuristic only when no usage records exist at
    all (e.g. the frozen DeepSeek arm, scanned before per-scan usage dirs existed).
    """
    existing = sorted(sarif_dir.glob("*.sarif"))
    valid = {p.stem: findings for p in existing if (findings := sarif_findings(p)) is not None}
    corrupt = len(existing) - len(valid)
    if corrupt:
        logger.warning("%d existing SARIF files are structurally invalid, re-scanning them", corrupt)
    if not valid:
        return set()

    if usage_root is not None and usage_root.exists():
        proven = {
            name for name in valid
            if read_usage_tokens(usage_root / name)["total_tokens"] > 0
        }
        rejected = len(valid) - len(proven)
        if rejected:
            logger.warning(
                "%d of %d existing SARIFs have no token record - the scan never reached "
                "the provider, re-scanning them", rejected, len(valid),
            )
        return proven

    # No usage records to consult: fall back to the directory-level signal.
    if not any(valid.values()):
        logger.warning(
            "all %d existing SARIF files in %s are zero-finding and no usage records "
            "exist: no evidence any LLM call succeeded, re-scanning the whole set",
            len(valid), sarif_dir,
        )
        return set()
    return set(valid)


def read_run_tokens(usage_root: Path) -> dict[str, int]:
    """Token totals for an ENTIRE run, summed across every per-scan usage directory.

    Must not be derived from the scans this invocation happened to execute. A resumed
    run re-writes the manifest, and a per-invocation total silently drops everything
    the earlier invocation did: sol run 1 resumed 244 cases and under-reported by
    1,274,319 tokens (2.98%), which was enough to invert the published
    token-efficiency ranking across the three arms.

    The per-scan directories are the durable record; the manifest is a view of them.
    """
    totals = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    if not usage_root.exists():
        return totals
    for scan_dir in usage_root.iterdir():
        # The preflight canary is a harness self-check, not a scan of a test case.
        if not scan_dir.is_dir() or scan_dir.name == "_preflight_canary":
            continue
        for key, value in read_usage_tokens(scan_dir).items():
            totals[key] += value
    return totals


def read_usage_tokens(usage_dir: Path) -> dict[str, int]:
    """Token totals from the usage files Metis wrote for one scan.

    Each scan gets its own usage directory, so this is exact per-scan attribution
    with no race: the alternative — diffing a shared directory around a subprocess
    call — misattributes under concurrency, and attributing by mtime across the
    6000+ pre-existing files is worse still.
    """
    totals = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    for path in usage_dir.glob("metis_usage_*.json"):
        try:
            recorded = json.loads(path.read_text()).get("totals", {})
        except (json.JSONDecodeError, OSError):
            continue
        for key in totals:
            totals[key] += int(recorded.get(key) or 0)
    return totals


def scan_one(name: str, sarif_dir: Path, metis_env: dict[str, str]) -> tuple[str, bool, str, dict[str, int]]:
    sarif_out = sarif_dir / f"{name}.sarif"
    java_path = TESTCODE_DIR / f"{name}.java"
    config = Path(metis_env["BENCHMARK_METIS_CONFIG"])
    usage_dir = Path(metis_env["BENCHMARK_USAGE_ROOT"]) / name
    usage_dir.mkdir(parents=True, exist_ok=True)
    # Metis resolves its usage directory relative to the CWD unless METIS_USAGE_DIR
    # pins it. Scoping it per scan is what makes the token total attributable to this
    # file, which is what the mid-run guard reads.
    env = {**metis_env, "METIS_USAGE_DIR": str(usage_dir)}

    last_error = ""
    for attempt in range(1, MAX_RETRIES + 2):
        try:
            result = subprocess.run(
                [
                    str(METIS_BIN),
                    "--config", str(config),
                    "--codebase-path", str(TESTCODE_DIR),
                    "--non-interactive",
                    "--command", f"review_file {java_path}",
                    "--tools", "none",
                    "--output-file", str(sarif_out),
                    "-q",
                ],
                capture_output=True,
                text=True,
                timeout=180,
                cwd=str(BENCHMARK_DIR),
                env=env,
            )
            if result.returncode == 0 and sarif_out.exists():
                return (name, True, "ok", read_usage_tokens(usage_dir))
            last_error = redact(result.stderr)[-500:] if result.stderr else f"exit={result.returncode}"
        except subprocess.TimeoutExpired:
            last_error = "timeout"
        except Exception as e:
            last_error = redact(f"{type(e).__name__}: {e}")

        if attempt <= MAX_RETRIES:
            time.sleep(RETRY_BACKOFF_SECONDS * attempt)

    return (name, False, last_error, read_usage_tokens(usage_dir))


def zero_token_guard(window: int = ZERO_TOKEN_ABORT_WINDOW):
    """Abort once `window` consecutive scans have consumed zero tokens.

    Zero tokens means no call reached the provider. Metis swallows provider errors
    and writes a valid, empty SARIF, so without this a dead provider produces a
    complete-looking run of 2740 zero-finding files — which is exactly what happened
    on run 3 and cost 1.4 hours.

    Deliberately not a zero-findings guard: see ZERO_TOKEN_ABORT_WINDOW.
    """
    def guard(executed: int, failed: list, recent_tokens: list[int]) -> str | None:
        if len(recent_tokens) < window:
            return None
        if any(recent_tokens[-window:]):
            return None
        return (
            f"{window} consecutive scans consumed 0 tokens - no call is reaching the "
            f"provider. Metis reports success and writes empty SARIF when the provider "
            f"errors, so the run would otherwise look complete."
        )
    # run_scans reads this to decide how many samples to retain. Without it the buffer
    # is trimmed to the module default and a wider guard can never fill its window,
    # leaving it permanently disarmed.
    guard.window = window
    return guard


def run_scans(
    names: list[str],
    sarif_dir: Path,
    metis_env: dict[str, str],
    concurrency: int,
    should_abort=None,
) -> tuple[int, list[tuple[str, str]], str | None, dict[str, int]]:
    """Scan `names`, keeping only a bounded window of work in flight.

    Returns (executed, failed, abort_reason, tokens). `should_abort(executed, failed,
    recent_tokens)` is consulted after each batch of completions and returns a reason
    to stop or None to continue; on abort the runner stops submitting and cancels
    whatever has not started, so the remaining queue is not drained.
    """
    guard_window = getattr(should_abort, "window", ZERO_TOKEN_ABORT_WINDOW)
    pending = iter(names)
    inflight: dict = {}
    failed: list[tuple[str, str]] = []
    recent_tokens: list[int] = []
    tokens = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    executed = 0
    abort_reason: str | None = None
    total = len(names)
    window = max(1, concurrency * INFLIGHT_PER_WORKER)

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        def top_up() -> None:
            while len(inflight) < window:
                name = next(pending, None)
                if name is None:
                    return
                inflight[pool.submit(scan_one, name, sarif_dir, metis_env)] = name

        top_up()
        stalled_intervals = 0
        while inflight:
            completed, _ = wait(list(inflight), return_when=FIRST_COMPLETED,
                                timeout=STALL_TIMEOUT_SECONDS)
            if not completed:
                # Nothing finished anywhere for a whole interval. Report it rather than
                # sitting silent, and give up after enough of them: a run frozen for
                # this long is not making progress that is worth waiting for.
                stalled_intervals += 1
                logger.warning(
                    "no scan completed in %ds (%d/%d intervals, %d in flight) - provider "
                    "or proxy appears stalled",
                    STALL_TIMEOUT_SECONDS, stalled_intervals, STALL_ABORT_AFTER, len(inflight),
                )
                if stalled_intervals >= STALL_ABORT_AFTER and abort_reason is None:
                    abort_reason = (
                        f"no scan completed in {STALL_TIMEOUT_SECONDS * stalled_intervals}s; "
                        f"stopped submitting rather than spending further on a stalled "
                        f"provider. Threads already blocked are still joined, so this bounds "
                        f"spend rather than wall time. Resume with the same command - "
                        f"completed scans are preserved."
                    )
                    logger.error(abort_reason)
                    for future in [f for f in inflight if f.cancel()]:
                        inflight.pop(future, None)
                continue
            stalled_intervals = 0

            for future in completed:
                inflight.pop(future, None)
                name, ok, info, scan_tokens = future.result()
                executed += 1
                for key in tokens:
                    tokens[key] += scan_tokens.get(key, 0)
                recent_tokens.append(scan_tokens.get("total_tokens", 0))
                # Keep the full window the guard asked for. Trimming to a module
                # constant while the guard compares its own window silently disables
                # any guard configured wider than the constant.
                del recent_tokens[:-max(ZERO_TOKEN_ABORT_WINDOW, guard_window)]
                if not ok:
                    failed.append((name, info))
                    logger.warning("[%d/%d] %s FAILED: %s", executed, total, name, info)
                elif executed % 50 == 0 or executed == total:
                    logger.info(
                        "[%d/%d] progress, %d failed, %d tokens so far",
                        executed, total, len(failed), tokens["total_tokens"],
                    )

            if abort_reason is None and should_abort is not None:
                abort_reason = should_abort(executed, failed, recent_tokens)
                if abort_reason:
                    logger.error("aborting run after %d scans: %s", executed, abort_reason)

            if abort_reason is None:
                top_up()
            else:
                for future in [f for f in inflight if f.cancel()]:
                    inflight.pop(future, None)

    return executed, failed, abort_reason, tokens


def preflight_canary(metis_env: dict[str, str]) -> None:
    """Metis silently swallows LLM API errors (e.g. DeepSeek "Insufficient
    Balance") and reports "no issues" with 0 SARIF results instead of failing -
    exit code 0, output file written, looks identical to a real clean scan. Real
    incident: an entire 2740-file run (run 3, 2026-07-21) passed every per-file
    check and only showed 0 findings + $0 spend across ALL files once inspected
    after the fact, wasting ~1.4h. Catch this in seconds instead of hours by
    running one real call first and checking Metis's own token-usage file for a
    nonzero total_tokens, which does reflect the underlying failure."""
    canary_usage_dir = Path(metis_env["BENCHMARK_USAGE_ROOT"]) / "_preflight_canary"
    canary_usage_dir.mkdir(parents=True, exist_ok=True)
    for stale in canary_usage_dir.glob("metis_usage_*.json"):
        stale.unlink()
    metis_env = {**metis_env, "METIS_USAGE_DIR": str(canary_usage_dir)}

    canary_out = RESULTS_DIR / "_preflight_canary.sarif"
    canary_java = TESTCODE_DIR / "BenchmarkTest00001.java"
    result = subprocess.run(
        [
            str(METIS_BIN),
            "--config", str(metis_env["BENCHMARK_METIS_CONFIG"]),
            "--codebase-path", str(TESTCODE_DIR),
            "--non-interactive",
            "--command", f"review_file {canary_java}",
            "--tools", "none",
            "--output-file", str(canary_out),
            "-q",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(BENCHMARK_DIR),
        env=metis_env,
    )
    if result.returncode != 0:
        logger.error("preflight canary call failed outright: %s", redact(result.stderr)[-500:])
        raise SystemExit(1)

    if not list(canary_usage_dir.glob("metis_usage_*.json")):
        logger.error("preflight canary: no usage file written, cannot verify the call actually worked")
        raise SystemExit(1)
    total_tokens = read_usage_tokens(canary_usage_dir)["total_tokens"]
    if total_tokens == 0:
        logger.error(
            "preflight canary: real API call used 0 tokens - almost certainly a silently-swallowed "
            "provider error (e.g. an auth rejection or an exhausted balance). Check `docker logs "
            "litellm-proxy --since 2m` for the real error before running the full scan. Aborting."
        )
        raise SystemExit(1)
    logger.info("preflight canary OK (%d tokens)", total_tokens)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True, choices=MODEL_TIERS)
    parser.add_argument("--run", type=int, required=True, choices=[1, 2, 3])
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument(
        "--limit", type=int, default=0,
        help="scan at most N outstanding cases then stop (smoke test). The run is "
             "recorded INCOMPLETE, which is accurate - the scans themselves are real "
             "and a later full run resumes them.")
    args = parser.parse_args()

    # The model dimension must reach the credential, not just the run directory: two
    # tiers at the same run number sharing one key re-creates the run-1 attribution bug
    # across both arms at once, and per-key attribution is the only per-arm accounting
    # that still works here.
    key_var = f"V0_{args.model.upper()}_RUN{args.run}_VIRTUAL_KEY"
    try:
        virtual_key = os.environ[key_var]
    except KeyError:
        logger.error("%s is not set - provision keys with scripts/provision-benchmark-keys.sh", key_var)
        return 2

    config = BENCHMARK_DIR / "configs" / f"metis-{args.model}.yaml"
    if not config.exists():
        logger.error("missing Metis config for tier %s: %s", args.model, config)
        return 2

    # The Metis config's llm_provider.api_key_env is the fixed string
    # "METIS_VIRTUAL_KEY" - alias it to this run's own key so subprocess calls bill
    # against this (tier, run), not whatever that name happened to hold before. Real
    # bug in run 1: all cost landed on a leftover spike key.
    run_id = f"v0-metis-owasp-{args.model}-run{args.run}"
    metis_env = dict(os.environ)
    metis_env["METIS_VIRTUAL_KEY"] = virtual_key
    metis_env["BENCHMARK_METIS_CONFIG"] = str(config)
    metis_env["BENCHMARK_USAGE_ROOT"] = str(RESULTS_DIR / "usage" / run_id)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    preflight_canary(metis_env)

    run_dir = REPO_ROOT / "runs" / run_id
    sarif_dir = run_dir / "sarif"
    sarif_dir.mkdir(parents=True, exist_ok=True)

    all_cases = load_all_test_cases()
    total = len(all_cases)
    already_done = trustworthy_prior_scans(sarif_dir, Path(metis_env["BENCHMARK_USAGE_ROOT"]))
    todo = [name for name in all_cases if name not in already_done]
    if already_done:
        logger.info("resuming: %d cases already scanned, %d to go", len(already_done), len(todo))
    if args.limit:
        todo = todo[:args.limit]
        logger.warning("--limit %d: smoke test, this run cannot be complete", args.limit)

    wall_start = time.time()
    executed, failed, abort_reason, tokens = run_scans(
        todo, sarif_dir, metis_env, args.concurrency, should_abort=zero_token_guard()
    )
    wall_elapsed = time.time() - wall_start
    run_tokens = read_run_tokens(Path(metis_env["BENCHMARK_USAGE_ROOT"]))

    # Completeness gate: never call it FULL from a truncated run.
    scanned = sorted(p.stem for p in sarif_dir.glob("*.sarif"))
    # --limit deliberately scans a subset; such a run can never be complete even if
    # the directory happens to be full from earlier invocations.
    complete = (
        len(scanned) == total and not failed and abort_reason is None and not args.limit
    )

    # No network call between the scan finishing and the manifest landing: a run's
    # record must not be lost because a lookup hung or the proxy went away.
    manifest = {
        "run": args.run,
        "model": args.model,
        "model_alias": f"sast-{args.model}",
        "run_id": run_id,
        "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_expected": total,
        "scanned_count": len(scanned),
        "executed_count": executed,
        "resumed_count": len(already_done),
        "failed_count": len(failed),
        "failed_cases": failed,
        "aborted_reason": abort_reason,
        "complete": complete,
        "tokens": run_tokens,
        "tokens_this_invocation": tokens,
        "tokens_note": (
            "`tokens` covers the WHOLE run, summed across every per-scan usage directory, "
            "so a resumed run still reports what the earlier invocation spent. "
            "`tokens_this_invocation` is only what this process executed."
        ),
        "spend_usd": None,
        "spend_unavailable_reason": SPEND_UNAVAILABLE_REASON,
        "backing_model": "not observable",
        "backing_model_note": (
            "LiteLLM rewrites the response `model` to the alias on every success path, and "
            "Metis's totals.by_model records that alias too. The router's own value never "
            "reaches the client, and where it was visible it was identical across tiers. "
            "Declared unobservable rather than detected by a check that always passes."
        ),
        "wall_seconds": wall_elapsed,
        "concurrency": args.concurrency,
        "limit": args.limit or None,
        "indexing": False,
    }
    (run_dir / "run-manifest.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest, indent=2))

    if not complete:
        logger.error(
            "%s INCOMPLETE (%d/%d scanned, %d failed%s) - not eligible for a FULL verdict",
            run_id, len(scanned), total, len(failed),
            f", aborted: {abort_reason}" if abort_reason else "",
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
