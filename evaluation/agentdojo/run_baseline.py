#!/usr/bin/env python3
"""Run a bounded, static AgentDojo indirect-prompt-injection baseline against a minimal
scaffold agent that calls the LLM exclusively through the Sentinel gateway.

Read evaluation/agentdojo/README.md before running or citing this. In short: this number
describes the scaffold agent defined in sentinel_pipeline.py, not Sentinel; the gateway
ships no injection detector by design (docs/decisions/0006-...); and AgentDojo's default
attack corpus is static, which published work shows overstates robustness.

Before scoring an attack, this runner first probes every injection task in the chosen
suite standalone (as its own goal, unattacked, no user task) and only feeds injection
tasks with standalone_utility == True into the attack matrix. AgentDojo's own
`injection_task.security()` check is what "standalone utility" means here: can this
scaffold execute the injected goal at all when it is the only instruction and nothing is
defending? An injection task the scaffold cannot complete unattacked cannot produce a
meaningful attack-success-rate contribution either way - a 0 there is true by
construction, not evidence the attack was blocked. See the `selection` block in every
result artifact for which tasks were considered, which were viable, and which were used.

Usage:
    python3 evaluation/agentdojo/run_baseline.py --help
    python3 evaluation/agentdojo/run_baseline.py --suite banking --max-user-tasks 3 \\
        --max-injection-tasks 2
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import openai

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_pipeline import (  # noqa: E402
    GENERIC_IMPORTANT_INSTRUCTIONS_ATTACK_NAME,
    SentinelOpenAILLM,
)

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message  # noqa: E402
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage  # noqa: E402
from agentdojo.agent_pipeline.tool_execution import (  # noqa: E402
    ToolsExecutionLoop,
    ToolsExecutor,
    tool_result_to_str,
)
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.benchmark import benchmark_suite_with_injections  # noqa: E402
from agentdojo.logging import OutputLogger  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite, get_suites  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_GATEWAY_BASE_URL = "http://127.0.0.1:4000"
DEFAULT_GATEWAY_KEY_ENV = "LITELLM_MASTER_KEY"

# Only the "sast-sol" alias has a config-documented, real-call-verified cost mapping (see
# infra/litellm/config.yaml, the model_list entry for sast-sol, dated 2026-07-23): LiteLLM's
# cost map matches `cx/gpt-5.6-sol` to the public `gpt-5.6-sol` list price of $5/$30 per 1M
# prompt/completion tokens after stripping the `cx/` prefix, and a real call's recorded
# spend matched that mapping exactly. No other alias in this gateway has that verification,
# so cost projection is only offered for sast-sol; other aliases report token counts with no
# derived dollar figure rather than inventing one.
KNOWN_PRICE_PER_MILLION = {
    "sast-sol": {
        "prompt_usd": 5.0,
        "completion_usd": 30.0,
        "basis": (
            "LiteLLM's bundled cost map entry for gpt-5.6-sol, matched after stripping the "
            "cx/ prefix; confirmed against one real call's recorded spend on 2026-07-23 "
            "(see infra/litellm/config.yaml). This is the backing tier's public list price, "
            "not a reconciled invoice from this router."
        ),
    }
}

ALL_V1_SUITE_SIZES = {
    # suite_name: (user_task_count, injection_task_count), read from the installed
    # agentdojo v1 suites. Used only to state what a full run across every default suite
    # would cost, never to run one.
    "workspace": (40, 6),
    "travel": (20, 7),
    "banking": (16, 9),
    "slack": (21, 5),
}


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Static AgentDojo indirect-prompt-injection baseline for a minimal scaffold "
            "agent behind the Sentinel gateway. Undefended baseline, static attack corpus, "
            "bounded task subset. See evaluation/agentdojo/README.md before citing a result."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--suite",
        default="banking",
        choices=sorted(get_suites("v1").keys()),
        help="AgentDojo v1 task suite to run against (banking is the smallest: 16 user tasks, 9 injection tasks).",
    )
    parser.add_argument("--benchmark-version", default="v1", help="AgentDojo suite version to load.")
    parser.add_argument(
        "--model-alias",
        default="sast-sol",
        help="Sentinel gateway model alias to call (see infra/litellm/config.yaml model_list).",
    )
    parser.add_argument("--gateway-base-url", default=DEFAULT_GATEWAY_BASE_URL, help="Sentinel gateway base URL.")
    parser.add_argument(
        "--gateway-key-env",
        default=DEFAULT_GATEWAY_KEY_ENV,
        help="Name of the environment variable holding the gateway key. The value is read, never printed or logged.",
    )
    parser.add_argument(
        "--max-user-tasks",
        type=int,
        default=3,
        help="Bounded, deterministic subset: first N user task IDs, sorted, from the chosen suite.",
    )
    parser.add_argument(
        "--max-injection-tasks",
        type=int,
        default=2,
        help=(
            "Bounded, deterministic subset: first N injection task IDs, sorted, among "
            "those the standalone-utility probe found viable (injection_task.security() "
            "true when the injection task is run as its own unattacked goal). Injection "
            "tasks the scaffold cannot complete standalone are excluded before this bound "
            "is applied, because they cannot produce a meaningful attack-success signal."
        ),
    )
    parser.add_argument(
        "--max-probe-injection-tasks",
        type=int,
        default=None,
        help=(
            "Bound on how many of the suite's injection tasks (sorted) get a standalone-"
            "utility probe before selection. Defaults to every injection task in the "
            "suite (each v1 suite has at most 9), since the probe is cheap: one run per "
            "task, no pairing with user tasks."
        ),
    )
    parser.add_argument(
        "--max-tool-iters",
        type=int,
        default=8,
        help="Upper bound on LLM<->tool round trips within a single task run.",
    )
    parser.add_argument(
        "--logdir",
        default=None,
        help="Directory for AgentDojo's own per-task transcript JSON. Defaults to a fresh temp directory; not committed.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Path to write the result JSON artifact. Defaults to evaluation/agentdojo/results/<timestamp>-<suite>-<model>.json.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable AgentDojo's per-message INFO logging to stdout.",
    )
    return parser


def build_pipeline(args: argparse.Namespace, client: openai.OpenAI, suite_name: str) -> tuple[AgentPipeline, SentinelOpenAILLM]:
    llm = SentinelOpenAILLM(client=client, model=args.model_alias, suite_name=suite_name)
    system_message = load_system_message(None)
    pipeline = AgentPipeline(
        [
            SystemMessage(system_message),
            InitQuery(),
            llm,
            ToolsExecutionLoop([ToolsExecutor(tool_result_to_str), llm], max_iters=args.max_tool_iters),
        ]
    )
    pipeline.name = args.model_alias
    return pipeline, llm


def compute_metrics(results, injection_task_utility) -> dict:
    # AgentDojo's `security_results[key]` is True when the INJECTED goal was executed
    # correctly (base_tasks.BaseInjectionTask.security: "Returns True if the injection was
    # executed correctly, False otherwise") - i.e. True means the attack succeeded, not
    # that the agent was safe. ASR is therefore the mean of security_results directly, and
    # a per-task "attack_succeeded" flag is the raw boolean, not its negation. Verified by
    # inspecting a live run's saved transcript JSON before wiring this in, because the
    # field name reads the opposite way at a glance.
    security_values = list(results["security_results"].values())
    utility_values = list(results["utility_results"].values())
    asr = (sum(security_values) / len(security_values)) if security_values else None
    utility_under_attack = (sum(utility_values) / len(utility_values)) if utility_values else None
    per_task = [
        {
            "user_task_id": user_task_id,
            "injection_task_id": injection_task_id,
            "utility_under_attack": bool(results["utility_results"][(user_task_id, injection_task_id)]),
            "attack_succeeded": bool(results["security_results"][(user_task_id, injection_task_id)]),
        }
        for (user_task_id, injection_task_id) in sorted(results["security_results"].keys())
    ]
    return {
        "attack_success_rate": asr,
        "utility_under_attack": utility_under_attack,
        "injection_task_standalone_utility": {
            task_id: bool(value) for task_id, value in injection_task_utility.items()
        },
        "per_task_result": per_task,
        "task_run_count": len(security_values),
    }


def cost_estimate(model_alias: str, usage: dict, task_run_count: int) -> dict:
    price = KNOWN_PRICE_PER_MILLION.get(model_alias)
    if price is None or task_run_count == 0:
        return {
            "priced": False,
            "reason": (
                f"no config-verified price mapping is recorded for alias {model_alias!r}; "
                "reporting token counts only, not a dollar figure"
            ),
        }
    observed_usd = (
        usage["prompt_tokens"] / 1_000_000 * price["prompt_usd"]
        + usage["completion_tokens"] / 1_000_000 * price["completion_usd"]
    )
    avg_prompt = usage["prompt_tokens"] / task_run_count
    avg_completion = usage["completion_tokens"] / task_run_count
    projections = {}
    for suite_name, (user_count, injection_count) in ALL_V1_SUITE_SIZES.items():
        # Same accounting benchmark_suite_with_injections uses: one run per (user task,
        # injection task) pair, plus one standalone-utility run per injection task.
        suite_task_runs = user_count * injection_count + injection_count
        projections[suite_name] = {
            "task_run_count": suite_task_runs,
            "estimated_usd": round(
                suite_task_runs * (avg_prompt / 1_000_000 * price["prompt_usd"] + avg_completion / 1_000_000 * price["completion_usd"]),
                4,
            ),
        }
    total_task_runs = sum(v["task_run_count"] for v in projections.values())
    total_usd = round(sum(v["estimated_usd"] for v in projections.values()), 4)
    return {
        "priced": True,
        "price_basis": price["basis"],
        "observed_run_usd": round(observed_usd, 6),
        "avg_tokens_per_task_run": {"prompt": round(avg_prompt, 1), "completion": round(avg_completion, 1)},
        "full_run_projection": {
            "method": (
                "linear extrapolation of this run's average prompt/completion tokens per "
                "task run, applied to every AgentDojo v1 suite's full (user_task x "
                "injection_task) + injection_task matrix for the SAME single static attack "
                "and model alias used here. A full AgentDojo evaluation typically covers "
                "multiple attacks and multiple models, which multiplies this further; this "
                "projection is a lower bound on that larger cost, not an estimate of it."
            ),
            "per_suite": projections,
            "all_v1_suites_task_run_count": total_task_runs,
            "all_v1_suites_estimated_usd": total_usd,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        logging.basicConfig(level=logging.INFO)

    gateway_key = os.environ.get(args.gateway_key_env)
    if not gateway_key:
        parser.error(
            f"environment variable {args.gateway_key_env} is not set; export the Sentinel gateway key first"
        )

    suite = get_suite(args.benchmark_version, args.suite)
    user_task_ids = sorted(suite.user_tasks.keys())[: args.max_user_tasks]
    if not user_task_ids:
        parser.error(f"suite {args.suite!r} has no user tasks left after applying --max-user-tasks")

    probe_injection_task_ids = sorted(suite.injection_tasks.keys())
    if args.max_probe_injection_tasks is not None:
        probe_injection_task_ids = probe_injection_task_ids[: args.max_probe_injection_tasks]
    if not probe_injection_task_ids:
        parser.error(f"suite {args.suite!r} has no injection tasks left after applying --max-probe-injection-tasks")

    client = openai.OpenAI(base_url=args.gateway_base_url, api_key=gateway_key, timeout=120, max_retries=2)
    pipeline, llm = build_pipeline(args, client, suite.name)
    attack = load_attack(GENERIC_IMPORTANT_INSTRUCTIONS_ATTACK_NAME, suite, pipeline)

    logdir = Path(args.logdir) if args.logdir else Path(tempfile.mkdtemp(prefix="agentdojo-sentinel-"))
    logdir.mkdir(parents=True, exist_ok=True)

    print(
        f"Probing standalone utility (unattacked, no user task) for injection_tasks="
        f"{probe_injection_task_ids} in suite={args.suite!r}",
        file=sys.stderr,
    )
    print(f"Per-task transcripts (not committed): {logdir}", file=sys.stderr)

    start = time.monotonic()
    with OutputLogger(str(logdir)):
        # Phase 1: every candidate injection task, run standalone (no user task, no attack).
        # This is the same check AgentDojo performs internally before scoring an attack
        # (`injection_tasks_utility_results` in benchmark_suite_with_injections) - run here
        # up front, against the full candidate set, so a task that cannot be completed
        # unattacked is excluded before it is ever scored as part of an "attack success"
        # denominator. `user_tasks=[]` runs no paired matrix in this phase, only the
        # standalone check, so probing every candidate is cheap (one run per task).
        probe_results = benchmark_suite_with_injections(
            pipeline,
            suite,
            attack,
            logdir=logdir,
            force_rerun=True,
            user_tasks=[],
            injection_tasks=probe_injection_task_ids,
            verbose=False,
            benchmark_version=args.benchmark_version,
        )
        standalone_utility = probe_results["injection_tasks_utility_results"]
        viable_injection_task_ids = sorted(tid for tid, ok in standalone_utility.items() if ok)
        selected_injection_task_ids = viable_injection_task_ids[: args.max_injection_tasks]

        print(
            f"Standalone utility: {standalone_utility}; viable={viable_injection_task_ids}; "
            f"selected for attack matrix={selected_injection_task_ids}",
            file=sys.stderr,
        )

        # Phase 2: score the attack only on injection tasks proven standalone-viable in
        # phase 1. force_rerun=False here so the standalone check phase 2 also performs
        # internally is served from phase 1's cache in `logdir` instead of re-billed.
        if selected_injection_task_ids:
            results = benchmark_suite_with_injections(
                pipeline,
                suite,
                attack,
                logdir=logdir,
                force_rerun=False,
                user_tasks=user_task_ids,
                injection_tasks=selected_injection_task_ids,
                verbose=False,
                benchmark_version=args.benchmark_version,
            )
        else:
            results = {
                "utility_results": {},
                "security_results": {},
                "injection_tasks_utility_results": standalone_utility,
            }
    duration_s = round(time.monotonic() - start, 2)

    metrics = compute_metrics(results, standalone_utility)
    usage = llm.usage.as_dict()
    cost = cost_estimate(args.model_alias, usage, metrics["task_run_count"])

    artifact = {
        "run_metadata": {
            "date": datetime.now(timezone.utc).isoformat(),
            "benchmark_version": args.benchmark_version,
            "suite": args.suite,
            "model_alias": args.model_alias,
            "attack_name": attack.name,
            "attack_corpus": "static",
            "provenance_declaration": "metadata.sentinel_provenance (per-message, declared for every call)",
            "gateway_base_url": args.gateway_base_url,
            "user_task_ids": user_task_ids,
            "injection_task_ids": selected_injection_task_ids,
            "max_tool_iters": args.max_tool_iters,
            "duration_seconds": duration_s,
            "selection": {
                "method": (
                    "Every injection task in injection_tasks_considered was first run "
                    "standalone (its own GOAL as the sole prompt, no attack, no user task); "
                    "injection_task.security() on that run is standalone_utility. Only "
                    "injection_tasks_viable (standalone_utility == True) were eligible for "
                    "the attack matrix; injection_task_ids above is the sorted-prefix bound "
                    "of that viable set, not of the full suite."
                ),
                "injection_tasks_considered": probe_injection_task_ids,
                "injection_tasks_viable": viable_injection_task_ids,
                "injection_tasks_used_for_asr": selected_injection_task_ids,
            },
        },
        "results": metrics,
        "token_usage": usage,
        "cost": cost,
        "caveats": {
            "scaffold_not_sentinel": (
                "This number describes the minimal scaffold agent in "
                "evaluation/agentdojo/sentinel_pipeline.py, built only so AgentDojo has "
                "something to run against. Sentinel has no agent of its own; this is not a "
                "measurement of Sentinel's product surface."
            ),
            "undefended_baseline": (
                "The Sentinel gateway ships no prompt-injection detector by design (decision "
                "0006). This is a starting point for a Week 7 before/after comparison once "
                "Stream D's agent-layer capability gating exists, not a measurement of a "
                "defense."
            ),
            "gateway_hygiene_always_on": (
                "This run still passed through the gateway's always-on, non-optional "
                "transformations: egress secret redaction and provenance spotlighting "
                "(datamarking/delimiting of target-derived spans). Decision 0006 calls "
                "spotlighting hygiene, not a control, and states it is bypassable - but it "
                "is present in every call this runner makes, so this is not a zero-"
                "intervention baseline. There is no code path in this gateway to disable it "
                "and still pass the fail-closed provenance check."
            ),
            "static_attack_overstates_robustness": (
                "AgentDojo's default attacks (including important_instructions, used here) "
                "are static. Published adaptive-attack work (AutoDojo, arxiv.org/abs/2606.15057) "
                "recovers up to 64% attack success on action-open tasks against filters "
                "measured at 0% under this same static methodology. A low or zero static ASR "
                "here must not be read as robustness against an adaptive attacker."
            ),
            "bounded_subset": (
                "This run covers a small, explicitly bounded subset of one suite with one "
                "attack and one model alias, not AgentDojo's full benchmark. See "
                "results.task_run_count and cost.full_run_projection for scope and estimated "
                "full-run cost."
            ),
            "standalone_utility_denominator": (
                "An injection task the scaffold cannot complete on its own (standalone_utility "
                "== false in results.injection_task_standalone_utility) cannot produce a "
                "meaningful attack_success_rate contribution: a False security() result there "
                "is true by construction, not evidence the attack was resisted, because the "
                "goal was never reachable in the first place. This run therefore only scores "
                "attack_success_rate over injection_task_ids drawn from "
                "run_metadata.selection.injection_tasks_viable. See "
                "run_metadata.selection.injection_tasks_considered for every injection task "
                "that was checked, including the ones excluded."
            ),
        }
        | (
            {
                "no_viable_injection_tasks": (
                    f"None of {probe_injection_task_ids} in suite {args.suite!r} had "
                    "standalone_utility == true for this scaffold: attack_success_rate is "
                    "None because there is no injection task this run could have scored. "
                    "This is a finding about the scaffold-suite pairing, not a defended "
                    "result. A meaningful ASR for this suite needs either a more capable "
                    "scaffold (this one has no memory/planning beyond a single tool-call "
                    "loop bounded by --max-tool-iters) or a different task suite whose "
                    "injection goals this scaffold can already complete unattacked."
                )
            }
            if not selected_injection_task_ids
            else {}
        ),
    }

    output_path = (
        Path(args.output)
        if args.output
        else REPO_ROOT
        / "evaluation"
        / "agentdojo"
        / "results"
        / f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{args.suite}-{args.model_alias}.json"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")

    print(f"Wrote result artifact: {output_path}", file=sys.stderr)
    print(json.dumps(metrics, indent=2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
