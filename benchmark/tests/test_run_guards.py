"""Mid-run guard, token accounting, and the model dimension reaching the credential.

The guard exists because Metis swallows provider errors: it exits 0 and writes a
valid, empty SARIF when no call succeeded, so a dead provider produces a run that
looks complete. Run 3 of the DeepSeek round burned 1.4 hours that way.

The guard therefore watches TOKENS, not findings. That distinction is the whole
design: expectedresults-1.2beta.csv contains a long block of consecutive `false`
cases, and a model that correctly declines to flag them is indistinguishable from a
dead provider to a findings-based guard.
"""
import importlib.util
import json
import pathlib
import threading

import pytest

RUNNER_PATH = pathlib.Path(__file__).resolve().parents[1] / "run/run-full-benchmark.py"
EXPECTEDRESULTS = (
    pathlib.Path(__file__).resolve().parents[1]
    / "targets/owasp-benchmark/expectedresults-1.2beta.csv"
)


def load_runner():
    spec = importlib.util.spec_from_file_location("run_full_benchmark_guards", RUNNER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load_runner()
WINDOW = runner.ZERO_TOKEN_ABORT_WINDOW


# --- guard threshold vs the real negative distribution (H6) ----------------

def longest_consecutive_false() -> int:
    longest = current = 0
    with open(EXPECTEDRESULTS, newline="") as handle:
        for line in handle:
            if line.startswith("#") or not line.strip():
                continue
            fields = line.split(",")
            if len(fields) < 3:
                continue
            if fields[2].strip().lower() == "false":
                current += 1
                longest = max(longest, current)
            else:
                current = 0
    return longest


@pytest.mark.skipif(not EXPECTEDRESULTS.exists(), reason="OWASP Benchmark target not provisioned")
def test_the_real_negative_block_is_long_enough_to_have_broken_a_findings_guard():
    """Establishes the hazard the token signal sidesteps, from the actual ground truth."""
    assert longest_consecutive_false() >= 41


@pytest.mark.skipif(not EXPECTEDRESULTS.exists(), reason="OWASP Benchmark target not provisioned")
def test_a_long_run_of_correct_negatives_does_not_trip_the_guard():
    """The 41+ consecutive `false` cases, scanned correctly: zero findings every time,
    but every call still billed the gateway prompt. A findings-based guard would abort
    here; the token-based one must not."""
    guard = runner.zero_token_guard()
    scanned = max(longest_consecutive_false(), 41)
    recent: list[int] = []
    for _ in range(scanned):
        recent.append(3300)  # gateway prompt alone, zero findings produced
        del recent[:-WINDOW]
        assert guard(len(recent), [], recent) is None


def test_guard_fires_only_after_a_full_window_of_zero_token_scans():
    guard = runner.zero_token_guard()
    recent = [0] * (WINDOW - 1)
    assert guard(len(recent), [], recent) is None, "fired before the window filled"
    recent.append(0)
    assert guard(len(recent), [], recent) is not None


def test_a_single_nonzero_scan_resets_the_evidence():
    """One successful call proves the provider is answering, so a window containing it
    is not silent no matter how many zeroes surround it."""
    guard = runner.zero_token_guard()
    recent = [0] * (WINDOW - 1) + [3300]
    assert guard(len(recent), [], recent) is None


def test_guard_stays_quiet_before_enough_scans_have_run():
    guard = runner.zero_token_guard()
    assert guard(3, [], [0, 0, 0]) is None


# --- the guard actually stops the run -------------------------------------

class SilentScan:
    """A provider that answers nothing: exit 0, empty SARIF, zero tokens."""

    def __init__(self):
        self.executed = 0
        self._lock = threading.Lock()

    def __call__(self, name, sarif_dir, metis_env):
        with self._lock:
            self.executed += 1
        return (name, True, "ok", {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0})


def test_a_silent_provider_aborts_the_run_early(monkeypatch):
    total = 500
    fake = SilentScan()
    monkeypatch.setattr(runner, "scan_one", fake)

    executed, failed, reason, tokens = runner.run_scans(
        [f"case{i}" for i in range(total)], pathlib.Path("/nonexistent"), {},
        concurrency=5, should_abort=runner.zero_token_guard(),
    )

    assert reason is not None and "0 tokens" in reason
    assert tokens["total_tokens"] == 0
    # Asserted against real task execution, not by inspection: the pre-Phase-0 runner
    # submitted everything upfront and would have run all 500 regardless.
    assert fake.executed < total // 4, f"silent run executed {fake.executed}/{total} tasks"
    assert executed == fake.executed


def test_a_healthy_run_is_never_aborted_by_the_guard(monkeypatch):
    total = 200
    calls = {"n": 0}
    lock = threading.Lock()

    def scan(name, sarif_dir, metis_env):
        with lock:
            calls["n"] += 1
        return (name, True, "ok", {"input_tokens": 3300, "output_tokens": 7, "total_tokens": 3307})

    monkeypatch.setattr(runner, "scan_one", scan)
    executed, failed, reason, tokens = runner.run_scans(
        [f"case{i}" for i in range(total)], pathlib.Path("/nonexistent"), {},
        concurrency=5, should_abort=runner.zero_token_guard(),
    )
    assert reason is None and executed == total
    assert tokens["total_tokens"] == total * 3307


# --- token accounting ------------------------------------------------------

def write_usage(path: pathlib.Path, total: int, inp: int = 0, out: int = 0) -> None:
    path.write_text(json.dumps({
        "schema_version": 1,
        "totals": {"input_tokens": inp, "output_tokens": out, "total_tokens": total},
    }))


def test_tokens_are_summed_across_a_scans_usage_files(tmp_path):
    write_usage(tmp_path / "metis_usage_a_1_1.json", 3300, inp=3290, out=10)
    write_usage(tmp_path / "metis_usage_b_2_1.json", 1200, inp=1190, out=10)
    assert runner.read_usage_tokens(tmp_path) == {
        "input_tokens": 4480, "output_tokens": 20, "total_tokens": 4500,
    }


def test_missing_or_corrupt_usage_files_read_as_zero_not_as_a_crash(tmp_path):
    """A run must not die on one unreadable record, but it must not silently inflate
    either — an unreadable file contributes nothing, which the guard then sees."""
    (tmp_path / "metis_usage_broken_1_1.json").write_text("{not json")
    assert runner.read_usage_tokens(tmp_path)["total_tokens"] == 0
    assert runner.read_usage_tokens(tmp_path / "absent")["total_tokens"] == 0


def test_null_token_fields_do_not_crash_aggregation(tmp_path):
    (tmp_path / "metis_usage_n_1_1.json").write_text(
        json.dumps({"totals": {"input_tokens": None, "total_tokens": None}}))
    assert runner.read_usage_tokens(tmp_path)["total_tokens"] == 0


# --- the model dimension reaches the credential (H5) ----------------------

def run_main(monkeypatch, argv, env):
    monkeypatch.setattr("sys.argv", ["run-full-benchmark.py", *argv])
    for name in list(env):
        monkeypatch.setenv(name, env[name])
    for tier in runner.MODEL_TIERS:
        for run in (1, 2, 3):
            var = f"V0_{tier.upper()}_RUN{run}_VIRTUAL_KEY"
            if var not in env:
                monkeypatch.delenv(var, raising=False)
    return runner.main()


def demanded_key_var(caplog) -> str:
    """The env var the runner said it needed, taken from its own error message."""
    for record in caplog.records:
        message = record.getMessage()
        if "VIRTUAL_KEY" in message:
            return message.split()[0]
    raise AssertionError("runner did not name a missing key variable")


def test_each_tier_and_run_demands_its_own_key(monkeypatch, caplog):
    """Two tiers at the same run number must not resolve to one credential: per-key
    attribution is the only per-arm accounting left once spend is unavailable."""
    named = {}
    for tier in runner.MODEL_TIERS:
        caplog.clear()
        assert run_main(monkeypatch, ["--model", tier, "--run", "1"], {}) == 2
        named[tier] = demanded_key_var(caplog)

    assert named == {
        "sol": "V0_SOL_RUN1_VIRTUAL_KEY",
        "terra": "V0_TERRA_RUN1_VIRTUAL_KEY",
        "gpt55": "V0_GPT55_RUN1_VIRTUAL_KEY",
    }
    assert len(set(named.values())) == len(runner.MODEL_TIERS)


def test_run_number_is_part_of_the_key_name(monkeypatch, caplog):
    seen = []
    for run in (1, 2, 3):
        caplog.clear()
        assert run_main(monkeypatch, ["--model", "sol", "--run", str(run)], {}) == 2
        seen.append(demanded_key_var(caplog))
    assert seen == ["V0_SOL_RUN1_VIRTUAL_KEY", "V0_SOL_RUN2_VIRTUAL_KEY", "V0_SOL_RUN3_VIRTUAL_KEY"]


def test_every_tier_has_a_metis_config():
    """A missing per-tier config would otherwise surface only once a run started."""
    configs = pathlib.Path(__file__).resolve().parents[1] / "configs"
    for tier in runner.MODEL_TIERS:
        path = configs / f"metis-{tier}.yaml"
        assert path.exists(), f"no Metis config for tier {tier}"
        assert f'model: "sast-{tier}"' in path.read_text()


def test_spend_is_declared_unavailable_rather_than_zero():
    """`spend_usd: 0.0` is the exact signature of the run-3 silent failure. A run that
    genuinely cannot measure spend must not be indistinguishable from it."""
    assert "null" in runner.SPEND_UNAVAILABLE_REASON.lower()
    assert "0.0" in runner.SPEND_UNAVAILABLE_REASON


# --- stall watchdog --------------------------------------------------------

def test_a_total_stall_aborts_instead_of_waiting_forever(monkeypatch):
    """Every worker blocked with nothing completing is the failure sol run 1 hit: the
    per-scan subprocess timeout did not bound it, so the loop must notice the silence
    itself. Without this the run sits idle indefinitely."""
    monkeypatch.setattr(runner, "STALL_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(runner, "STALL_ABORT_AFTER", 2)

    release = threading.Event()

    def hangs(name, sarif_dir, metis_env):
        release.wait(timeout=10)
        return (name, True, "ok", {"total_tokens": 100})

    monkeypatch.setattr(runner, "scan_one", hangs)
    timer = threading.Timer(1.5, release.set)  # backstop so the test cannot hang
    timer.start()
    try:
        executed, failed, reason, tokens = runner.run_scans(
            [f"case{i}" for i in range(50)], pathlib.Path("/nonexistent"), {}, concurrency=2,
        )
    finally:
        release.set()
        timer.cancel()

    assert reason is not None and "stalled" in reason
    assert executed < 50, "aborted run still worked through the whole queue"


def test_a_slow_but_progressing_run_is_not_treated_as_stalled(monkeypatch):
    """The watchdog keys on completions, not on speed. A run that is merely slow must
    survive it, or a busy provider looks identical to a dead one."""
    monkeypatch.setattr(runner, "STALL_TIMEOUT_SECONDS", 0.3)
    monkeypatch.setattr(runner, "STALL_ABORT_AFTER", 2)

    def slow(name, sarif_dir, metis_env):
        import time
        time.sleep(0.1)
        return (name, True, "ok", {"total_tokens": 100})

    monkeypatch.setattr(runner, "scan_one", slow)
    executed, failed, reason, tokens = runner.run_scans(
        [f"case{i}" for i in range(12)], pathlib.Path("/nonexistent"), {}, concurrency=3,
    )
    assert reason is None and executed == 12


# --- regressions found by independent review (2026-07-23) -----------------

A_FINDING = [{"ruleId": "AI001", "message": {"text": "sqli"}}]


def write_sarif(path: pathlib.Path, findings: list) -> None:
    path.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Metis"}}, "results": findings}],
    }))

def test_run_tokens_include_resumed_work(tmp_path):
    """Manifest token totals must cover the whole run, not one invocation.

    sol run 1 resumed 244 cases; the per-invocation total under-reported by
    1,274,319 tokens (2.98%) and inverted the published token-efficiency ranking.
    """
    root = tmp_path / "usage"
    for name, tok in (("caseA", 3300), ("caseB", 4100), ("caseC", 0)):
        d = root / name
        d.mkdir(parents=True)
        write_usage(d / "metis_usage_x_1_1.json", tok, inp=tok, out=0)
    # The canary is a harness self-check, not a scanned case.
    canary = root / "_preflight_canary"
    canary.mkdir()
    write_usage(canary / "metis_usage_c_1_1.json", 9999)

    totals = runner.read_run_tokens(root)
    assert totals["total_tokens"] == 3300 + 4100, "canary counted, or a scan dropped"


def test_run_tokens_on_missing_root_is_zero_not_a_crash(tmp_path):
    assert runner.read_run_tokens(tmp_path / "absent")["total_tokens"] == 0


def test_resume_rejects_poisoned_scans_that_sit_beside_healthy_ones(tmp_path):
    """The directory-level rule ("one finding vouches for the batch") was wrong.

    When a provider dies mid-run, the zero-finding files written afterwards sit beside
    earlier files that DO carry findings. Vouching by directory accepts every poisoned
    artifact — the run-3 failure with extra steps — and the harness's own abort path
    leaves exactly that mixture on disk.
    """
    sarif_dir = tmp_path / "sarif"
    usage_root = tmp_path / "usage"
    sarif_dir.mkdir()

    healthy = ["good1", "good2"]
    benign = ["clean1"]          # real scan, legitimately zero findings
    poisoned = ["dead1", "dead2", "dead3"]

    for name in healthy:
        write_sarif(sarif_dir / f"{name}.sarif", A_FINDING)
    for name in benign + poisoned:
        write_sarif(sarif_dir / f"{name}.sarif", [])
    for name in healthy + benign:          # reached the provider -> billed tokens
        d = usage_root / name
        d.mkdir(parents=True)
        write_usage(d / "metis_usage_x_1_1.json", 3300)
    for name in poisoned:                  # provider dead -> no usage record at all
        (usage_root / name).mkdir(parents=True)

    accepted = runner.trustworthy_prior_scans(sarif_dir, usage_root)
    assert accepted == set(healthy) | set(benign)
    assert not (accepted & set(poisoned)), "poisoned scans vouched for by their siblings"


def test_resume_falls_back_to_directory_rule_without_usage_records(tmp_path):
    """The frozen DeepSeek arm predates per-scan usage dirs; it must still resume."""
    sarif_dir = tmp_path / "sarif"
    sarif_dir.mkdir()
    write_sarif(sarif_dir / "a.sarif", A_FINDING)
    write_sarif(sarif_dir / "b.sarif", [])
    assert runner.trustworthy_prior_scans(sarif_dir, tmp_path / "no-usage") == {"a", "b"}


def test_a_wider_guard_window_is_actually_honoured(monkeypatch):
    """`recent_tokens` was trimmed with the module constant while the guard compared
    its own window, so any guard configured wider than the constant could never fill
    its window and silently never fired."""
    wide = runner.ZERO_TOKEN_ABORT_WINDOW + 15
    fake = SilentScan()
    monkeypatch.setattr(runner, "scan_one", fake)

    executed, _failed, reason, _tokens = runner.run_scans(
        [f"case{i}" for i in range(400)], pathlib.Path("/nonexistent"), {},
        concurrency=5, should_abort=runner.zero_token_guard(window=wide),
    )
    assert reason is not None, f"guard with window={wide} never fired"
    assert executed < 400
