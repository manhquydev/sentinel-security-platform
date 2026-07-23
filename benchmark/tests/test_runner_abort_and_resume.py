"""Runner must be abortable, and must not mistake a poisoned artifact for work done.

Two failures from the DeepSeek round motivate this file:

* the runner submitted all 2740 tasks to the pool upfront, so nothing raised while
  collecting results could stop the queue draining — an "abort" was cosmetic;
* resume accepted any SARIF that merely parsed as JSON, so run 3's 2740
  provider-failure artifacts read as completed work.
"""
import ast
import importlib.util
import json
import pathlib
import re
import threading

import pytest

RUNNER_PATH = pathlib.Path(__file__).resolve().parents[1] / "run/run-full-benchmark.py"
RUNS_DIR = pathlib.Path(__file__).resolve().parents[2] / "runs"


def load_runner():
    spec = importlib.util.spec_from_file_location("run_full_benchmark", RUNNER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load_runner()


def write_sarif(path: pathlib.Path, findings: list) -> None:
    path.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Metis"}}, "results": findings}],
    }))


A_FINDING = [{"ruleId": "AI001", "message": {"text": "sqli"}}]


# --- resume validity (C5) -------------------------------------------------

def test_directory_with_a_real_finding_is_accepted(tmp_path):
    write_sarif(tmp_path / "a.sarif", A_FINDING)
    write_sarif(tmp_path / "b.sarif", [])
    # b.sarif is empty but sits beside evidence that the provider was answering,
    # so it is a genuine clean scan rather than a failure artifact.
    assert runner.trustworthy_prior_scans(tmp_path) == {"a", "b"}


def test_all_zero_finding_directory_is_rejected_wholesale(tmp_path):
    for name in ("a", "b", "c"):
        write_sarif(tmp_path / f"{name}.sarif", [])
    assert runner.trustworthy_prior_scans(tmp_path) == set()


def test_structurally_invalid_sarif_is_rejected(tmp_path):
    write_sarif(tmp_path / "good.sarif", A_FINDING)
    (tmp_path / "truncated.sarif").write_text('{"runs": [')
    (tmp_path / "not-sarif.sarif").write_text('{"hello": "world"}')
    (tmp_path / "wrong-shape.sarif").write_text('{"runs": [{"tool": {}, "results": []}]}')
    assert runner.trustworthy_prior_scans(tmp_path) == {"good"}


def test_empty_directory_yields_nothing_to_resume(tmp_path):
    assert runner.trustworthy_prior_scans(tmp_path) == set()


@pytest.mark.skipif(not (RUNS_DIR / "v0-metis-owasp-benchmark-run3/sarif").is_dir(),
                    reason="frozen DeepSeek run artifacts not present")
def test_poisoned_run3_is_rejected_and_valid_run1_is_accepted():
    """The signal has to hold against the real artifacts, not just synthetic ones.

    run 1 contains 131 legitimately zero-finding files that are structurally
    identical to run 3's 2740 poisoned ones, so any per-file rule either loses
    those 131 or keeps all 2740.
    """
    run3 = runner.trustworthy_prior_scans(RUNS_DIR / "v0-metis-owasp-benchmark-run3/sarif")
    assert run3 == set(), f"{len(run3)} poisoned SARIFs would have been resumed as done"

    run1_dir = RUNS_DIR / "v0-metis-owasp-benchmark-run1/sarif"
    accepted = runner.trustworthy_prior_scans(run1_dir)
    assert len(accepted) == len(list(run1_dir.glob("*.sarif"))) == 2740


# --- abortability (C4) ----------------------------------------------------

class FakeScan:
    """Stands in for scan_one, counting how many tasks actually executed."""

    def __init__(self, tokens=100):
        self.executed = 0
        self.tokens = tokens
        self._lock = threading.Lock()

    def __call__(self, name, sarif_dir, metis_env):
        with self._lock:
            self.executed += 1
        return (name, True, "ok", {"input_tokens": self.tokens, "output_tokens": 0,
                                   "total_tokens": self.tokens})


def test_abort_stops_the_run_well_short_of_the_queue(monkeypatch):
    total = 200
    fake = FakeScan()
    monkeypatch.setattr(runner, "scan_one", fake)

    executed, failed, reason, tokens = runner.run_scans(
        [f"case{i}" for i in range(total)],
        pathlib.Path("/nonexistent"),
        {},
        concurrency=5,
        should_abort=lambda done, _failed, _tok: "simulated guard" if done >= 10 else None,
    )

    assert reason == "simulated guard"
    assert not failed
    # The pool drains whatever it already started; the point is that the bounded
    # window keeps that remainder small instead of running the other 190 tasks.
    assert fake.executed < total // 2, f"abort executed {fake.executed}/{total} tasks"
    assert executed == fake.executed


def test_without_an_abort_every_case_runs(monkeypatch):
    total = 50
    fake = FakeScan()
    monkeypatch.setattr(runner, "scan_one", fake)

    executed, failed, reason, tokens = runner.run_scans(
        [f"case{i}" for i in range(total)], pathlib.Path("/nonexistent"), {}, concurrency=5
    )

    assert reason is None and not failed
    assert executed == fake.executed == total
    assert tokens["total_tokens"] == total * fake.tokens


def test_failures_are_collected_without_aborting(monkeypatch):
    def flaky(name, sarif_dir, metis_env):
        ok = name != "case3"
        return (name, ok, "boom" if not ok else "ok", {"total_tokens": 50})

    monkeypatch.setattr(runner, "scan_one", flaky)
    executed, failed, reason, _tokens = runner.run_scans(
        [f"case{i}" for i in range(10)], pathlib.Path("/nonexistent"), {}, concurrency=3
    )
    assert executed == 10 and reason is None
    assert failed == [("case3", "boom")]


# --- credential handling (H3) ---------------------------------------------

def test_redact_strips_key_shaped_tokens_from_tool_output():
    raw = "AuthenticationError: key sk-abc123DEF456ghi789 was rejected by provider"
    cleaned = runner.redact(raw)
    assert "sk-abc123DEF456ghi789" not in cleaned
    assert "sk-<redacted>" in cleaned
    assert "was rejected by provider" in cleaned


def test_no_credential_travels_in_a_url_anywhere_in_the_harness():
    """A credential in a query string lands verbatim in proxy access logs.

    This greps the whole harness rather than asserting on one module's namespace. The
    previous version checked `not hasattr(runner, "get_run_spend")`, which was green
    while the identical leak was still live in run/estimate-cost.py -- a test that
    certified a property of the codebase by inspecting a single import.
    """
    harness = pathlib.Path(__file__).resolve().parents[1]
    pattern = re.compile(r"\?(key|api_key|token)=")
    offenders = []

    for path in (harness / "run").rglob("*.py"):
        source = path.read_text()
        # Documentation describing the rule is not a breach of it. Exclude docstring
        # line ranges via AST so the check stays strict on executable code without
        # forbidding the comment that explains why the rule exists.
        doc_lines: set[int] = set()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                doc = ast.get_docstring(node, clean=False)
                if doc and node.body and isinstance(node.body[0], ast.Expr):
                    lit = node.body[0]
                    doc_lines.update(range(lit.lineno, (lit.end_lineno or lit.lineno) + 1))
        for lineno, line in enumerate(source.splitlines(), 1):
            if lineno in doc_lines or line.lstrip().startswith("#"):
                continue
            if pattern.search(line):
                offenders.append(f"{path.relative_to(harness)}:{lineno}")

    for path in (harness / "scripts").rglob("*.sh"):
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if pattern.search(line):
                offenders.append(f"{path.relative_to(harness)}:{lineno}")

    assert not offenders, f"credential passed via URL query string: {offenders}"


def test_redaction_survives_truncation():
    """redact() must run BEFORE any slice.

    Truncating first can sever the `sk-` prefix from a key straddling the cut, after
    which SECRET_PATTERN no longer matches and the remaining body is written verbatim
    into run-manifest.json. Guards the call-site ordering, which is the actual defect.
    """
    fake = "sk-" + "A" * 22  # synthetic, never a real credential
    stderr = "q" * 800 + fake + "!! auth rejected"

    for cut_inside_key in (3, 8, 15):
        total = 800 + cut_inside_key + 500
        padded = stderr + "p" * (total - len(stderr)) if total > len(stderr) else stderr
        body = fake[cut_inside_key:cut_inside_key + 8]
        wrong = runner.redact(padded[-500:])          # slice-then-redact (the bug)
        right = runner.redact(padded)[-500:]          # redact-then-slice (correct)
        assert body not in right, "correct ordering still leaked a key fragment"
        if "sk-" not in padded[-500:]:
            assert body in wrong, "test no longer reproduces the truncation hazard"


def test_harness_call_sites_redact_before_truncating():
    """The property above only holds if every call site orders it correctly."""
    harness = pathlib.Path(__file__).resolve().parents[1] / "run"
    bad = []
    for path in harness.rglob("*.py"):
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if re.search(r"redact\([^)]*\[-\d+:\]\s*\)", line):
                bad.append(f"{path.relative_to(harness.parent)}:{lineno}")
    assert not bad, f"redact() applied after truncation: {bad}"
