"""Metis usage summaries must survive concurrency.

Upstream names them metis_usage_{YYYYmmdd_HHMMSS}.json, CWD-relative. At the
concurrency this harness runs, two scans finishing in the same second produce the
same filename and the later write silently destroys the earlier record; the
DeepSeek round lost ~19% of its per-scan token data that way, which is why that
round's token and cost totals are undercounts rather than measurements.
"""
import ast
import json
import os
import pathlib
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

RUNTIME_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "tools/arm-metis/src/metis/usage/runtime.py"
)

pytestmark = pytest.mark.skipif(
    not RUNTIME_PATH.exists(),
    reason="vendored Metis not provisioned (benchmark/scripts/setup-tools.sh)",
)


STDLIB_ROOTS = set(sys.stdlib_module_names) | {"__future__"}


def load_runtime_module():
    """Import the patched module without the engine's virtualenv.

    `metis.usage.runtime` pulls in llama_index and langchain at import time. The
    patched surface — usage filename generation and the exclusive-create write —
    touches none of it, so parse the real source, drop the third-party and
    intra-package imports, and execute what remains. Names those imports provide
    survive as string annotations under `from __future__ import annotations` and
    are only dereferenced by code these tests do not run.
    """
    tree = ast.parse(RUNTIME_PATH.read_text())
    tree.body = [
        node for node in tree.body
        if not (
            (isinstance(node, ast.ImportFrom) and (node.level > 0 or (node.module or "").split(".")[0] not in STDLIB_ROOTS))
            or (isinstance(node, ast.Import) and any(a.name.split(".")[0] not in STDLIB_ROOTS for a in node.names))
        )
    ]
    name = "patched_metis_usage_runtime"
    module = type(sys)(name)
    sys.modules[name] = module  # @dataclass resolves its class's module by name
    exec(compile(tree, str(RUNTIME_PATH), "exec"), module.__dict__)
    return module


runtime = load_runtime_module()


def test_generated_names_are_unique_within_a_process():
    names = {pathlib.Path(runtime.UsageRuntime.default_output_path(None)).name for _ in range(500)}
    assert len(names) == 500


def test_generated_name_carries_pid_and_sequence():
    name = pathlib.Path(runtime.UsageRuntime.default_output_path(None)).name
    assert name.startswith("metis_usage_")
    assert str(os.getpid()) in name


def test_output_dir_is_absolute_and_independent_of_cwd(tmp_path, monkeypatch):
    monkeypatch.setenv("METIS_USAGE_DIR", str(tmp_path / "results"))
    monkeypatch.chdir(tmp_path)
    pinned = runtime.usage_output_dir()
    monkeypatch.chdir(tmp_path.parent)
    assert runtime.usage_output_dir() == pinned
    assert pinned.is_absolute()


def test_output_dir_is_absolute_without_the_env_var(tmp_path, monkeypatch):
    monkeypatch.delenv("METIS_USAGE_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    assert runtime.usage_output_dir().is_absolute()


class _Runtime(runtime.UsageRuntime):
    """UsageRuntime without the collector/callback machinery under test here."""

    def __init__(self, codebase_path):
        self.codebase_path = str(codebase_path)
        self.started_at = runtime._utc_now()

    def build_persisted_payload(self):
        return {"schema_version": 1, "totals": {"total_tokens": 1}}


def test_concurrent_writes_lose_no_file(tmp_path, monkeypatch):
    monkeypatch.setenv("METIS_USAGE_DIR", str(tmp_path))
    writers = 32

    with ThreadPoolExecutor(max_workers=8) as pool:
        paths = list(pool.map(lambda _: _Runtime(tmp_path).save_run_summary(), range(writers)))

    assert len(set(paths)) == writers
    written = list(tmp_path.glob("metis_usage_*.json"))
    assert len(written) == writers, "a usage file was overwritten by a concurrent write"
    for path in written:
        assert json.loads(path.read_text())["totals"]["total_tokens"] == 1


def test_collision_raises_instead_of_overwriting(tmp_path, monkeypatch):
    """Exclusive create is the backstop: if the naming scheme ever collides again,
    the run must fail loudly rather than quietly discard a token record."""
    monkeypatch.setenv("METIS_USAGE_DIR", str(tmp_path))
    target = tmp_path / "taken.json"
    target.write_text("{}")

    with pytest.raises(FileExistsError):
        _Runtime(tmp_path).save_run_summary(str(target))
