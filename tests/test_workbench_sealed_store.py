from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from workbench.sealed_store import SealedStoreViolation, SealedFixtureStore


ROOT = Path(__file__).resolve().parents[1]
COMMITTED_FIXTURE = ROOT / "workbench" / "fixtures" / "typescript-graph"


def fixture_workspace(tmp_path: Path) -> tuple[Path, Path]:
    fixture_root = tmp_path / "fixtures"
    source = fixture_root / "typescript-graph"
    source.mkdir(parents=True)
    for committed in COMMITTED_FIXTURE.rglob("*"):
        if committed.is_file():
            target = source / committed.relative_to(COMMITTED_FIXTURE)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(committed.read_bytes())
    return fixture_root, source


def test_seal_copies_fixture_bytes_into_a_private_atomic_registered_snapshot(tmp_path: Path):
    fixture_root, source = fixture_workspace(tmp_path)
    store = SealedFixtureStore(tmp_path / "evidence", fixture_root)

    snapshot = store.seal_fixture(source, fixture_id="typescript-graph")

    manifest = json.loads(snapshot.manifest_path.read_text(encoding="utf-8"))
    assert snapshot.snapshot_id == manifest["snapshot_id"] == manifest["root_digest"]
    assert snapshot.root.is_relative_to(tmp_path / "evidence")
    assert (snapshot.root / "src" / "main.ts").read_text(encoding="utf-8").startswith("import")
    assert stat.S_IMODE(snapshot.manifest_path.stat().st_mode) == 0o400
    assert stat.S_IMODE(snapshot.root.stat().st_mode) == 0o500
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o400 for path in snapshot.root.rglob("*") if path.is_file())


def test_resolver_refuses_forged_ids_or_manifests_and_never_returns_an_original_fixture_path(tmp_path: Path):
    fixture_root, source = fixture_workspace(tmp_path)
    store = SealedFixtureStore(tmp_path / "evidence", fixture_root)
    snapshot = store.seal_fixture(source, fixture_id="typescript-graph")

    with pytest.raises(SealedStoreViolation):
        store.resolve("f" * 64)

    forged_manifest = snapshot.manifest_path.with_name("e" * 64 + ".json")
    forged_manifest.write_text(snapshot.manifest_path.read_text(encoding="utf-8"), encoding="utf-8")
    forged_manifest.chmod(0o400)
    with pytest.raises(SealedStoreViolation):
        store.resolve("e" * 64)

    source.joinpath("src", "main.ts").write_text("export const changed = true;\n", encoding="utf-8")
    resolved = store.resolve(snapshot.snapshot_id)
    assert resolved.root != source
    assert "changed = true" not in (resolved.root / "src" / "main.ts").read_text(encoding="utf-8")


def test_fixture_only_issuer_refuses_paths_outside_the_registered_fixture_root(tmp_path: Path):
    fixture_root, _ = fixture_workspace(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "index.ts").write_text("export {};\n", encoding="utf-8")

    with pytest.raises(SealedStoreViolation):
        SealedFixtureStore(tmp_path / "evidence", fixture_root).seal_fixture(outside, fixture_id="outside")
