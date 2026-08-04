from __future__ import annotations

from pathlib import Path
import os

import pytest

from workbench.intake import IntakeViolation, RepositoryIntake


def approved_repository(tmp_path: Path) -> Path:
    root = tmp_path / "approved" / "candidate"
    root.mkdir(parents=True)
    (root / "src").mkdir()
    (root / "src" / "app.ts").write_text("export const app = true;\n", encoding="utf-8")
    (root / "package.json").write_text('{"name":"fixture"}\n', encoding="utf-8")
    return root


def intake(tmp_path: Path, root: Path) -> RepositoryIntake:
    return RepositoryIntake(
        evidence_root=tmp_path / "evidence",
        approved_roots={"fixture-candidate": root},
        profile="typescript",
    )


def test_intake_copies_only_admitted_regular_files_into_a_private_sealed_snapshot(tmp_path):
    root = approved_repository(tmp_path)
    snapshot = intake(tmp_path, root).seal_registered_root("fixture-candidate", repository_identity="fixture-repository")

    assert snapshot.repository_identity == "fixture-repository"
    assert (snapshot.root / "src" / "app.ts").read_text(encoding="utf-8").startswith("export")
    assert snapshot.root.is_relative_to(tmp_path / "evidence")
    assert snapshot.root.stat().st_mode & 0o077 == 0
    root.joinpath("src", "app.ts").write_text("export const changed = true;\n", encoding="utf-8")
    assert "changed" not in (snapshot.root / "src" / "app.ts").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("name", "content"),
    [
        (".env", "API_KEY=canary-secret\n"),
        ("credentials.pem", "-----BEGIN PRIVATE KEY-----\n"),
        ("src/minified.ts", "x=" + "a" * 40000),
    ],
)
def test_intake_refuses_sensitive_or_minified_admitted_tree_instead_of_silently_skipping_it(tmp_path, name, content):
    root = approved_repository(tmp_path)
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")

    with pytest.raises(IntakeViolation):
        intake(tmp_path, root).seal_registered_root("fixture-candidate", repository_identity="fixture-repository")


def test_intake_refuses_unregistered_paths_symlinks_and_special_files(tmp_path):
    root = approved_repository(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "app.ts").write_text("export {};\n", encoding="utf-8")
    link = root / "src" / "escape.ts"
    link.symlink_to(outside / "app.ts")

    service = intake(tmp_path, root)
    with pytest.raises(IntakeViolation):
        service.seal_registered_root("fixture-candidate", repository_identity="fixture-repository")
    with pytest.raises(IntakeViolation):
        service.seal_registered_root("../fixture-candidate", repository_identity="fixture-repository")


def test_intake_refuses_fifo_and_detects_inode_swap_during_descriptor_relative_open(tmp_path, monkeypatch):
    root = approved_repository(tmp_path)
    fifo = root / "src" / "blocked.ts"
    os.mkfifo(fifo)
    with pytest.raises(IntakeViolation, match="non-regular"):
        intake(tmp_path, root).seal_registered_root("fixture-candidate", repository_identity="fixture-repository")

    fifo.unlink()
    original = os.open
    source = root / "src" / "app.ts"
    replacement = root / "src" / "replacement.ts"
    replacement.write_text("export const replacement = true;\n", encoding="utf-8")

    def swap_before_open(name, flags, *args, **kwargs):
        if name == "app.ts" and kwargs.get("dir_fd") is not None:
            source.unlink()
            source.symlink_to(replacement)
        return original(name, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swap_before_open)
    with pytest.raises(IntakeViolation, match="opened without following"):
        intake(tmp_path, root).seal_registered_root("fixture-candidate", repository_identity="fixture-repository")


def test_intake_rejects_symlink_escape_inside_ignored_dependency_directories(tmp_path):
    root = approved_repository(tmp_path)
    dependencies = root / "node_modules"
    dependencies.mkdir()
    outside = tmp_path / "outside.ts"
    outside.write_text("export const escape = true;\n", encoding="utf-8")
    (dependencies / "escape.ts").symlink_to(outside)

    with pytest.raises(IntakeViolation, match="symlink"):
        intake(tmp_path, root).seal_registered_root("fixture-candidate", repository_identity="fixture-repository")
