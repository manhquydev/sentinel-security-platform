from __future__ import annotations

from pathlib import Path

import pytest

from workbench.comparison_pair import ComparisonPairViolation, build_comparison_pair
from workbench.intake import RepositoryIntake


def root(tmp_path: Path, name: str, files: dict[str, str]) -> Path:
    result = tmp_path / "roots" / name
    for relative, content in files.items():
        path = result / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return result


def snapshots(tmp_path: Path):
    base_root = root(tmp_path, "base", {"src/old.ts": "export const value = 1;\n", "package.json": "{}\n"})
    candidate_root = root(tmp_path, "candidate", {"src/new.ts": "export const value = 1;\n", "package.json": '{"version":2}\n'})
    intake = RepositoryIntake(
        evidence_root=tmp_path / "evidence",
        approved_roots={"base": base_root, "candidate": candidate_root},
        profile="typescript",
    )
    base = intake.seal_registered_root("base", repository_identity="fixture")
    candidate = intake.seal_registered_root("candidate", repository_identity="fixture")
    return intake, base, candidate


def test_pair_is_digest_bound_and_classifies_deterministic_rename_modify_delete_diff(tmp_path):
    store, base, candidate = snapshots(tmp_path)

    pair = build_comparison_pair(store, base.snapshot_id, candidate.snapshot_id)

    assert pair.repository_identity == "fixture"
    assert pair.diff["renamed"] == [{"from": "src/old.ts", "to": "src/new.ts"}]
    assert pair.diff["modified"] == ["package.json"]
    assert pair.diff["deleted"] == []
    assert pair.pair_digest


def test_pair_refuses_unregistered_snapshot_identifiers(tmp_path):
    store, base, _candidate = snapshots(tmp_path)
    with pytest.raises(ComparisonPairViolation):
        build_comparison_pair(store, base.snapshot_id, "0" * 64)


def test_pair_does_not_call_an_ambiguous_many_to_one_content_move_a_rename(tmp_path):
    base_root = root(
        tmp_path,
        "base",
        {"src/one.ts": "export const same = true;\n", "src/two.ts": "export const same = true;\n", "package.json": "{}\n"},
    )
    candidate_root = root(
        tmp_path,
        "candidate",
        {"src/moved.ts": "export const same = true;\n", "package.json": "{}\n"},
    )
    intake = RepositoryIntake(
        evidence_root=tmp_path / "evidence",
        approved_roots={"base": base_root, "candidate": candidate_root},
        profile="typescript",
    )
    base = intake.seal_registered_root("base", repository_identity="fixture")
    candidate = intake.seal_registered_root("candidate", repository_identity="fixture")

    pair = build_comparison_pair(intake, base.snapshot_id, candidate.snapshot_id)

    assert pair.diff["renamed"] == []
    assert pair.diff["added"] == ["src/moved.ts"]
    assert pair.diff["deleted"] == ["src/one.ts", "src/two.ts"]


def test_pair_refuses_a_tampered_sealed_copy_before_deriving_the_diff(tmp_path):
    store, base, candidate = snapshots(tmp_path)
    target = candidate.root / "src" / "new.ts"
    target.chmod(0o600)
    target.write_text("export const forged = true;\n", encoding="utf-8")

    with pytest.raises(ComparisonPairViolation, match="sealed"):
        build_comparison_pair(store, base.snapshot_id, candidate.snapshot_id)
