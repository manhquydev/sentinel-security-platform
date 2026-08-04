from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from workbench.artifacts import ArtifactViolation, PrivateArtifactStore


def test_private_artifact_store_persists_metadata_only_and_builds_source_free_bundle(tmp_path):
    store = PrivateArtifactStore(tmp_path / "evidence")
    run = store.begin_run("run-1")
    record = {
        "schema_version": "sentinel-workbench-egress-record/v1",
        "request_digest": "a" * 64,
        "redaction_summary": {"secret_findings": 1, "pii_findings": 1},
        "terminal_state": "succeeded",
    }

    artifact = store.write_record(run, "egress-receipt", record)
    bundle = store.build_reproducibility_bundle(run)

    assert artifact.stat().st_mode & 0o077 == 0
    assert bundle.stat().st_mode & 0o077 == 0
    assert "source" not in bundle.read_text(encoding="utf-8").lower()


def test_artifact_store_rejects_raw_source_or_secrets_and_deletes_only_owned_expired_runs(tmp_path):
    store = PrivateArtifactStore(tmp_path / "evidence")
    run = store.begin_run("run-1")
    with pytest.raises(ArtifactViolation):
        store.write_record(run, "bad", {"raw_provider_body": "sk-canary-secret"})
    with pytest.raises(ArtifactViolation):
        store.write_record(run, "bad", {"source": "const secret = 'canary'"})

    store.mark_terminal(run, "failed", finished_at=datetime.now(UTC) - timedelta(days=31))
    other = store.begin_run("other")
    removed = store.delete_expired(run, now=datetime.now(UTC))
    assert removed is True
    assert store.run_path(other).exists()


@pytest.mark.parametrize(
    "record",
    [
        {"detail": "WORKBENCH_RAW_SOURCE_CANARY export const credential = 'do-not-persist';"},
        {"detail": "alice@example.com"},
        {"detail": "sk-supersecretvalue012345"},
    ],
)
def test_artifact_store_rejects_raw_material_hidden_under_benign_keys(tmp_path, record):
    store = PrivateArtifactStore(tmp_path / "evidence")
    run = store.begin_run("run-1")

    with pytest.raises(ArtifactViolation):
        store.write_record(run, "egress-receipt", record)
