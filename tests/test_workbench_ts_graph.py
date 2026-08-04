from __future__ import annotations

from pathlib import Path

from workbench.sealed_store import SealedFixtureStore
from workbench.ts_graph import extract_typescript_graph


ROOT = Path(__file__).resolve().parents[1]
COMMITTED_FIXTURE = ROOT / "workbench" / "fixtures" / "typescript-graph"


def sealed_fixture(tmp_path: Path):
    fixture_root = tmp_path / "fixtures"
    source = fixture_root / "typescript-graph"
    source.mkdir(parents=True)
    for committed in COMMITTED_FIXTURE.rglob("*"):
        if committed.is_file():
            target = source / committed.relative_to(COMMITTED_FIXTURE)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(committed.read_bytes())
    store = SealedFixtureStore(tmp_path / "evidence", fixture_root)
    return store, store.seal_fixture(source, fixture_id="typescript-graph"), source


def test_graph_emits_resolved_import_route_auth_and_config_edges_from_the_sealed_copy(tmp_path: Path):
    store, snapshot, source = sealed_fixture(tmp_path)
    source.joinpath("src", "main.ts").write_text("export const altered = true;\n", encoding="utf-8")

    graph = extract_typescript_graph(store, snapshot.snapshot_id)
    edges = {(edge.source, edge.target, edge.kind, edge.resolution) for edge in graph.edges}

    assert ("src/main.ts", "src/lib/alias.ts", "import", "resolved") in edges
    assert ("src/main.ts", "route:/accounts/:id", "route", "resolved") in edges
    assert ("src/main.ts", "auth:requireAuth", "auth", "resolved") in edges
    assert ("src/main.ts", "config:SESSION_SECRET", "config", "resolved") in edges
    assert all(edge.source != "src/comment-only.ts" for edge in graph.edges)


def test_graph_marks_dynamic_and_unresolved_imports_unknown_without_dropping_them(tmp_path: Path):
    store, snapshot, _ = sealed_fixture(tmp_path)

    graph = extract_typescript_graph(store, snapshot.snapshot_id)
    unknown = {(edge.source, edge.target, edge.kind, edge.resolution) for edge in graph.unknown_edges}

    assert ("src/main.ts", "./lazy", "import", "unknown") in unknown
    assert ("src/main.ts", "<dynamic>", "import", "unknown") in unknown
    assert ("src/main.ts", "./missing", "import", "unknown") in unknown


def test_path_looking_comments_are_not_graph_edges(tmp_path: Path):
    store, snapshot, _ = sealed_fixture(tmp_path)

    graph = extract_typescript_graph(store, snapshot.snapshot_id)

    assert all("comment-only" not in edge.target for edge in graph.edges)
