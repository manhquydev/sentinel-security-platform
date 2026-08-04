from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_browser_client_clears_the_capability_fragment_before_view_or_broker_network_activity():
    source = (ROOT / "workbench" / "web" / "static" / "app.js").read_text(encoding="utf-8")

    assert source.index("history.replaceState") < source.index("fetch(")
    assert "/api/bootstrap" in source
    assert "/api/commands" in source
    assert "/api/status" in source
    assert 'credentials: "include"' in source
    assert "startup_capability" in source
    assert "WORKBENCH_RAW_SOURCE_CANARY" not in source
