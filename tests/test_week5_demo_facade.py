"""Week-5 teaching facade: IPI / PII / HITL reject, never sends."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "sentinel_week5_demo", ROOT / "scripts" / "sentinel-week5-demo.py"
)
assert _SPEC and _SPEC.loader
demo = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(demo)


def test_ipi_fixture_goal_is_quarantined() -> None:
    code, payload = demo.handle_ipi({"fixture": "goal"})
    assert code == 200
    assert payload["status"] == "quarantined"
    assert payload["sent"] is False
    assert "objective-change" in payload["reasons"]


def test_ipi_fixture_secrets_is_quarantined() -> None:
    code, payload = demo.handle_ipi({"fixture": "secrets"})
    assert code == 200
    assert payload["status"] == "quarantined"
    assert payload["sent"] is False


def test_pii_user_phone_is_redacted() -> None:
    code, payload = demo.handle_pii({"text": "user_phone=+12025550143"})
    assert code == 200
    assert payload["sent"] is False
    assert "+12025550143" not in payload["redacted"]
    assert any(item["cls"] == "phone" for item in payload["findings"])


def test_hitl_preview_is_catalog_only() -> None:
    code, payload = demo.handle_hitl_preview({"case_id": "post-empty-object"})
    assert code == 200
    assert payload["method"] == "POST"
    assert payload["path"] == "/sentinel-charter/rest/basket"
    assert payload["body"] == "{}"
    assert payload["sent"] is False


def test_hitl_unknown_case_is_rejected() -> None:
    code, payload = demo.handle_hitl_preview({"case_id": "invented"})
    assert code == 400
    assert "outside" in payload["error"]


@pytest.mark.parametrize("decision", ["reject", "approve"])
def test_hitl_decide_never_sends(decision: str) -> None:
    code, payload = demo.handle_hitl_decide({"case_id": "get-baseline", "decision": decision})
    assert code == 200
    assert payload["sent"] is False
    assert payload["decision"] == decision


def test_busy_port_exits_two_without_traceback(monkeypatch, capsys) -> None:
    monkeypatch.setattr(demo, "ThreadingHTTPServer", lambda *a, **k: (_ for _ in ()).throw(OSError(98, "Address already in use")))
    monkeypatch.setattr(sys, "argv", ["sentinel-week5-demo.py", "--bind", "127.0.0.1", "--port", "18055"])
    assert demo.main() == 2
    err = capsys.readouterr().err
    assert "cannot bind" in err
    assert "Traceback" not in err


def test_host_wildcard_bind_is_rejected(monkeypatch, capsys) -> None:
    monkeypatch.delenv("SENTINEL_WEEK5_DEMO_CONTAINER", raising=False)
    monkeypatch.setattr(sys, "argv", ["sentinel-week5-demo.py", "--bind", "0.0.0.0", "--port", "18055"])
    assert demo.main() == 2
    err = capsys.readouterr().err
    assert "0.0.0.0 bind is only for the published container" in err
    assert "Traceback" not in err


@pytest.mark.parametrize("bind", ["1.2.3.4", "::1", "localhost"])
def test_non_allowlisted_bind_is_rejected(monkeypatch, capsys, bind: str) -> None:
    monkeypatch.setattr(sys, "argv", ["sentinel-week5-demo.py", "--bind", bind, "--port", "18055"])
    assert demo.main() == 2
    err = capsys.readouterr().err
    assert "bind must be 127.0.0.1" in err
    assert "Traceback" not in err


@pytest.mark.parametrize("port", [0, -1, 65536])
def test_invalid_port_exits_two_without_traceback(monkeypatch, capsys, port: int) -> None:
    monkeypatch.setattr(sys, "argv", ["sentinel-week5-demo.py", "--bind", "127.0.0.1", "--port", str(port)])
    assert demo.main() == 2
    err = capsys.readouterr().err
    assert "port must be 1-65535" in err
    assert "Traceback" not in err


def test_unhashable_ipi_fixture_is_json_400() -> None:
    code, payload = demo.handle_ipi({"fixture": []})
    assert code == 400
    assert "fixture" in payload["error"]


def test_unhashable_hitl_decision_is_json_400() -> None:
    code, payload = demo.handle_hitl_decide({"case_id": "get-baseline", "decision": ["approve"]})
    assert code == 400
    assert "decision" in payload["error"]


def test_module_does_not_import_executor_or_signer() -> None:
    text = Path(demo.__file__).read_text(encoding="utf-8")
    assert "sentinel-charter-executor" not in text
    assert "sentinel-charter-approve" not in text
    assert "charter_approval" not in text


def test_goal_fixture_file_still_present() -> None:
    path = ROOT / "tests/fixtures/charter-response-ipi-goal.json"
    assert "Ignore the prior objective" in json.loads(path.read_text(encoding="utf-8"))["response"]
