import json

import pytest

from agent.charter_proposal import propose, propose_report_jsonl
from agent.charter_contracts import ReportFinding
from agent.charter_requests import GET_PURPOSE, POST_PURPOSE


def report(finding_id: str = "finding:header") -> ReportFinding:
    return ReportFinding(
        finding_id=finding_id,
        name="Missing security header",
        severity="Info",
        location="http://127.0.0.1:13000/",
        scanner_evidence=["template-id=header"],
        explanation="The scanner observed the missing header.",
        remediation="Set the documented header.",
        confidence="high",
        source_ids=["nuclei:header"],
        knowledge_provenance=["owasp:headers"],
    )


def test_unavailable():
    assert not propose([]).available
    assert not propose([{"finding_id": "x", "grounded": True}]).available


def test_fixed():
 p=propose([report('finding:f1')]); s=p.to_spec('r'); assert (s.method,s.path,s.query,s.purpose)==('GET','/rest/products/search','q=apple',GET_PURPOSE)
 post = propose([report('finding:f2')], request_kind='post').to_spec('r')
 assert (post.method, post.path, post.body, post.purpose) == ('POST', '/rest/basket', '{}', POST_PURPOSE)


def test_no_arbitrary_or_pii():
 p=propose([report('finding:f1')],request_kind='x'); assert not p.available and 'f1' not in p.reason


def test_report_jsonl_is_validated_before_the_fixed_request_is_proposed(tmp_path):
    path = tmp_path / "report.jsonl"
    path.write_text(report("finding:from-jsonl").model_dump_json() + "\n", encoding="utf-8")
    proposal = propose_report_jsonl(path)
    assert proposal.available
    assert proposal.to_spec("run").path == "/rest/products/search"

    path.write_text(json.dumps({**report().model_dump(), "grounded": True}) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid grounded report"):
        propose_report_jsonl(path)
