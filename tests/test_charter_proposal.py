import json

import pytest

from agent.charter_proposal import propose, propose_report_jsonl
from agent.charter_contracts import ReportFinding
from agent.charter_requests import CHARTER_BASKET_PATH, CHARTER_SEARCH_PATH, GET_PURPOSE, POST_PURPOSE


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


def week3_report_row(finding_id: str = "finding:week3-header") -> dict:
    """A minimal valid week3-analysis/v1 row (not a free-form invention path)."""
    digest = "a" * 64
    return {
        "schema_version": "week3-analysis/v1",
        "finding_id": finding_id,
        "tool": "nuclei",
        "scanner": "DAST",
        "name": "Missing security header",
        "severity": "Info",
        "location": "http://127.0.0.1:13000/rest/products/search",
        "scanner_evidence": ["template-id=header"],
        "explanation": "The scanner reported 'Missing security header' at the listed location.",
        "remediation": "Review the scanner evidence and the retrieved guidance, then verify the documented fix only in an authorized sandbox.",
        "confidence": "medium",
        "source_ids": ["nuclei-js:0123456789abcdef:item:1"],
        "knowledge_provenance": [
            "OWASP A05 Security Misconfiguration | https://example.invalid/a05 | sha256:" + digest
        ],
        "corpus_digest": digest,
        "retrieval_digest": digest,
    }


def test_unavailable():
    assert not propose([]).available
    assert not propose([{"finding_id": "x", "grounded": True}]).available


def test_fixed():
    p = propose([report("finding:f1")])
    s = p.to_spec("r")
    assert (s.method, s.path, s.query, s.purpose) == (
        "GET",
        CHARTER_SEARCH_PATH,
        "q=apple",
        GET_PURPOSE,
    )
    post = propose([report("finding:f2")], request_kind="post").to_spec("r")
    assert (post.method, post.path, post.body, post.purpose) == (
        "POST",
        CHARTER_BASKET_PATH,
        "{}",
        POST_PURPOSE,
    )


def test_no_arbitrary_or_pii():
    p = propose([report("finding:f1")], request_kind="x")
    assert not p.available and "f1" not in p.reason


def test_report_jsonl_is_validated_before_the_fixed_request_is_proposed(tmp_path):
    path = tmp_path / "report.jsonl"
    path.write_text(report("finding:from-jsonl").model_dump_json() + "\n", encoding="utf-8")
    proposal = propose_report_jsonl(path)
    assert proposal.available
    assert proposal.to_spec("run").path == CHARTER_SEARCH_PATH

    path.write_text(json.dumps({**report().model_dump(), "grounded": True}) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid grounded report"):
        propose_report_jsonl(path)


def test_week3_analysis_jsonl_proposes_fixed_get_catalog_case(tmp_path):
    path = tmp_path / "week3-report.jsonl"
    row = week3_report_row("finding:w3-get")
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")

    proposal = propose_report_jsonl(path, request_kind="get")
    assert proposal.available
    assert proposal.finding_ids == ("finding:w3-get",)
    spec = proposal.to_spec("run-w3")
    assert (spec.method, spec.path, spec.query, spec.purpose) == (
        "GET",
        CHARTER_SEARCH_PATH,
        "q=apple",
        GET_PURPOSE,
    )
    # Finding location must never become the request path/query/body.
    assert row["location"] not in (spec.path, spec.query, spec.body)
    assert spec.path != row["location"]


def test_week3_analysis_jsonl_proposes_fixed_post_catalog_case(tmp_path):
    path = tmp_path / "week3-report.jsonl"
    path.write_text(json.dumps(week3_report_row("finding:w3-post")) + "\n", encoding="utf-8")

    proposal = propose_report_jsonl(path, request_kind="post")
    assert proposal.available
    spec = proposal.to_spec("run-w3-post")
    assert (spec.method, spec.path, spec.body, spec.purpose) == (
        "POST",
        CHARTER_BASKET_PATH,
        "{}",
        POST_PURPOSE,
    )


def test_week3_analysis_jsonl_missing_digest_fails_closed(tmp_path):
    path = tmp_path / "week3-bad.jsonl"
    bad = week3_report_row()
    del bad["corpus_digest"]
    path.write_text(json.dumps(bad) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid grounded report"):
        propose_report_jsonl(path)


def test_week3_analysis_jsonl_extra_field_fails_closed(tmp_path):
    path = tmp_path / "week3-extra.jsonl"
    bad = week3_report_row()
    bad["grounded"] = True
    path.write_text(json.dumps(bad) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid grounded report"):
        propose_report_jsonl(path)


def test_unsupported_schema_version_fails_closed(tmp_path):
    path = tmp_path / "unknown.jsonl"
    payload = report().model_dump()
    payload["schema_version"] = "week99-fantasy/v9"
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid grounded report"):
        propose_report_jsonl(path)


def test_mixed_charter_and_week3_lines_load_when_each_is_valid(tmp_path):
    path = tmp_path / "mixed.jsonl"
    path.write_text(
        report("finding:charter").model_dump_json()
        + "\n"
        + json.dumps(week3_report_row("finding:week3"))
        + "\n",
        encoding="utf-8",
    )
    proposal = propose_report_jsonl(path)
    assert proposal.available
    assert proposal.finding_ids == ("finding:charter", "finding:week3")
    assert proposal.to_spec("mixed").path == CHARTER_SEARCH_PATH


def test_partial_file_with_one_bad_line_never_yields_a_proposal(tmp_path):
    """A trailing invalid line must fail the whole file (no partial success)."""
    path = tmp_path / "partial.jsonl"
    path.write_text(
        report("finding:good").model_dump_json()
        + "\n"
        + json.dumps({**week3_report_row("finding:bad"), "grounded": True})
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="invalid grounded report"):
        propose_report_jsonl(path)
