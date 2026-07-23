"""TDD for findings.sarif_to_jsonl. Fixtures in tests/fixtures/ are reconciled
with real tool output (see sample_metis.sarif docstring-equivalent note in
sample_saist.sarif and runs/spike-engine-endpoint.md) - not fabricated from scratch."""
import json
import pathlib

from findings.sarif_to_jsonl import convert_sarif_to_findings

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def load_fixture(name):
    with open(FIXTURES / name) as f:
        return json.load(f)


def convert(name, **overrides):
    sarif = load_fixture(name)
    kwargs = dict(
        sarif_ref=name,
        run_id="run-test",
        timestamp="2026-07-21T00:00:00Z",
        variant="V0",
        model="deepseek/deepseek-chat",
        target="owasp-benchmark",
    )
    kwargs.update(overrides)
    return convert_sarif_to_findings(sarif, **kwargs)


def test_metis_real_finding_converts_with_cwe_from_result_properties():
    findings = convert("sample_metis.sarif")
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "Metis"
    assert f.tool_version == "1.5.0"
    assert f.cwe == 89
    assert f.severity == "critical"
    assert f.file == "VulnSample.java"
    assert f.start_line == 9
    assert f.end_line == 10
    assert f.confidence == 1.0
    assert f.sarif_ref == "sample_metis.sarif"


def test_saist_finding_converts_with_cwe_from_rule_tags():
    findings = convert("sample_saist.sarif")
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "datadog-ai-static-analyzer"
    assert f.cwe == 89
    assert f.severity == "medium"  # SEVERITY:WARNING -> medium via SARIF-level fallback map
    assert f.rule_id == "datadog/java-sqli"


def test_finding_id_deterministic():
    a = convert("sample_metis.sarif")[0]
    b = convert("sample_metis.sarif")[0]
    assert a.finding_id == b.finding_id


def _append_mutated_result(sarif, mutate):
    result = sarif["runs"][0]["results"][0]
    other = json.loads(json.dumps(result))
    mutate(other)
    sarif["runs"][0]["results"].append(other)
    return sarif


def test_finding_id_no_collision_for_different_cwe_alone_same_start_and_end_line():
    """Isolates cwe as the only changed field (same start_line AND end_line) so this
    test can't pass by accident on end_line alone differentiating the two records."""
    sarif = _append_mutated_result(
        load_fixture("sample_metis.sarif"),
        lambda other: other["properties"].__setitem__("cwe", "CWE-79"),
    )
    findings = convert_sarif_to_findings(
        sarif,
        sarif_ref="mutated",
        run_id="run-test",
        timestamp="2026-07-21T00:00:00Z",
        variant="V0",
        model="deepseek/deepseek-chat",
        target="owasp-benchmark",
    )
    assert len({f.finding_id for f in findings}) == 2


def test_finding_id_no_collision_for_different_end_line_alone_same_cwe():
    sarif = _append_mutated_result(
        load_fixture("sample_metis.sarif"),
        lambda other: other["locations"][0]["physicalLocation"]["region"].__setitem__("endLine", 99),
    )
    findings = convert_sarif_to_findings(
        sarif,
        sarif_ref="mutated",
        run_id="run-test",
        timestamp="2026-07-21T00:00:00Z",
        variant="V0",
        model="deepseek/deepseek-chat",
        target="owasp-benchmark",
    )
    assert len({f.finding_id for f in findings}) == 2


def test_duplicate_identical_results_share_finding_id_and_are_logged(caplog):
    sarif = _append_mutated_result(load_fixture("sample_metis.sarif"), lambda other: None)
    with caplog.at_level("WARNING"):
        findings = convert_sarif_to_findings(
            sarif,
            sarif_ref="dup",
            run_id="run-test",
            timestamp="2026-07-21T00:00:00Z",
            variant="V0",
            model="m",
            target="owasp-benchmark",
        )
    assert len(findings) == 2
    assert findings[0].finding_id == findings[1].finding_id
    assert any("duplicate finding_id" in rec.message for rec in caplog.records)


def test_malformed_result_is_skipped_not_crashed(caplog):
    sarif = load_fixture("sample_metis.sarif")
    sarif["runs"][0]["results"][0]["message"] = "plain string message, not a dict"
    sarif["runs"][0]["results"][0]["locations"] = []  # force a real skip too, verified below
    with caplog.at_level("WARNING"):
        findings = convert_sarif_to_findings(
            sarif,
            sarif_ref="ref",
            run_id="r",
            timestamp="t",
            variant="V0",
            model="m",
            target="owasp-benchmark",
        )
    assert findings == []
    assert any("skipping" in rec.message for rec in caplog.records)


def test_plain_string_message_does_not_crash():
    sarif = load_fixture("sample_metis.sarif")
    sarif["runs"][0]["results"][0]["message"] = "plain string message"
    findings = convert_sarif_to_findings(
        sarif,
        sarif_ref="ref",
        run_id="r",
        timestamp="t",
        variant="V0",
        model="m",
        target="owasp-benchmark",
    )
    assert findings[0].message == "plain string message"


def test_null_short_description_does_not_crash():
    sarif = load_fixture("sample_metis.sarif")
    sarif["runs"][0]["tool"]["driver"]["rules"][0]["shortDescription"] = None
    findings = convert_sarif_to_findings(
        sarif,
        sarif_ref="ref",
        run_id="r",
        timestamp="t",
        variant="V0",
        model="m",
        target="owasp-benchmark",
    )
    assert findings[0].title  # falls back to message text, doesn't crash


def test_skip_log_collects_reasons_for_missing_locations():
    sarif = load_fixture("sample_metis.sarif")
    del sarif["runs"][0]["results"][0]["locations"]
    skip_log: list[dict] = []
    findings = convert_sarif_to_findings(
        sarif,
        sarif_ref="ref",
        run_id="r",
        timestamp="t",
        variant="V0",
        model="m",
        target="owasp-benchmark",
        skip_log=skip_log,
    )
    assert findings == []
    assert len(skip_log) == 1
    assert "no locations" in skip_log[0]["reason"]


def test_target_test_case_none_for_webgoat_target_even_if_path_matches():
    """target_test_case is documented as owasp-benchmark-only; must not leak for webgoat
    even if a WebGoat path coincidentally contains a BenchmarkTestNNNNN-like substring."""
    sarif = load_fixture("sample_metis.sarif")
    sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = (
        "org/owasp/benchmark/testcode/BenchmarkTest00123.java"
    )
    findings = convert_sarif_to_findings(
        sarif,
        sarif_ref="ref",
        run_id="r",
        timestamp="t",
        variant="V0",
        model="m",
        target="webgoat",
    )
    assert findings[0].target_test_case is None


def test_unrecognized_severity_tag_logs_and_defaults_to_info(caplog):
    with caplog.at_level("WARNING"):
        from findings.schema import normalize_severity

        result = normalize_severity("MODERATE")
    assert result == "info"
    assert any("unrecognized severity" in rec.message for rec in caplog.records)


def test_non_numeric_confidence_becomes_null_not_crash(caplog):
    sarif = load_fixture("sample_metis.sarif")
    sarif["runs"][0]["results"][0]["properties"]["confidence"] = "very-confident"
    with caplog.at_level("WARNING"):
        findings = convert_sarif_to_findings(
            sarif,
            sarif_ref="ref",
            run_id="r",
            timestamp="t",
            variant="V0",
            model="m",
            target="owasp-benchmark",
        )
    assert findings[0].confidence is None


def test_empty_sarif_yields_no_findings():
    findings = convert_sarif_to_findings(
        {"runs": []},
        sarif_ref="empty",
        run_id="run-test",
        timestamp="2026-07-21T00:00:00Z",
        variant="V0",
        model="m",
        target="webgoat",
    )
    assert findings == []


def test_multi_run_sarif_combines_all_runs():
    metis = load_fixture("sample_metis.sarif")
    saist = load_fixture("sample_saist.sarif")
    combined = {"runs": metis["runs"] + saist["runs"]}
    findings = convert_sarif_to_findings(
        combined,
        sarif_ref="combined",
        run_id="run-test",
        timestamp="2026-07-21T00:00:00Z",
        variant="V0",
        model="m",
        target="owasp-benchmark",
    )
    assert len(findings) == 2
    assert {f.tool for f in findings} == {"Metis", "datadog-ai-static-analyzer"}


def test_target_test_case_extracted_from_owasp_benchmark_path():
    sarif = load_fixture("sample_metis.sarif")
    sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = (
        "org/owasp/benchmark/testcode/BenchmarkTest00123.java"
    )
    findings = convert_sarif_to_findings(
        sarif,
        sarif_ref="ref",
        run_id="r",
        timestamp="t",
        variant="V0",
        model="m",
        target="owasp-benchmark",
    )
    assert findings[0].target_test_case == "BenchmarkTest00123"


def test_target_test_case_none_for_non_benchmark_path():
    findings = convert("sample_metis.sarif")
    assert findings[0].target_test_case is None


def test_missing_cwe_becomes_null():
    sarif = load_fixture("sample_metis.sarif")
    del sarif["runs"][0]["results"][0]["properties"]["cwe"]
    findings = convert_sarif_to_findings(
        sarif,
        sarif_ref="ref",
        run_id="r",
        timestamp="t",
        variant="V0",
        model="m",
        target="owasp-benchmark",
    )
    assert findings[0].cwe is None


def test_stage_status_defaults_to_validated_with_documented_caveat():
    findings = convert("sample_metis.sarif")
    assert findings[0].stage_status == "validated"


def test_findings_to_jsonl_one_record_per_line():
    from findings.sarif_to_jsonl import findings_to_jsonl

    findings = convert("sample_metis.sarif")
    lines = findings_to_jsonl(findings).splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["finding_id"] == findings[0].finding_id
