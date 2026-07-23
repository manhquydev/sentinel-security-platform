"""TDD for scoring/scorer.py. Fixtures pin a real 6-row subset of
expectedresults-1.2beta.csv (copied verbatim, see mini_expectedresults.csv) with
findings constructed to exercise each scoring rule:
- BenchmarkTest00001 (pathtraver/22, real): 2 duplicate-category findings -> must
  reduce to ONE TP, not two (no double-counting a test case).
- BenchmarkTest00003 (hash/328, real): 1 matching finding -> TP.
- BenchmarkTest00004 (trustbound/501, real): 1 finding with NO cwe -> CWE-scoped FN,
  CWE-agnostic TP (demonstrates the collapse a missing CWE tag causes).
- BenchmarkTest00016 (securecookie/614, fake): no findings -> TN.
- BenchmarkTest00008 (sqli/89, real): no findings -> FN (missed).
- BenchmarkTest00010 (weakrand/330, fake): 1 wrong-category (xss) finding ->
  CWE-scoped TN (no category match), CWE-agnostic FP (something was reported on
  a fake case regardless of category).
- A finding on BenchmarkTest09999 (not in expectedresults) -> skipped, not
  silently added as a phantom test case."""
import pathlib

from scoring.scorer import load_expectedresults, load_findings_jsonl, score_per_test_case

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def test_load_expectedresults_parses_real_csv_subset():
    expected = load_expectedresults(str(FIXTURES / "mini_expectedresults.csv"))
    assert len(expected) == 6
    assert expected["BenchmarkTest00001"].category == "pathtraver"
    assert expected["BenchmarkTest00001"].real is True
    assert expected["BenchmarkTest00001"].cwe == 22
    assert expected["BenchmarkTest00016"].real is False


def _load():
    expected = load_expectedresults(str(FIXTURES / "mini_expectedresults.csv"))
    findings = load_findings_jsonl(str(FIXTURES / "mini_findings.jsonl"))
    return expected, findings


def test_multiple_findings_on_one_test_case_reduce_to_single_tp_not_double_counted():
    expected, findings = _load()
    result = score_per_test_case(expected, findings)
    # pathtraver category has exactly 1 test case in the fixture; 2 findings on it
    # must still yield tp=1, not tp=2.
    assert result.cwe_scoped["pathtraver"].tp == 1
    assert result.cwe_scoped["pathtraver"].fp == 0


def test_cwe_scoped_overall_confusion_matrix():
    expected, findings = _load()
    result = score_per_test_case(expected, findings)
    overall = result.cwe_scoped["__overall__"]
    # TP: pathtraver(1), hash(3) = 2 ; FN: trustbound(4, no cwe), sqli(8, no finding) = 2
    # FP: 0 ; TN: securecookie(16), weakrand(10, wrong category) = 2
    assert (overall.tp, overall.fp, overall.fn, overall.tn) == (2, 0, 2, 2)
    assert overall.n == 6


def test_cwe_agnostic_overall_confusion_matrix_differs_from_scoped():
    expected, findings = _load()
    result = score_per_test_case(expected, findings)
    overall = result.cwe_agnostic["__overall__"]
    # TP: pathtraver, hash, trustbound(missing cwe still "reported") = 3
    # FN: sqli (no finding at all) = 1 ; FP: weakrand (wrong-category finding still counts) = 1
    # TN: securecookie = 1
    assert (overall.tp, overall.fp, overall.fn, overall.tn) == (3, 1, 1, 1)
    assert overall.n == 6


def test_missing_cwe_causes_scoped_vs_agnostic_divergence_on_same_test_case():
    """This is the concrete demonstration plan.md requires: a real finding with no
    machine-readable CWE must not silently become an invisible FN with no signal
    that CWE-agnostic would have counted it as a hit."""
    expected, findings = _load()
    result = score_per_test_case(expected, findings)
    assert result.cwe_scoped["trustbound"].fn == 1
    assert result.cwe_agnostic["trustbound"].tp == 1


def test_wrong_category_finding_is_fp_in_agnostic_but_not_scoped():
    expected, findings = _load()
    result = score_per_test_case(expected, findings)
    assert result.cwe_scoped["weakrand"].fp == 0
    assert result.cwe_scoped["weakrand"].tn == 1
    assert result.cwe_agnostic["weakrand"].fp == 1
    assert result.cwe_agnostic["weakrand"].tn == 0


def test_finding_on_unknown_test_case_is_skipped_not_phantom_category():
    expected, findings = _load()
    result = score_per_test_case(expected, findings)
    assert result.unmatched_test_cases == ["BenchmarkTest09999"]
    # every category key in the result must be one of the 6 real fixture categories + overall
    real_categories = {c.category for c in expected.values()} | {"__overall__"}
    assert set(result.cwe_scoped.keys()) <= real_categories
    assert set(result.cwe_agnostic.keys()) <= real_categories


def test_category_match_not_raw_cwe_int_equality():
    """Mechanism test (not real-distribution test): the real 1.2beta CSV happens to
    have a clean 1:1 category<->cwe mapping (verified: 11 categories, 11 distinct
    pairs), so this exact multi-CWE-per-category scenario doesn't occur in real
    data this round. This test verifies the matching *mechanism* still works if it
    ever did, by using a temporarily patched map - it does not claim this is
    real OWASP Benchmark data."""
    import scoring.cwe_category_map as cwe_map

    original = dict(cwe_map.CWE_TO_CATEGORY)
    try:
        cwe_map.CWE_TO_CATEGORY[9001] = "pathtraver"  # synthetic second CWE for the same category
        expected, findings = _load()
        findings = findings + [
            {"finding_id": "f-synthetic", "target_test_case": "BenchmarkTest00001", "target": "owasp-benchmark", "cwe": 9001}
        ]
        result = score_per_test_case(expected, findings)
        # still exactly 1 TP for pathtraver: a different CWE mapping to the same
        # category doesn't create a second unit, and correctly matches by category.
        assert result.cwe_scoped["pathtraver"].tp == 1
    finally:
        cwe_map.CWE_TO_CATEGORY.clear()
        cwe_map.CWE_TO_CATEGORY.update(original)
