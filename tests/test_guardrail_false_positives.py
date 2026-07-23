"""Guards on the false-positive measurement itself.

The measurement reports zero unambiguous false positives. That number is worth something
only if the thing producing it can produce a different one, so most of what is asserted
here is that the machinery is live. A dead oracle, an empty corpus, or a pipeline that
never reaches the oracles all report zero forever and look like success.

Three of these tests exist because a review found ways the zero could be wrong:
the oracles judged whole lines rather than the matched span, so a correct redaction
sharing a line with a dotted identifier was cleared as a false positive; the corpus could
vanish silently and take the number with it; and nothing exercised the pipeline
end-to-end against a guardrail that should produce findings.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = ROOT / "evaluation" / "false-positive" / "measure-false-positives.py"
BASELINE = ROOT / "evaluation" / "false-positive" / "baseline-2026-07-23.json"

sys.path.insert(0, str(ROOT / "infra" / "litellm" / "guardrails"))
import egress_redaction  # noqa: E402


def load_harness():
    # Loaded by path: the filename is kebab-case because it is a script, not a module
    # anything imports by name.
    spec = importlib.util.spec_from_file_location("measure_false_positives", HARNESS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


harness = load_harness()

# The corpus lives outside git: `benchmark/targets/` and `scanners/out/` are ignored, so
# a fresh clone has almost none of it. Tests that would otherwise pass over an empty
# corpus must skip instead — a vacuous pass is the failure mode this whole file exists to
# prevent.
CORPUS_PRESENT = (ROOT / "benchmark" / "targets" / "webgoat-src").is_dir()
needs_corpus = pytest.mark.skipif(
    not CORPUS_PRESENT,
    reason="measurement corpus is not in git; see evaluation/README.md for provisioning",
)


# --- the oracles must be able to fire, and must not over-fire --------------------


@pytest.mark.parametrize(
    "line, matched, expected",
    [
        ("package org.owasp.webgoat.lessons.sqlinjection;",
         "org.owasp.webgoat.lessons.sqlinjection", "java-dotted-identifier"),
        ("import organization.applications.configuration.LoaderFactory;",
         "organization.applications.configuration", "java-dotted-identifier"),
        ("import static java.util.Collections.emptyList;",
         "java.util.Collections.emptyList", "java-dotted-identifier"),
        ("  artifact sha256: 9f3a55e5fa27e6c53d68f5241b462ca80e00e2629459f9277cb9a0a267c9dc6f",
         "9f3a55e5fa27e6c53d68f5241b462ca80e00e2629459f9277cb9a0a267c9dc6f", "hash-context"),
        ("org.springframework.boot:spring-boot-starter-web:3.2.1",
         "spring-boot-starter-web", "dependency-coordinate"),
    ],
)
def test_each_structural_oracle_fires(line, matched, expected):
    """A dead oracle reports zero false positives forever and looks like success.

    `matched` is the substring a detector would have acted on, so the span handed to the
    oracle is the shape it sees in production rather than a whole line.
    """
    start = line.index(matched)
    assert harness.classify(line, (start, start + len(matched)), "webgoat-java") == expected


@pytest.mark.parametrize(
    "line",
    [
        # Each of these is a real credential sharing a line with something an oracle
        # recognises. Judging by the line rather than the matched span cleared all four,
        # which would report correct redactions as false positives — and the natural
        # response to a false alarm is to narrow the detector, which is how a leak ships.
        "import org.foo.Bar; // password=hunter2SuperSecret",
        'String pw = "abc"; // sha256: 0123456789abcdef0123456789abcdef',
        "cookie: JSESSIONID=deadbeef  md5=0123456789abcdef01",
        "password:hunter2:2024",
    ],
)
def test_a_real_credential_is_not_cleared_by_an_oracle_sharing_its_line(line):
    cleared = [
        harness.classify(m["line"], m["span"], "webgoat-java")
        for m in harness.locate_matches(line)
    ]
    assert not any(cleared), f"a correct redaction was reported as a false positive: {cleared}"


def test_committed_artifact_corpus_is_treated_as_proven_secret_free():
    assert harness.classify("any line", (0, 3), "attack-surface-baseline") == "proven-secret-free-artifact"


# --- line attribution must survive a detector that collapses lines ---------------


def test_a_line_collapsing_match_does_not_shift_later_attributions():
    """Redaction is not line-preserving: the PEM detector spans newlines and collapses a
    key block to one placeholder. Reading line numbers back out of `redact()` — whose
    passes each run over the previous pass's output — attributed later findings to
    whatever line had drifted into that position, so an oracle could inspect an unrelated
    line. Measuring against the original document is what removes the shift."""
    doc = (
        "line one\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "AAAA\n"
        "BBBB\n"
        "-----END RSA PRIVATE KEY-----\n"
        "filler\n"
        "String p = \"x\"; password=topsecretvalue\n"
    )
    matches = {m["detector"]: m["line_number"] for m in harness.locate_matches(doc)}
    assert matches["pem-private-key"] == 2
    assert matches["assignment"] == 7, (
        f"the credential is on line 7 of the original; attributed to {matches.get('assignment')}"
    )


# --- the pipeline, not just its parts, must be shown to work ---------------------


@needs_corpus
def test_reintroducing_the_known_bug_makes_the_measurement_report_it(monkeypatch):
    """The end-to-end proof. Everything else checks a component; this checks that a
    guardrail defect actually reaches the reported number.

    The pattern below is the one that shipped: three dotted segments of ten-plus
    characters is a JWT and also a Java package path. One instance was caught by hand in
    review; the measurement finds them all.
    """
    monkeypatch.setattr(
        egress_redaction,
        "_JWT",
        re.compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    )
    result = harness.measure(ROOT)
    fp = result["unambiguous_false_positives"]
    assert fp["count"] > 0, "a known guardrail defect did not reach the reported number"
    assert "java-dotted-identifier" in fp["by_oracle"]


# --- the properties asserted about the live guardrail ----------------------------


def test_no_attack_payload_is_mangled():
    """This system's legitimate cargo is exploit strings. Mangling one degrades every
    downstream result with no signal that anything happened. Independent of the corpus:
    the payloads are fixtures."""
    assert harness.measure(ROOT)["attack_payload_preservation"]["mangled"] == []


@needs_corpus
def test_no_unambiguous_false_positives_on_the_real_corpus():
    fp = harness.measure(ROOT)["unambiguous_false_positives"]
    assert fp["count"] == 0, f"guardrail altered content that cannot hold a credential: {fp['by_oracle']}"


@needs_corpus
def test_every_corpus_is_present_in_the_expected_size():
    """Each corpus is asserted separately. Guarding only the largest let the other three
    disappear without a sound — and the one with an unconditional oracle, whose absence
    would be least visible, is the smallest."""
    corpus = harness.measure(ROOT)["corpus"]
    expected = {"webgoat-java": 300, "sanitized-scanner-report": 3, "attack-surface-baseline": 1}
    for name, minimum in expected.items():
        assert name in corpus, f"corpus '{name}' vanished; the reported zero would be vacuous"
        assert corpus[name]["documents"] >= minimum, (
            f"corpus '{name}' has {corpus[name]['documents']} documents, expected at least {minimum}"
        )


@needs_corpus
def test_the_two_counting_paths_agree():
    """`redactions_located` walks the detectors over the original document;
    `redactions_by_detector` counts what `redact()` reported. They are computed
    independently, so agreement is corroboration rather than arithmetic — an earlier
    version derived both from the same list, where equality held by construction and
    proved nothing."""
    result = harness.measure(ROOT)
    located = sum(c["redactions_located"] for c in result["corpus"].values())
    reported = sum(result["redactions_by_detector"].values())
    assert located == reported, f"located {located} matches but redact() reported {reported}"


@needs_corpus
def test_recorded_baseline_matches_what_the_harness_measures_now():
    """Not an exact-match gate on the rate — that is expected to move when a detector
    legitimately changes. What must not drift silently is the set of detectors firing on
    real content, because one appearing or vanishing is a behaviour change."""
    recorded = json.loads(BASELINE.read_text(encoding="utf-8"))
    current = harness.measure(ROOT)
    assert set(current["redactions_by_detector"]) == set(recorded["redactions_by_detector"]), (
        "the set of detectors firing on the real corpus changed; re-record the baseline "
        "as part of whatever change caused it"
    )
