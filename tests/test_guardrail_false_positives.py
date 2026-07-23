"""Guards on the false-positive measurement itself.

The measurement currently reports zero unambiguous false positives. That number is only
worth anything if the thing producing it is capable of producing a different one, so most
of what is asserted here is that the oracles fire — a dead oracle reports zero forever and
looks like success.

The one that matters historically: a length-only JWT pattern rewrote Java package paths
into a redaction placeholder. One instance was caught by hand during review. Running the
measurement against that pattern finds thirty-six, across real WebGoat source, which is
the difference between review and measurement.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = ROOT / "evaluation" / "false-positive" / "measure-false-positives.py"

sys.path.insert(0, str(ROOT / "infra" / "litellm" / "guardrails"))


def load_harness():
    # Loaded by path: the filename is kebab-case because it is a script, not a module
    # anything imports by name.
    spec = importlib.util.spec_from_file_location("measure_false_positives", HARNESS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


harness = load_harness()


# --- the oracles must be able to fire -------------------------------------------


@pytest.mark.parametrize(
    "line, expected",
    [
        ("package org.owasp.webgoat.lessons.sqlinjection;", "java-dotted-identifier"),
        ("import organization.applications.configuration.LoaderFactory;", "java-dotted-identifier"),
        ("import static java.util.Collections.emptyList;", "java-dotted-identifier"),
        ("  artifact sha256: 9f3a55e5fa27e6c53d68f5241b462ca80e00e2629459f9277cb9a0a267c9dc6f", "hash-context"),
        ("org.springframework.boot:spring-boot-starter-web:3.2.1", "dependency-coordinate"),
    ],
)
def test_each_structural_oracle_fires(line, expected):
    """A dead oracle reports zero false positives forever and looks like success."""
    assert harness.classify(line, "webgoat-java") == expected


def test_oracle_does_not_fire_on_a_line_that_could_hold_a_credential():
    """Over-broad oracles would suppress real findings, which is the opposite failure."""
    assert harness.classify('String password = "hunter2";', "webgoat-java") is None


def test_committed_artifact_corpus_is_treated_as_proven_secret_free():
    """The attack-surface exporter refuses forbidden fields, path tokens and opaque
    segments, and its own suite proves each control fails when it should. Anything
    redacted there is wrong by construction."""
    assert harness.classify("any line at all", "attack-surface-baseline") == "proven-secret-free-artifact"


# --- the properties the measurement asserts about the live guardrail -------------


def test_no_attack_payload_is_mangled():
    """This system's legitimate cargo is exploit strings. Mangling one degrades every
    downstream result with no signal that anything happened."""
    result = harness.measure(ROOT)
    assert result["attack_payload_preservation"]["mangled"] == []


def test_no_unambiguous_false_positives_on_the_real_corpus():
    result = harness.measure(ROOT)
    fp = result["unambiguous_false_positives"]
    assert fp["count"] == 0, f"guardrail altered content that cannot hold a credential: {fp['by_oracle']}"


def test_the_corpus_is_actually_present():
    """A measurement over an empty corpus reports zero of everything. If the WebGoat
    source is absent the number above is vacuous, so the absence must fail loudly rather
    than read as a clean result."""
    result = harness.measure(ROOT)
    webgoat = result["corpus"].get("webgoat-java")
    assert webgoat and webgoat["documents"] > 100, (
        "the Java corpus is missing or truncated; a zero false-positive count over it "
        "would mean nothing"
    )


# --- the recorded baseline must describe the current guardrail -------------------


def test_recorded_baseline_matches_what_the_harness_measures_now():
    """Not an exact-match gate on the alteration rate — that is expected to move when a
    detector legitimately changes. What must not drift silently is the set of detectors
    firing on real content, because a detector appearing or vanishing is a behaviour
    change someone should have noticed."""
    recorded = json.loads(
        (ROOT / "evaluation" / "false-positive" / "baseline-2026-07-23.json").read_text(encoding="utf-8")
    )
    current = harness.measure(ROOT)
    assert set(current["redactions_by_detector"]) == set(recorded["redactions_by_detector"]), (
        "the set of detectors firing on the real corpus changed; re-record the baseline "
        "as part of whatever change caused it"
    )
