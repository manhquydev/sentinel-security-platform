"""CWE -> OWASP Benchmark category map, derived from the real
targets/owasp-benchmark/expectedresults-1.2beta.csv (verified: exactly 11
distinct (category, cwe) pairs across all 2740 rows in this benchmark version,
a clean 1:1 mapping). Matching must go through category, not raw CWE-int
equality, because a tool may report a CWE that's semantically the same
vulnerability class but a different specific number than BenchmarkJava's pick
for that category (plan.md red-team finding #3). If a future OWASP Benchmark
version introduces multiple CWEs per category, extend this map accordingly —
it is not derived from documentation, it is pinned from the real CSV."""
from __future__ import annotations

CWE_TO_CATEGORY: dict[int, str] = {
    # --- BenchmarkJava's own pick per category (the 11 pairs in the CSV) ---
    78: "cmdi",
    327: "crypto",
    328: "hash",
    90: "ldapi",
    22: "pathtraver",
    614: "securecookie",
    89: "sqli",
    501: "trustbound",
    330: "weakrand",
    643: "xpathi",
    79: "xss",

    # --- Semantically equivalent CWEs a tool may legitimately report instead ---
    #
    # Added 2026-07-23 after independent review found this map was an identity map
    # of the CSV, directly contradicting the docstring above: a correct detection
    # reported under a more specific CWE was being scored as a miss. All 60 sol
    # weakrand false-negatives were CWE-338 reports, and 41 of the hash
    # false-negatives were CWE-916/759 - detections the scorer rejected on the
    # number rather than the finding.
    #
    # Admission rule, applied to keep this honest rather than score-improving: only
    # a CWE in a direct parent/child or sibling relationship with the category's
    # own CWE, describing the SAME weakness. Deliberately rejected, with reasons:
    #   1004 (HttpOnly cookie) seen on weakrand cases - a different vulnerability
    #        the model found in the same file, not a weakrand detection
    #   200/20 (info exposure, input validation) - too generic to attribute
    #   134 (format string) on xss, 15 on cmdi, 915/472 on trustbound - distinct classes
    #   327 seen on hash cases - already maps to `crypto`; weak-hash and risky-algorithm
    #        genuinely overlap in the CWE taxonomy, so remapping it would trade hash
    #        false-negatives for crypto ones rather than fix anything
    338: "weakrand",     # Weak PRNG - child of CWE-330
    916: "hash",         # Password hash w/ insufficient computational effort
    759: "hash",         # One-way hash without salt
    760: "hash",         # One-way hash with predictable salt
    73: "pathtraver",    # External control of file name or path - sibling of CWE-22
}


def cwe_to_category(cwe: int | None) -> str | None:
    if cwe is None:
        return None
    return CWE_TO_CATEGORY.get(cwe)
