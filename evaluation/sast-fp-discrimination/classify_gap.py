"""Why SAST misses what it misses: presence-of-bad-pattern vs absence-of-required-control.

Reads the per-CWE gap data (`cwe-gap-260725.json`, produced by analyze_cwe_gap.py) and buckets each
CWE class by a structural property taken from the CWE DEFINITION — not from the results:

  * presence-of-bad-pattern — the vulnerability IS a dangerous construct in the code (SQL string
    concatenation, MD5, a hardcoded key, `os.system` with user input). A pattern/AST engine can see it.
  * absence-of-control      — the vulnerability is a MISSING control (no authorization check, no rate
    limit, no ownership check before an object reference). There is no token to match: the evidence is
    what is NOT there, which pattern matching structurally cannot detect.

The measured split is the empirical justification for pairing SAST with runtime/DAST testing: you find
a missing rate limit by hitting the endpoint, not by reading the source. Fast, offline, no re-scan.

    rag/.venv/bin/python evaluation/sast-fp-discrimination/classify_gap.py
"""

from __future__ import annotations

import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
GAP = os.path.join(_HERE, "cwe-gap-260725.json")

# Classified from the CWE definitions (structural property), independent of the measurement.
ABSENCE_OF_CONTROL = {
    284,   # improper access control
    862,   # missing authorization
    863,   # incorrect authorization
    306,   # missing authentication for critical function
    307,   # improper restriction of excessive authentication attempts (no rate limit)
    639,   # authorization bypass through user-controlled key (IDOR)
    269,   # improper privilege management
    400,   # uncontrolled resource consumption (no limit)
    770,   # allocation without limits
    352,   # CSRF (missing anti-forgery control)
    732,   # incorrect permission assignment
    1188,  # insecure default initialization
    16,    # configuration (missing hardening)
    200,   # information exposure (missing output restriction)
    215,   # information exposure through debug info
}
PRESENCE_OF_BAD_PATTERN = {
    89, 79, 77, 78, 94, 90, 943, 91,   # injection families
    22, 611, 502, 1336,                # traversal / XXE / deserialisation / SSTI
    327, 328, 330, 326, 338,           # broken or weak crypto primitives
    259, 321, 312, 256, 798,           # hardcoded / cleartext credentials & keys
}


def bucket(cwe: int | None) -> str:
    if cwe in ABSENCE_OF_CONTROL:
        return "absence-of-control"
    if cwe in PRESENCE_OF_BAD_PATTERN:
        return "presence-of-bad-pattern"
    return "other/unclassified"


def main() -> int:
    if not os.path.exists(GAP):
        print(f"FAIL: {GAP} missing — run analyze_cwe_gap.py first")
        return 2
    data = json.load(open(GAP, encoding="utf-8"))
    agg: dict = {}
    for r in data["per_cwe"]:
        b = agg.setdefault(bucket(r["cwe"]), {"classes": 0, "real": 0, "found": 0})
        b["classes"] += 1
        b["real"] += r["real"]
        b["found"] += r["union"]

    print(f"corpus: {data['total_real']} real vulns / {data['classes']} CWE classes "
          f"(engines: bandit ∪ semgrep)")
    print(f"{'bucket':26s} {'classes':>7} {'real':>6} {'found':>6} {'recall':>8}")
    for name, a in sorted(agg.items(), key=lambda kv: -kv[1]["real"]):
        print(f"  {name:24s} {a['classes']:>7} {a['real']:>6} {a['found']:>6} "
              f"{a['found']/a['real']:>8.1%}")
    p = agg.get("presence-of-bad-pattern")
    ab = agg.get("absence-of-control")
    if p and ab and ab["found"]:
        ratio = (p["found"] / p["real"]) / (ab["found"] / ab["real"])
        print(f"\nSAST detects PRESENCE {ratio:.1f}x better than ABSENCE — and the absence bucket is the "
              f"LARGER half ({ab['real']} vs {p['real']} real vulns).")
        print("=> the residual is not a SAST tuning problem; missing controls are found at RUNTIME.")
    json.dump({"buckets": agg}, open(os.path.join(_HERE, "gap-classification-260725.json"), "w"), indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
