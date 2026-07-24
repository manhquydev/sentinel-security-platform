"""Week-9 PII-redaction measurement (decision 0017, invariant PA5).

Two independent numbers, never one aggregate (the Week-7 discipline):

  * RECALL — of the corpus items the policy says MUST be redacted, how many did `agent.pii` catch
    (correct class placeholder present, raw PII shape gone). Threshold: 1.0 for the covered shapes.
  * FALSE-POSITIVE — of the items the policy says MUST be preserved (legitimate security content,
    non-card numeric IDs, file hashes), how many did the redactor alter. Threshold: 0.

Documented GAP shapes (bare positional PAN, phone — deferred to decision 0016) are reported but
never counted against recall; the run only NOTES if a gap's status changed, so the boundary stays
visible without a tautological score.

Fails closed (non-zero exit) if the corpus is missing or empty — a "0% FP over an absent corpus" is
the exact vacuous-measurement failure this project has already journaled. This is the regression
guard `tests/week9-pii-eval-test.sh` asserts.

    rag/.venv/bin/python -m evaluation.pii-redaction.measure   # from repo root
"""

from __future__ import annotations

import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from agent import pii  # noqa: E402

CORPUS = os.path.join(os.path.dirname(__file__), "corpus.json")
RECALL_MIN = 1.0   # every COVERED shape must be caught
FP_MAX = 0         # zero alteration of legitimate security content (decision 0006)


def _load_items() -> list[dict]:
    if not os.path.exists(CORPUS):
        print(f"FAIL: corpus not found at {CORPUS} — refusing to report over an absent corpus")
        sys.exit(2)
    with open(CORPUS, encoding="utf-8") as f:
        items = json.load(f).get("items", [])
    if not items:
        print("FAIL: corpus is empty — refusing to report a vacuous 0% FP")
        sys.exit(2)
    return items


def measure(items: list[dict]) -> dict:
    recall_total = recall_hit = 0
    fp_total = fp_hit = 0
    gaps: list[dict] = []
    fp_examples: list[dict] = []
    recall_misses: list[dict] = []

    for it in items:
        text = it["text"]
        out, findings = pii.redact(text)
        classes = {f.cls for f in findings}
        policy = it["policy"]

        if policy == "redact":
            recall_total += 1
            want = it["cls"]
            caught = f"[redacted:pii:{want}]" in out and want in classes
            if caught:
                recall_hit += 1
            else:
                recall_misses.append({"cls": want, "text": text, "out": out})
        elif policy == "preserve":
            fp_total += 1
            if out != text:
                fp_hit += 1
                fp_examples.append({"text": text, "out": out})
        elif policy == "gap":
            gaps.append({"cls": it.get("cls"), "still_gap": out == text, "text": text})

    return {
        "recall": {"hit": recall_hit, "total": recall_total,
                   "rate": (recall_hit / recall_total) if recall_total else 1.0,
                   "misses": recall_misses},
        "false_positive": {"hit": fp_hit, "total": fp_total, "examples": fp_examples},
        "gaps": gaps,
    }


def main() -> int:
    r = measure(_load_items())
    print(json.dumps({k: (v if k == "gaps" else {kk: vv for kk, vv in v.items() if kk != "misses" or vv})
                      for k, v in r.items()}, indent=2))
    ok = r["recall"]["rate"] >= RECALL_MIN and r["false_positive"]["hit"] <= FP_MAX
    changed = [g for g in r["gaps"] if not g["still_gap"]]
    if changed:
        # An improvement, not a failure — but surface it so the documented boundary gets updated.
        print(f"NOTE: {len(changed)} documented gap(s) are now caught — update decision 0017's gap list.")
    print(f"\nRESULT: recall={r['recall']['hit']}/{r['recall']['total']} "
          f"FP={r['false_positive']['hit']}/{r['false_positive']['total']} "
          f"-> {'PASS' if ok else 'FAIL'} (recall_min={RECALL_MIN}, fp_max={FP_MAX})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
