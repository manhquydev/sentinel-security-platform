"""Re-derive every stored verdict from its own stored prose, and reconcile the headline statistics.

A verdict in a committed artefact is not raw data. It is a *derived* value: the deterministic classifier
applied to the model's prose, which IS the raw data. So every time the classifier is fixed, every stored
verdict silently becomes a claim about an instrument that no longer exists.

That drift was found, not anticipated. Eleven rows across nine artefacts disagreed with their own prose,
and it had cut both ways: one arm's headline was too high (a response that merely echoed the file back
inside a code fence had been scored as a finding, before code spans were stripped), while another arm's
control count was too high (a false positive the fixed classifier correctly clears). Being wrong in the
flattering direction on one number and the unflattering direction on another is what makes this a
systematic defect rather than a lucky or unlucky rounding.

Re-derivation is deterministic and makes no model call: the prose is fixed, only the reading of it moves.
What each artefact published is preserved under `superseded` so the correction stays auditable — the point
is not to make the old number disappear, it is to make the change visible.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/rescore_artefacts.py [--write]
"""

from __future__ import annotations

import glob
import json
import os
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.abspath(os.path.join(_HERE, "..", "..")), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import run_generative as rg  # noqa: E402
from stats import fisher_one_sided  # noqa: E402

# Statistics that are functions of the verdicts. When a verdict moves, these are stale by definition, so
# they are recomputed rather than left to be spotted by a reader comparing two numbers by eye.
_DERIVED = ("counts", "flag_rate_vulnerable", "flag_rate_clean", "separation",
            "tp", "fp", "sensitivity", "false_positive_rate", "fisher_p_one_sided",
            "arm_a_prime", "arm_c", "difference")


def recompute(doc: dict) -> None:
    """Rebuild the verdict-derived statistics in place, for whichever schema the artefact uses.

    Only keys the artefact already published are rebuilt. Inventing a statistic an experiment never
    claimed would quietly widen its conclusions, which is the opposite of the point.
    """
    rows = _rows(doc)
    flagged = lambda rs: sum(1 for r in rs if r["verdict"] == "flagged")  # noqa: E731

    if "counts" in doc and all("arm" in r for r in rows):   # arm-labelled discrimination runs
        counts: dict[str, dict[str, int]] = {}
        for r in rows:
            counts.setdefault(r["arm"], {}).setdefault(r["verdict"], 0)
            counts[r["arm"]][r["verdict"]] += 1
        doc["counts"] = counts
        for key, arm in (("flag_rate_vulnerable", "positive"), ("flag_rate_clean", "negative")):
            if key in doc and arm in counts:
                # The denominator is answered files only — flagged + clean. That is the estimand these
                # artefacts were published under, and reconciling a verdict is not licence to change it:
                # switching to "all files scored" silently converts a flag rate into a sensitivity and
                # would have restated a published figure while claiming to have only re-read it.
                # Non-answers are a separate measured quantity; the conservative sensitivity that counts
                # them as misses is reported in the log, not here.
                answered = counts[arm].get("flagged", 0) + counts[arm].get("clean", 0)
                doc[key] = round(counts[arm].get("flagged", 0) / answered, 4) if answered else None
        if "separation" in doc:
            doc["separation"] = round((doc.get("flag_rate_vulnerable") or 0)
                                      - (doc.get("flag_rate_clean") or 0), 4)

    if "tp" in doc and all("truth" in r for r in rows):     # matched-pair authored sets
        vuln = [r for r in rows if r["truth"] == "vulnerable"]
        ctrl = [r for r in rows if r["truth"] == "controlled"]
        tp, fp = flagged(vuln), flagged(ctrl)
        doc["tp"], doc["fp"] = tp, fp
        if "sensitivity" in doc:
            doc["sensitivity"] = round(tp / len(vuln), 4) if vuln else None
        if "false_positive_rate" in doc:
            doc["false_positive_rate"] = round(fp / len(ctrl), 4) if ctrl else None
        if "fisher_p_one_sided" in doc:
            doc["fisher_p_one_sided"] = round(
                fisher_one_sided(tp, len(vuln) - tp, fp, len(ctrl) - fp), 4)

    if "arm_a_prime" in doc:                               # two-arm role controls
        by_arm = {}
        for r in rows:
            by_arm.setdefault(r["arm"], []).append(r)
        for key, arm in (("arm_a_prime", "A_prime_handlers_with_absence"),
                         ("arm_c", "C_handlers_without_absence")):
            if key in doc and arm in by_arm:
                doc[key] = {"flagged": flagged(by_arm[arm]), "n": len(by_arm[arm])}
        a, c = doc.get("arm_a_prime"), doc.get("arm_c")
        if a and c:
            if "difference" in doc:
                doc["difference"] = round(a["flagged"] / a["n"] - c["flagged"] / c["n"], 4)
            if "fisher_p_one_sided" in doc:
                doc["fisher_p_one_sided"] = round(fisher_one_sided(
                    a["flagged"], a["n"] - a["flagged"], c["flagged"], c["n"] - c["flagged"]), 4)


def _rows(doc: dict) -> list[dict]:
    """Every record in the document that carries both a stored verdict and the prose it came from."""
    out = []
    for value in doc.values():
        if isinstance(value, list):
            out += [r for r in value
                    if isinstance(r, dict) and "verdict" in r and isinstance(r.get("response"), str)]
    return out


def truncated(doc: dict) -> bool:
    """True if this artefact's stored prose was cut off when it was written.

    An early harness wrote only the first 400 characters of each response. Re-deriving a verdict from
    that is not reconciliation — the classifier would be reading text the original verdict was never
    based on, and would "correct" a sound verdict into a wrong one using evidence that was destroyed.
    These artefacts can only be reported as unverifiable, which is what the log already says about them.
    """
    lens = [len(r["response"]) for r in _rows(doc)]
    return bool(lens) and sum(1 for n in lens if n == 400) > 0.05 * len(lens)


def drifted(doc: dict) -> list[tuple[dict, str]]:
    """Rows whose stored verdict disagrees with re-reading their own prose."""
    out = []
    for r in _rows(doc):
        now = rg.classify_prose(r["response"])
        if now != r["verdict"]:
            out.append((r, now))
    return out


def main() -> int:
    write = "--write" in sys.argv
    total = 0
    for path in sorted(glob.glob(os.path.join(_HERE, "*.json"))):
        name = os.path.basename(path)
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        if not _rows(doc):
            continue
        if truncated(doc):
            print(f"  {name:36} rows={len(_rows(doc)):4} SKIPPED — stored prose is truncated, "
                  "so its verdicts cannot be re-derived from it")
            continue
        drift = drifted(doc)
        print(f"  {name:36} rows={len(_rows(doc)):4} drift={len(drift)}")
        for r, now in drift:
            who = r.get("file", "?")
            print(f"      {who}: {r['verdict']} -> {now}")
        total += len(drift)
        if drift and write:
            # Keep what was published. A correction that erases the previous number cannot be audited,
            # and the direction of a correction is itself evidence about the lab.
            doc.setdefault("superseded", {})[datetime.now(timezone.utc).isoformat()] = {
                "reason": "verdicts re-derived from stored prose after classifier fixes",
                "previous": {k: doc[k] for k in _DERIVED if k in doc},
                "rows_changed": [{"file": r.get("file"), "from": r["verdict"], "to": now}
                                 for r, now in drift],
            }
            for r, now in drift:
                r["verdict"] = now
            recompute(doc)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, indent=2)

    print(f"\ntotal drifted rows: {total}")
    if total and not write:
        print("re-run with --write to reconcile (previous values are preserved under 'superseded')")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
