"""Is the generative-role capability class-uniform, or concentrated in particular absence classes?

Decision 0027 was narrowed to "absent ownership and absent authentication" on the strength of an
authored matched-pair set in which the model found ownership 4/4 and authentication 2/2 but missed rate
limiting, mass assignment, error-path leakage and re-authentication 0/4. Four files decided that
narrowing. CWE-307 (no limit on authentication attempts) is the single most common absence class in the
corpus, so if the narrowing is right it matters commercially, and if it is an artefact of four authored
files it is misleading in the direction of underselling.

DESIGN — paired WITHIN a file. Every file here carries, in its ground truth, both an ownership or
authentication class AND CWE-307. One reading of the file produces one piece of prose, and both
questions are read off that same prose: did it say the ownership/authn control is absent, did it say the
rate limit is absent. File difficulty, framework, size, style and the instrument's own churn are held
fixed by construction, because there is only ever one response per file. That is why a single reading per
file is enough here and would not be in an unpaired design.

THIS IS AN ESTIMATION, NOT A TEST, AND THE DIFFERENCE IS PREREGISTERED. The significance test of this
same question was cancelled at the power gate: against the rates actually measured on existing data
(ownership/authn named on 13.3% of absence-arm files, CWE-307 on 3.3%), paired McNemar over these 53
files reaches 43% power, and the k=3 variant reaches 80% only under an independence assumption that E31
already falsified by measuring the churn. So no p-value is claimed here. What is reported is the pair of
rates and a paired bootstrap interval on their difference. If that interval excludes zero it is
suggestive and needs replication before anything rests on it; it is not a powered confirmation.

Class attribution uses `names_class_absence`, which requires the class term and an absence marker in the
same sentence window with the reassurance test first. Bare vocabulary matching was measured firing on
3-8% of prose in which the model had concluded the file was fine — that is the regex talking, not the
model. CWE-200 is excluded from attribution entirely: its vocabulary ("disclose", "leak", "expose") fires
almost as often on all-clear prose as on defect claims and cannot carry a class claim.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/run_class_asymmetry.py
"""

from __future__ import annotations

import json
import os
import random
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import run_spike as rs  # noqa: E402
from agent import trace  # noqa: E402
from run_generative import (MAX_BYTES, _BINARY_RUBRIC, _CANARY_SRC, _load_gt_index,
                            classify_prose, names_class_absence)  # noqa: E402

# Ownership / authorization / authentication absence. CWE-200 is deliberately absent from both groups:
# it is neither the comparison class nor trustworthy enough to fold into the ownership group.
OWN_AUTHN = {639, 862, 863, 285, 284, 306, 287}
RATE_LIMIT = 307


def paired_files() -> list[tuple[str, str, set[int]]]:
    """Corpus files whose ground truth carries BOTH an ownership/authn class and CWE-307."""
    out = []
    for (slug, relpath), entries in _load_gt_index().items():
        cwes: set[int] = set()
        for e in entries:
            if e["is_vulnerable"]:
                cwes |= set(e["cwes"])
        if cwes & OWN_AUTHN and RATE_LIMIT in cwes:
            out.append((slug, relpath, cwes))
    out.sort()
    return out


def paired_bootstrap(pairs: list[tuple[bool, bool]], seed: int = 13, draws: int = 20000):
    """Interval on (rate_own - rate_307), resampling FILES so the pairing is never broken apart."""
    rnd = random.Random(seed)
    n = len(pairs)
    diffs = []
    for _ in range(draws):
        sample = [pairs[rnd.randrange(n)] for _ in range(n)]
        diffs.append(sum(o for o, _ in sample) / n - sum(r for _, r in sample) / n)
    diffs.sort()
    return diffs[int(0.025 * draws)], diffs[int(0.975 * draws)]


def main() -> int:
    if not os.path.isdir(rs.REPOS):
        print(f"FAIL: corpus not fetched — run {os.path.join(_HERE, 'fetch.sh')}")
        return 2
    if not os.environ.get("LITELLM_MASTER_KEY"):
        print("FAIL: no gateway credential — a zero from a dead model is not a measurement.")
        return 2
    model = os.environ.get("RECON_MODEL", "sast-grok45")
    from agent import llm

    def query(slug, relpath, literal=None):
        if literal is not None:
            body = literal
        else:
            try:
                src = open(os.path.join(rs.REPOS, slug, relpath), encoding="utf-8",
                           errors="replace").read()[:MAX_BYTES]
            except OSError:
                return ""
            body = "\n".join(f"{i+1}: {ln}" for i, ln in enumerate(src.splitlines()))
        try:
            return llm.chat([llm.Msg("system", _BINARY_RUBRIC, llm.operator()),
                             llm.Msg("user", f"file: {relpath}\n\n{body}",
                                     llm.target_derived(source="corpus-file", target=slug))],
                            model=model, max_tokens=160, temperature=0.0)
        except Exception:
            return ""

    # A run that measures a dead harness reports zeros that look exactly like a negative result. This
    # lab has published one of those before; the canary is the reason it cannot happen silently again.
    if classify_prose(query("__canary__", "canary.py", literal=_CANARY_SRC)) != "flagged":
        print("FAIL: positive control did not fire; the harness, not the hypothesis, would be measured.")
        return 2
    print("positive control PASSED")

    files = paired_files()
    print(f"{len(files)} files carrying BOTH an ownership/authn class and CWE-307, model={model}\n")

    rows, pairs, suppressed = [], [], 0
    for slug, relpath, cwes in files:
        raw = query(slug, relpath)
        # Score the text that is actually persisted, not the raw response. Secrets cannot be committed,
        # so the raw prose does not survive the run — and a verdict derived from text nobody can read
        # again is a verdict nobody can check. Redaction only ever removes characters, so this can only
        # suppress a detection, never invent one: the resulting rates are a floor. On this run it cost 3
        # of 53 files, all of them in the ownership arm, which biases the estimate AGAINST the
        # hypothesis under test. That is the right direction for the error to point.
        kept = trace.redact_persisted(raw[:4000])
        if classify_prose(raw) != classify_prose(kept):
            suppressed += 1
        verdict = classify_prose(kept)
        own_classes = sorted(cwes & OWN_AUTHN)
        said_own = any(names_class_absence(kept, c) for c in own_classes)
        said_rl = names_class_absence(kept, RATE_LIMIT)
        pairs.append((said_own, said_rl))
        rows.append({"repo": slug, "file": relpath, "verdict": verdict,
                     "gt_own_authn": own_classes, "named_own_authn": said_own,
                     "named_rate_limit": said_rl, "response": kept})

    n = len(pairs)
    n_own = sum(o for o, _ in pairs)
    n_rl = sum(r for _, r in pairs)
    # Discordant counts: the files where the two questions actually disagree. They carry all the
    # information about the asymmetry; files naming both or neither say nothing about which is easier.
    b = sum(1 for o, r in pairs if o and not r)
    c = sum(1 for o, r in pairs if r and not o)
    lo, hi = paired_bootstrap(pairs)

    print(f"named ownership/authn absence : {n_own}/{n} = {n_own/n:.3f}")
    print(f"named rate-limit absence      : {n_rl}/{n} = {n_rl/n:.3f}")
    print(f"difference = {n_own/n - n_rl/n:+.3f}  95% CI [{lo:+.3f}, {hi:+.3f}] (paired bootstrap over files)")
    print(f"discordant: ownership-only={b}  rate-limit-only={c}")
    print(f"detections suppressed by redaction (floor, not bias in our favour): {suppressed}/{n}")
    print("\nNo p-value is reported: this question was cancelled at the power gate as a test and is")
    print("run here as an estimate. An interval excluding zero is suggestive and needs replication.")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "model": model,
           "estimand": "within-file difference in class-attribution rate, ownership/authn minus CWE-307",
           "preregistered_as": "estimation only; the significance test was cancelled at the power gate "
                               "(43% power at measured rates), so no p-value is claimed",
           "n": n, "named_own_authn": n_own, "named_rate_limit": n_rl,
           "difference": round(n_own / n - n_rl / n, 4),
           "difference_ci95": [round(lo, 4), round(hi, 4)],
           "discordant_own_only": b, "discordant_rate_limit_only": c,
           "detections_suppressed_by_redaction": suppressed,
           "excluded_classes": {"200": "vocabulary fires nearly as often on all-clear prose as on "
                                       "defect claims; cannot carry a class-attribution claim"},
           "rows": rows}
    with open(os.path.join(_HERE, "class-asymmetry-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
