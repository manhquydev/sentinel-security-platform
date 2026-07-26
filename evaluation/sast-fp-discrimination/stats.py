"""Shared exact statistics for the SAST experiments.

Fisher's exact test was written inline inside `run_role_control.main` and then needed again by the
artefact reconciler. Rather than copy it, it lives here: two implementations of a test statistic are two
things that can disagree while both look right, and this lab has already published one number that
drifted away from the data it was derived from.

The inline copy in `run_role_control` is deliberately left in place for now — that runner cannot be
re-executed without spending model calls, so changing it is a change no test in this repo can verify.
Anything newly written imports from here.

Exact rather than chi-square deliberately: the arms here routinely contain zero-count cells (a control
arm flagging nothing at all is the normal outcome, not a degenerate one), which is exactly where the
asymptotic approximation stops being trustworthy.
"""

from __future__ import annotations

from math import comb


def fisher_one_sided(a: int, b: int, c: int, d: int) -> float:
    """P(observing >= `a` successes in row 1) under the null of no association.

    Table layout::

        a  b     row 1 (e.g. vulnerable arm: flagged, not flagged)
        c  d     row 2 (e.g. control arm:    flagged, not flagged)

    One-sided because every hypothesis in this project is directional and was preregistered that way;
    a two-sided p here would be answering a question nobody asked.
    """
    n = a + b + c + d
    if n == 0:
        return 1.0
    row1, col1 = a + b, a + c
    total = comb(n, row1)
    p = 0.0
    for x in range(max(0, row1 - (n - col1)), min(row1, col1) + 1):
        if x >= a:
            p += comb(col1, x) * comb(n - col1, row1 - x) / total
    return p
