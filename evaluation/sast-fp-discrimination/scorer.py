"""Finding-level FP-discrimination scorer for the AI-SAST verifier spike (decision-in-progress).

NOT a reuse of benchmark/scoring's OWASP-Java per-test-case scorer — that measures a different unit.
This scores per SAST FINDING against RealVuln's `is_vulnerable` labels, and isolates the verifier's
MARGINAL contribution over the deterministic gate (the red-team's attribution point). It reuses only
the pure ConfusionMatrix / precision / recall primitives from benchmark/scoring/stats.py.

A record (one SAST finding the engine flagged, already matched to ground truth by file+CWE+line±10):
    {"is_vulnerable": bool,          # ground truth: True=real vuln, False=FP-trap or unmatched
     "gate_autokept": bool,          # the deterministic high-precision gate kept it (no LLM)
     "verifier_effective": str|None} # "keep" | "likely-fp" | None (None iff gate_autokept)

Pre-registered, gameable-proofed:
  * Denominator for the verifier's credit is the RESIDUAL (not gate_autokept) — the gate's work is
    never counted as the LLM's.
  * Recall is measured over SAST-flagged true-positives; a hard floor (1 - eps) must hold or the spike
    FAILS regardless of FP-reduction (you cannot buy precision by dropping real vulns).
  * F2 (recall weighted 4x, RealVuln's own metric) reported for leaderboard comparability.
"""

from __future__ import annotations

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from benchmark.scoring.stats import ConfusionMatrix, precision, recall  # noqa: E402


def _f2(p: float, r: float) -> float | None:
    if p != p or r != r or (4 * p + r) == 0:   # nan-safe
        return None
    return 5 * p * r / (4 * p + r)


def _cm(records: list[dict], *, apply_verifier: bool) -> ConfusionMatrix:
    """Confusion over all flagged findings. Kept = predicted-positive. `apply_verifier` lets the
    verifier drop residual findings it marked likely-fp; otherwise every flagged finding is kept
    (the gate-only / raw-SAST baseline)."""
    tp = fp = fn = tn = 0
    for rec in records:
        real = bool(rec["is_vulnerable"])
        dropped = apply_verifier and (not rec["gate_autokept"]) and rec.get("verifier_effective") == "likely-fp"
        kept = not dropped
        if kept and real:
            tp += 1
        elif kept and not real:
            fp += 1
        elif dropped and real:
            fn += 1          # recall loss — the verifier dropped a real vuln
        else:
            tn += 1          # correct drop of an FP
    return ConfusionMatrix(tp=tp, fp=fp, fn=fn, tn=tn)


def score(records: list[dict], *, recall_floor_eps: float = 0.02) -> dict:
    """Compute gate-only vs gate+verifier metrics + the verifier's marginal FP-reduction + the
    pre-registered pass/fail (recall floor)."""
    residual = [r for r in records if not r["gate_autokept"]]
    res_fp = [r for r in residual if not r["is_vulnerable"]]
    res_tp = [r for r in residual if r["is_vulnerable"]]
    fp_removed = sum(1 for r in res_fp if r.get("verifier_effective") == "likely-fp")
    tp_dropped = sum(1 for r in res_tp if r.get("verifier_effective") == "likely-fp")

    base = _cm(records, apply_verifier=False)     # gate-only == keep-all == raw-SAST over flagged
    full = _cm(records, apply_verifier=True)      # gate + verifier
    bp, br = precision(base), recall(base)
    fp_, fr = precision(full), recall(full)

    flagged_tp = sum(1 for r in records if r["is_vulnerable"])
    recall_floor = 1.0 - recall_floor_eps
    recall_over_flagged = (flagged_tp - tp_dropped) / flagged_tp if flagged_tp else float("nan")
    recall_ok = recall_over_flagged >= recall_floor if flagged_tp else False

    return {
        "residual": {"total": len(residual), "fp_traps": len(res_fp), "true_pos": len(res_tp)},
        "verifier_marginal": {
            "fp_removed": fp_removed, "fp_total": len(res_fp),
            "fp_reduction_rate": (fp_removed / len(res_fp)) if res_fp else None,
            "tp_dropped": tp_dropped, "tp_total": len(res_tp)},
        "gate_only": {"precision": _r(bp), "recall": _r(br), "f2": _r(_f2(bp, br)),
                      "confusion": base.__dict__},
        "gate_plus_verifier": {"precision": _r(fp_), "recall": _r(fr), "f2": _r(_f2(fp_, fr)),
                               "confusion": full.__dict__},
        "recall_over_flagged": _r(recall_over_flagged), "recall_floor": recall_floor,
        "recall_ok": recall_ok,
    }


def _r(x: float | None) -> float | None:
    if x is None or x != x:   # None or nan
        return None
    return round(x, 4)
