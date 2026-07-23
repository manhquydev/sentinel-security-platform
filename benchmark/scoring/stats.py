"""Confusion-matrix statistics: Precision/Recall/F1, Wilson score interval, Youden's J.
Pure math, no I/O, no API key."""
from __future__ import annotations

import math
from dataclasses import dataclass

_Z_95 = 1.959963984540054  # two-sided 95% normal quantile


@dataclass(frozen=True)
class ConfusionMatrix:
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.fn + self.tn


def wilson_interval(k: int, n: int, z: float = _Z_95) -> tuple[float, float]:
    """95% Wilson score interval for a proportion k/n. nan-safe for n=0."""
    if n == 0:
        return (float("nan"), float("nan"))
    phat = k / n
    denom = 1 + z**2 / n
    center = (phat + z**2 / (2 * n)) / denom
    margin = z * math.sqrt(phat * (1 - phat) / n + z**2 / (4 * n**2)) / denom
    return (center - margin, center + margin)


def precision(cm: ConfusionMatrix) -> float:
    denom = cm.tp + cm.fp
    return cm.tp / denom if denom else float("nan")


def recall(cm: ConfusionMatrix) -> float:
    denom = cm.tp + cm.fn
    return cm.tp / denom if denom else float("nan")


def f1(cm: ConfusionMatrix) -> float:
    p, r = precision(cm), recall(cm)
    if math.isnan(p) or math.isnan(r) or (p + r) == 0:
        return float("nan")
    return 2 * p * r / (p + r)


def youden_j(cm: ConfusionMatrix) -> float:
    """Sensitivity + Specificity - 1. >0 means better than random guessing."""
    sens = recall(cm)  # TP / (TP+FN)
    spec_denom = cm.tn + cm.fp
    spec = cm.tn / spec_denom if spec_denom else float("nan")
    if math.isnan(sens) or math.isnan(spec):
        return float("nan")
    return sens + spec - 1


def precision_wilson_ci(cm: ConfusionMatrix, z: float = _Z_95) -> tuple[float, float]:
    return wilson_interval(cm.tp, cm.tp + cm.fp, z)


def recall_wilson_ci(cm: ConfusionMatrix, z: float = _Z_95) -> tuple[float, float]:
    return wilson_interval(cm.tp, cm.tp + cm.fn, z)
