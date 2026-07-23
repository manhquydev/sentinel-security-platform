"""TDD for scoring/stats.py. Wilson CI reference values computed independently via
the standard closed-form formula (z=1.959963984540054, the 95% two-sided normal
quantile) - not derived from the implementation under test."""
import math

from scoring.stats import ConfusionMatrix, f1, precision, precision_wilson_ci, recall, recall_wilson_ci, wilson_interval, youden_j


def test_precision_recall_f1_hand_computed():
    cm = ConfusionMatrix(tp=7, fp=3, fn=2, tn=8)
    assert precision(cm) == 7 / 10
    assert recall(cm) == 7 / 9
    assert math.isclose(f1(cm), 2 * (7 / 10) * (7 / 9) / ((7 / 10) + (7 / 9)))


def test_wilson_interval_k7_n10_matches_reference():
    lo, hi = wilson_interval(7, 10)
    assert math.isclose(lo, 0.39677814746114537, abs_tol=1e-6)
    assert math.isclose(hi, 0.8922087325936989, abs_tol=1e-6)


def test_wilson_interval_k0_n10_matches_reference():
    lo, hi = wilson_interval(0, 10)
    assert math.isclose(lo, 0.0, abs_tol=1e-6)
    assert math.isclose(hi, 0.2775327998628892, abs_tol=1e-6)


def test_wilson_interval_k10_n10_matches_reference():
    lo, hi = wilson_interval(10, 10)
    assert math.isclose(lo, 0.7224672001371107, abs_tol=1e-6)
    assert math.isclose(hi, 1.0, abs_tol=1e-6)


def test_wilson_interval_n_zero_is_nan_safe():
    lo, hi = wilson_interval(0, 0)
    assert math.isnan(lo) and math.isnan(hi)


def test_precision_n_zero_is_nan_not_crash():
    cm = ConfusionMatrix(tp=0, fp=0, fn=5, tn=5)
    assert math.isnan(precision(cm))


def test_recall_n_zero_is_nan_not_crash():
    cm = ConfusionMatrix(tp=0, fp=5, fn=0, tn=5)
    assert math.isnan(recall(cm))


def test_youden_j_positive_for_better_than_random():
    cm = ConfusionMatrix(tp=9, fp=1, fn=1, tn=9)  # sens=0.9, spec=0.9 -> J=0.8
    assert math.isclose(youden_j(cm), 0.8)


def test_youden_j_zero_for_random_guess():
    cm = ConfusionMatrix(tp=5, fp=5, fn=5, tn=5)  # sens=0.5, spec=0.5 -> J=0.0
    assert math.isclose(youden_j(cm), 0.0)


def test_youden_j_negative_for_worse_than_random():
    cm = ConfusionMatrix(tp=1, fp=9, fn=9, tn=1)  # sens=0.1, spec=0.1 -> J=-0.8
    assert math.isclose(youden_j(cm), -0.8)


def test_precision_wilson_ci_uses_tp_fp_as_k_n():
    cm = ConfusionMatrix(tp=7, fp=3, fn=0, tn=0)
    assert precision_wilson_ci(cm) == wilson_interval(7, 10)


def test_recall_wilson_ci_uses_tp_fn_as_k_n():
    cm = ConfusionMatrix(tp=7, fp=0, fn=3, tn=0)
    assert recall_wilson_ci(cm) == wilson_interval(7, 10)
