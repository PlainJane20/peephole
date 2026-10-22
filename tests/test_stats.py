"""Metrics pinned against values worked out by hand."""
import math

import pytest

from peephole.stats import (aurc, confusion, ece, latency_summary, percentile, rate, reliability_table,
                            risk_coverage, wilson)


def test_wilson_zero_of_ten_hand_computed():
    # k=0, n=10, z=1.96: lower = 0, upper = z^2/(n+z^2) = 3.8416/13.8416
    lo, hi = wilson(0, 10)
    assert lo == 0.0
    assert hi == pytest.approx(3.8416 / 13.8416, abs=1e-6)       # 0.27753


def test_wilson_five_of_ten_known_interval():
    lo, hi = wilson(5, 10)
    assert lo == pytest.approx(0.2366, abs=1e-4)
    assert hi == pytest.approx(0.7634, abs=1e-4)


def test_wilson_all_of_n_symmetry():
    lo, hi = wilson(10, 10)
    assert hi == 1.0 and lo == pytest.approx(1 - 3.8416 / 13.8416, abs=1e-6)


def test_wilson_empty_is_uninformative():
    assert wilson(0, 0) == (0.0, 1.0)


def test_wilson_contains_point_estimate():
    for k, n in [(1, 7), (3, 9), (50, 125), (98, 125)]:
        lo, hi = wilson(k, n)
        assert lo <= k / n <= hi


def test_rate_dict():
    r = rate(98, 125)
    assert r["k"] == 98 and r["n"] == 125 and r["rate"] == 0.784
    assert rate(0, 0)["rate"] is None


def test_percentile_hand_values():
    assert percentile([1, 2, 3, 4], 50) == 2.5
    assert percentile(list(range(1, 101)), 95) == pytest.approx(95.05)
    assert percentile([7], 95) == 7
    assert percentile([3, 1, 2], 0) == 1 and percentile([3, 1, 2], 100) == 3
    with pytest.raises(ValueError):
        percentile([], 50)


def test_latency_summary_empty_and_filled():
    assert latency_summary([])["p50_ms"] is None
    s = latency_summary([1.0, 2.0, 3.0, 4.0])
    assert s["p50_ms"] == 2.5 and s["n"] == 4


ITEMS = [(0.9, True), (0.9, True), (0.9, True), (0.9, False), (0.6, True), (0.6, False)]


def test_reliability_table_hand_computed():
    rows = reliability_table(ITEMS)
    assert len(rows) == 10
    b9 = rows[9]
    assert b9["n"] == 4 and b9["accuracy"] == 0.75 and b9["mean_confidence"] == 0.9 and b9["gap"] == 0.15
    b6 = rows[6]
    assert b6["n"] == 2 and b6["accuracy"] == 0.5 and b6["gap"] == 0.1
    assert all(r["n"] == 0 for i, r in enumerate(rows) if i not in (6, 9))


def test_ece_hand_computed():
    # (4*0.15 + 2*0.10) / 6 = 0.13333
    assert ece(ITEMS) == pytest.approx(0.8 / 6, abs=1e-6)


def test_ece_perfect_calibration_is_zero():
    items = [(1.0, True)] * 5 + [(0.5, True), (0.5, False)]
    assert ece(items) == 0.0


def test_ece_ignores_missing_confidence_and_none_when_empty():
    assert ece([(None, True), (None, False)]) is None
    assert ece(ITEMS + [(None, False)]) == ece(ITEMS)


def test_ece_confidence_one_goes_in_last_bin():
    rows = reliability_table([(1.0, True)])
    assert rows[9]["n"] == 1


def test_risk_coverage_hand_computed():
    pts = risk_coverage(ITEMS)
    by = {p["threshold"]: p for p in pts}
    assert by[0.6]["n_auto"] == 6 and by[0.6]["coverage"] == 1.0 and by[0.6]["errors"] == 2
    assert by[0.6]["error_rate"] == pytest.approx(2 / 6, abs=1e-4)
    assert by[0.9]["n_auto"] == 4 and by[0.9]["coverage"] == pytest.approx(4 / 6, abs=1e-4)
    assert by[0.9]["error_rate"] == 0.25


def test_risk_coverage_missing_confidence_never_auto_decided_but_counts_in_denominator():
    items = ITEMS + [(None, True), (None, True)]
    by = {p["threshold"]: p for p in risk_coverage(items)}
    assert by[0.6]["n_auto"] == 6 and by[0.6]["coverage"] == pytest.approx(6 / 8, abs=1e-4)


def test_risk_coverage_explicit_thresholds_and_empty_auto_set():
    pts = risk_coverage(ITEMS, [0.0, 0.95])
    assert pts[0]["coverage"] == 1.0
    assert pts[1]["n_auto"] == 0 and pts[1]["error_rate"] is None


def test_coverage_is_monotone_non_increasing_in_threshold():
    pts = risk_coverage(ITEMS, [0.0, 0.5, 0.7, 0.95])
    cov = [p["coverage"] for p in pts]
    assert cov == sorted(cov, reverse=True)


def test_aurc_hand_computed():
    # ranked: .9T .9T .9T .9F .6T .6F -> selective risk after k: 0,0,0,1/4,1/5,2/6
    assert aurc(ITEMS) == pytest.approx((0 + 0 + 0 + 0.25 + 0.2 + 2 / 6) / 6, abs=1e-6)


def test_aurc_none_when_no_confidence():
    assert aurc([(None, True)]) is None


def test_confusion_matrix_counts_and_rejects_unknown_labels():
    m = confusion([("a", "x"), ("a", "y"), ("b", "y"), ("a", "x")], ["a", "b"], ["x", "y"])
    assert m == {"a": {"x": 2, "y": 1}, "b": {"x": 0, "y": 1}}
    with pytest.raises(KeyError):
        confusion([("zzz", "x")], ["a"], ["x"])
