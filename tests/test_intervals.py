"""Tests for src/evaluation/intervals.py."""
import pytest

from src.evaluation.evaluator import InstanceVerdict
from src.evaluation.intervals import (
    bootstrap_metrics,
    evidence_stratified_recall,
    label_sensitivity,
    wilson_interval,
)


def _verdict(name, gt_vulnerable, outcome, status=None, predicted=None):
    return InstanceVerdict(
        instance_id=f"f.ts::{name}",
        function_name=name,
        file="f.ts",
        gt_vulnerable=gt_vulnerable,
        gt_cwe="CWE-89" if gt_vulnerable else None,
        analyzed=True,
        predicted_vulnerable=(outcome in ("TP", "FP")) if predicted is None else predicted,
        predicted_cwe=None,
        outcome=outcome,
        cwe_correct=None,
        verification_status=status,
    )


class TestWilsonInterval:
    def test_brackets_the_point_estimate(self):
        iv = wilson_interval(38, 78)
        assert iv["low"] < iv["point"] < iv["high"]
        assert iv["point"] == pytest.approx(0.4872, abs=1e-4)

    def test_stays_inside_zero_and_one_at_the_extremes(self):
        # The reason for choosing Wilson over the normal approximation: at 9/10
        # the textbook interval runs past 1.0, which is not a probability.
        iv = wilson_interval(9, 10)
        assert 0.0 <= iv["low"] < iv["high"] <= 1.0

    def test_small_denominators_produce_wide_bands(self):
        # Semgrep's 0.900 precision comes from ten flagged rows; the analyzer's
        # 0.487 from seventy-eight. The bands have to show that asymmetry or the
        # comparison in Chapter V overstates the gap.
        few = wilson_interval(9, 10)
        many = wilson_interval(38, 78)
        assert (few["high"] - few["low"]) > (many["high"] - many["low"])

    def test_no_observations_is_not_an_interval(self):
        assert wilson_interval(0, 0) is None


class TestBootstrap:
    def test_reproducible_across_calls(self):
        outcomes = ["TP"] * 38 + ["FP"] * 40 + ["FN"] * 17 + ["TN"] * 284
        assert bootstrap_metrics(outcomes, iterations=200) == bootstrap_metrics(
            outcomes, iterations=200
        )

    def test_agrees_with_wilson_on_precision(self):
        outcomes = ["TP"] * 38 + ["FP"] * 40 + ["FN"] * 17 + ["TN"] * 284
        boot = bootstrap_metrics(outcomes)["precision"]
        wilson = wilson_interval(38, 78)
        assert boot["low"] == pytest.approx(wilson["low"], abs=0.05)
        assert boot["high"] == pytest.approx(wilson["high"], abs=0.05)

    def test_covers_f1_which_wilson_cannot(self):
        outcomes = ["TP"] * 10 + ["FP"] * 5 + ["FN"] * 5
        assert bootstrap_metrics(outcomes, iterations=200)["f1"]["low"] < 0.6667

    def test_no_rows_is_not_an_interval(self):
        assert bootstrap_metrics([]) is None


class TestLabelSensitivity:
    def test_none_when_nothing_is_disputed(self):
        assert label_sensitivity([_verdict("a", True, "TP"), _verdict("b", False, "TN")]) is None

    def test_flagged_disputed_row_moves_from_false_positive_to_true_positive(self):
        instances = [
            _verdict("a", True, "TP"),
            _verdict("b", False, "FP", status="BORDERLINE_PENDING_AUTHOR"),
        ]
        out = label_sensitivity(instances)
        assert out["disputed_rows"] == 1
        assert out["pessimistic"]["precision"] == pytest.approx(0.5)
        assert out["optimistic"]["precision"] == pytest.approx(1.0)

    def test_unflagged_disputed_row_becomes_a_missed_detection(self):
        instances = [
            _verdict("a", True, "TP"),
            _verdict("b", False, "TN", status="BORDERLINE_PENDING_AUTHOR"),
        ]
        out = label_sensitivity(instances)
        assert out["pessimistic"]["recall"] == pytest.approx(1.0)
        assert out["optimistic"]["recall"] == pytest.approx(0.5)


class TestEvidenceStratifiedRecall:
    def test_splits_recall_by_tier_and_ignores_clean_rows(self):
        instances = [
            _verdict("a", True, "TP", status="VERIFIED_VULNERABLE"),
            _verdict("b", True, "FN", status="VERIFIED_VULNERABLE"),
            _verdict("c", True, "TP"),
            _verdict("d", False, "TN", status="VERIFIED_CLEAN"),
        ]
        out = evidence_stratified_recall(instances)
        assert out["VERIFIED_VULNERABLE"]["recall"] == pytest.approx(0.5)
        assert out["VERIFIED_VULNERABLE"]["total"] == 2
        # Unstamped rather than an assumed provenance: the tier has to come from
        # the row, not from which dataset happens to be loaded.
        assert out["UNSTAMPED"]["total"] == 1
        assert "VERIFIED_CLEAN" not in out

    def test_none_when_no_vulnerable_rows(self):
        assert evidence_stratified_recall([_verdict("a", False, "TN")]) is None
