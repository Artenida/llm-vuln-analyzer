"""
Automated evaluation harness.
Public API re-exported from submodules.
"""
from src.evaluation.ground_truth import GroundTruthDataset, GroundTruthEntry, load_ground_truth
from src.evaluation.evaluator import (
    EvaluationReport,
    InstanceVerdict,
    ConfusionMetrics,
    evaluate_run,
    save_evaluation_report,
    comparison_table,
)

__all__ = [
    "GroundTruthDataset",
    "GroundTruthEntry",
    "load_ground_truth",
    "EvaluationReport",
    "InstanceVerdict",
    "ConfusionMetrics",
    "evaluate_run",
    "save_evaluation_report",
    "comparison_table",
]
