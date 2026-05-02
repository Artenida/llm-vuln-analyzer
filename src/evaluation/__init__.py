"""
src/evaluation/__init__.py

Public API for the evaluation package.
Import everything from here — don't reach into submodules directly.

Usage:
    from src.evaluation import evaluate_result_file, build_report, print_summary
"""

from src.evaluation.metrics import (
    BinaryMetrics,
    compute_binary_metrics,
    compute_coverage,
    metrics_by_group,
    confidence_distribution,
)
from src.evaluation.loader import (
    load_result_file,
    load_multiple_result_files,
    filter_results,
)
from src.evaluation.report import (
    build_report,
    save_report,
    print_summary,
    evaluate_result_file,
)

__all__ = [
    # metrics
    "BinaryMetrics",
    "compute_binary_metrics",
    "compute_coverage",
    "metrics_by_group",
    "confidence_distribution",
    # loader
    "load_result_file",
    "load_multiple_result_files",
    "filter_results",
    # report
    "build_report",
    "save_report",
    "print_summary",
    "evaluate_result_file",
]