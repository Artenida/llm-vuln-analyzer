"""
src/evaluation/report.py

Orchestrates metric computation into a full evaluation report.
Handles saving the report JSON and printing the console summary.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from src.evaluation.metrics import (
    compute_binary_metrics,
    compute_coverage,
    metrics_by_group,
    confidence_distribution,
)
from src.evaluation.loader import load_result_file


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def build_report(
    results: list[dict],
    metadata: dict | None = None,
) -> dict[str, Any]:
    """
    Build a complete evaluation report from a flat results list.

    Sections in the returned dict:
        generated_at     — ISO timestamp
        source_metadata  — metadata forwarded from the result file
        coverage         — processed/failed/hallucinated counts + pct
        overall          — BinaryMetrics across ALL results
        by_cwe           — BinaryMetrics per CWE id
        by_language      — BinaryMetrics per language
        by_model         — BinaryMetrics per model_used
        confidence       — calibration stats (correct vs incorrect)
        error_analysis   — full FP and FN sample lists

    Args:
        results:  flat list of result dicts (from loader.py)
        metadata: original metadata from the result file (optional)

    Returns:
        report dict — ready to be JSON-serialised by save_report()
    """
    y_true = [r["ground_truth_vulnerable"]           for r in results]
    y_pred = [r["llm_result"]["vulnerability_found"] for r in results]

    # Pull model name from results themselves to support multi-model files
    model_key = "model_used"   # key inside llm_result

    # Build the per-model group key at the top level for metrics_by_group
    _results_with_model_key = [
        {**r, "_model": r["llm_result"].get("model_used", "unknown")}
        for r in results
    ]

    return {
        "generated_at":    datetime.now().isoformat(),
        "source_metadata": metadata or {},
        "coverage":        compute_coverage(results),
        "overall":         asdict(compute_binary_metrics(y_true, y_pred)),
        "by_cwe":          metrics_by_group(results, "cwe_id"),
        "by_language":     metrics_by_group(results, "language"),
        "by_model":        metrics_by_group(_results_with_model_key, "_model"),
        "confidence":      confidence_distribution(results),
        "error_analysis":  _error_analysis(results),
    }


# ---------------------------------------------------------------------------
# Error analysis helpers
# ---------------------------------------------------------------------------

def _error_analysis(results: list[dict]) -> dict[str, Any]:
    """
    Collect full detail on every false positive and false negative.

    False positive: model said vulnerable, code is actually safe.
    False negative: model said safe, code is actually vulnerable.
    """
    fp_samples = [
        r for r in results
        if not r["ground_truth_vulnerable"]
        and r["llm_result"]["vulnerability_found"]
    ]
    fn_samples = [
        r for r in results
        if r["ground_truth_vulnerable"]
        and not r["llm_result"]["vulnerability_found"]
    ]

    def _summarise(samples: list[dict]) -> list[dict]:
        return [
            {
                "method":     r["method"],
                "file":       r["file"],
                "cwe_id":     r["cwe_id"],
                "language":   r["language"],
                "confidence": r["llm_result"].get("confidence"),
                # Truncate long explanations to keep the report readable
                "explanation": (r["llm_result"].get("explanation") or "")[:300],
            }
            for r in samples
        ]

    return {
        "false_positives": {
            "count":   len(fp_samples),
            "samples": _summarise(fp_samples),
        },
        "false_negatives": {
            "count":   len(fn_samples),
            "samples": _summarise(fn_samples),
        },
    }


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_report(report: dict, output_path: str | Path) -> Path:
    """
    Write the report dict to a JSON file.
    Creates parent directories if they do not exist.

    Returns the resolved output path.
    """
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return p


# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------

def print_summary(report: dict) -> None:
    """
    Print a human-readable evaluation summary to stdout.
    Called after every evaluate run in cli.py.
    """
    cov = report["coverage"]
    m   = report["overall"]

    _line  = "=" * 54
    _dline = "-" * 54

    print(f"\n{_line}")
    print("  EVALUATION SUMMARY")
    print(_line)

    # Coverage block
    print(f"  Coverage      {cov['coverage_pct']:>6.1f}%"
          f"  ({cov['processed']}/{cov['total']} samples)")
    print(f"  Failures      {cov['failure_rate_pct']:>6.1f}%"
          f"  ({cov['failed']} samples with API/parse errors)")
    print(f"  Hallucinated  {cov['hallucination_rate_pct']:>6.1f}%"
          f"  ({cov['hallucinated']} samples flagged)")

    # Coverage warning
    if cov["coverage_pct"] < 80:
        print(f"\n  ⚠  Coverage is below 80% — check API errors in result file")

    print(_dline)

    # Overall metrics
    print(f"  Accuracy      {m['accuracy']:>8.4f}")
    print(f"  Precision     {m['precision']:>8.4f}")
    print(f"  Recall        {m['recall']:>8.4f}")
    print(f"  F1 Score      {m['f1']:>8.4f}")
    print(f"  MCC           {m['mcc']:>8.4f}")
    print(f"  Confusion     TP={m['tp']}  TN={m['tn']}"
          f"  FP={m['fp']}  FN={m['fn']}")

    # Per-CWE block
    by_cwe = report.get("by_cwe", {})
    if by_cwe:
        print(_dline)
        print("  Per-CWE")
        print(f"  {'CWE':<14} {'n':>4} {'F1':>7} {'Prec':>7} {'Recall':>7}")
        for cwe, mm in by_cwe.items():
            print(
                f"  {cwe:<14} {mm['support']:>4}"
                f" {mm['f1']:>7.4f} {mm['precision']:>7.4f}"
                f" {mm['recall']:>7.4f}"
            )

    # Per-language block
    by_lang = report.get("by_language", {})
    if by_lang:
        print(_dline)
        print("  Per-language")
        print(f"  {'Language':<14} {'n':>4} {'F1':>7} {'Prec':>7} {'Recall':>7}")
        for lang, mm in by_lang.items():
            print(
                f"  {lang:<14} {mm['support']:>4}"
                f" {mm['f1']:>7.4f} {mm['precision']:>7.4f}"
                f" {mm['recall']:>7.4f}"
            )

    # Error analysis summary
    ea = report.get("error_analysis", {})
    fp_count = ea.get("false_positives", {}).get("count", 0)
    fn_count = ea.get("false_negatives", {}).get("count", 0)
    if fp_count or fn_count:
        print(_dline)
        print(f"  False positives: {fp_count}  (safe code flagged as vulnerable)")
        print(f"  False negatives: {fn_count}  (vulnerable code missed)")

    print(f"{_line}\n")


# ---------------------------------------------------------------------------
# One-shot convenience function
# ---------------------------------------------------------------------------

def evaluate_result_file(
    result_path:  str | Path,
    output_path:  str | Path | None = None,
    print_to_console: bool = True,
) -> dict[str, Any]:
    """
    Load a result file, compute all metrics, optionally save the report,
    and optionally print the summary.

    This is the function called by the `evaluate` CLI command.

    Args:
        result_path:      path to the analysis JSON from cli.py
        output_path:      where to save the evaluation report (optional)
        print_to_console: whether to print the summary table

    Returns:
        full report dict
    """
    data   = load_result_file(result_path)
    report = build_report(data["results"], metadata=data.get("metadata"))

    if output_path:
        saved = save_report(report, output_path)
        if print_to_console:
            print(f"Report saved to: {saved}")

    if print_to_console:
        print_summary(report)

    return report