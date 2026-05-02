"""
src/evaluation/metrics.py

Pure-computation layer — no I/O, no side effects.
All functions take the flat list of result dicts produced by cli.py.

Each result dict has the shape:
    {
        "file": str,
        "method": str,
        "cwe_id": str,
        "ground_truth_vulnerable": bool,
        "language": str,
        "llm_result": {
            "vulnerability_found": bool,
            "confidence": float,
            "hallucination_flag": bool,
            "model_used": str,
            "explanation": str,
            ...
        }
    }
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_div(numerator: float, denominator: float, default: float = 0.0) -> float:
    return numerator / denominator if denominator != 0 else default


def _is_failed(result: dict) -> bool:
    """
    True when the llm_result is present but indicates an API/parse error.
    These count as 'not processed' when computing coverage.
    """
    lr = result.get("llm_result")
    if lr is None:
        return True
    explanation = lr.get("explanation", "")
    return (
        explanation.startswith("API error")
        or explanation.startswith("Failed to parse")
        or (lr.get("confidence", 0.0) == 0.0 and lr.get("hallucination_flag", False))
    )


# ---------------------------------------------------------------------------
# Core dataclass
# ---------------------------------------------------------------------------

@dataclass
class BinaryMetrics:
    tp: int
    tn: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    accuracy: float
    fpr: float          # false-positive rate  FP / (FP + TN)
    fnr: float          # false-negative rate  FN / (FN + TP)
    mcc: float          # Matthews correlation coefficient
    support: int        # total samples in this slice


# ---------------------------------------------------------------------------
# Binary classification metrics
# ---------------------------------------------------------------------------

def compute_binary_metrics(
    y_true: list[bool],
    y_pred: list[bool],
) -> BinaryMetrics:
    """
    Compute all classification metrics from ground-truth and predicted labels.

    Args:
        y_true: ground-truth vulnerability flags
        y_pred: model-predicted vulnerability flags

    Returns:
        BinaryMetrics dataclass
    """
    tp = sum(t and p     for t, p in zip(y_true, y_pred))
    tn = sum(not t and not p for t, p in zip(y_true, y_pred))
    fp = sum(not t and p     for t, p in zip(y_true, y_pred))
    fn = sum(t and not p     for t, p in zip(y_true, y_pred))

    precision = _safe_div(tp, tp + fp)
    recall    = _safe_div(tp, tp + fn)
    f1        = _safe_div(2 * precision * recall, precision + recall)
    accuracy  = _safe_div(tp + tn, tp + tn + fp + fn)
    fpr       = _safe_div(fp, fp + tn)
    fnr       = _safe_div(fn, fn + tp)

    # Matthews Correlation Coefficient — robust to class imbalance
    denom = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
    mcc = _safe_div(tp * tn - fp * fn, denom)

    return BinaryMetrics(
        tp=tp, tn=tn, fp=fp, fn=fn,
        precision=round(precision, 6),
        recall=round(recall, 6),
        f1=round(f1, 6),
        accuracy=round(accuracy, 6),
        fpr=round(fpr, 6),
        fnr=round(fnr, 6),
        mcc=round(mcc, 6),
        support=len(y_true),
    )


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------

def compute_coverage(results: list[dict]) -> dict[str, Any]:
    """
    Coverage = how many samples were successfully processed by the LLM.

    A sample is 'failed' if:
      - llm_result is None, OR
      - explanation starts with 'API error' / 'Failed to parse', OR
      - confidence == 0.0 AND hallucination_flag is True
      (all of these are set by LLMClient on error paths in client.py)

    Returns dict with counts and percentages.
    """
    total       = len(results)
    failed      = sum(1 for r in results if _is_failed(r))
    processed   = total - failed
    hallucinated = sum(
        1 for r in results
        if r.get("llm_result") and r["llm_result"].get("hallucination_flag", False)
    )

    return {
        "total":                  total,
        "processed":              processed,
        "failed":                 failed,
        "hallucinated":           hallucinated,
        "coverage_pct":           round(_safe_div(processed, total) * 100, 2),
        "failure_rate_pct":       round(_safe_div(failed, total) * 100, 2),
        "hallucination_rate_pct": round(_safe_div(hallucinated, total) * 100, 2),
    }


# ---------------------------------------------------------------------------
# Grouped metrics (per-CWE, per-language, per-model)
# ---------------------------------------------------------------------------

def metrics_by_group(
    results: list[dict],
    group_key: str,
) -> dict[str, dict[str, Any]]:
    """
    Compute BinaryMetrics for every unique value of group_key.

    group_key can be 'cwe_id', 'language', or any top-level key in results.

    Returns dict: { group_value -> metrics_dict }
    """
    groups: dict[str, list[dict]] = {}
    for r in results:
        key = r.get(group_key) or "unknown"
        groups.setdefault(key, []).append(r)

    out: dict[str, dict] = {}
    for key, group in sorted(groups.items()):
        y_true = [r["ground_truth_vulnerable"] for r in group]
        y_pred = [r["llm_result"]["vulnerability_found"] for r in group]

        m   = compute_binary_metrics(y_true, y_pred)
        cov = compute_coverage(group)

        confs = [r["llm_result"].get("confidence", 0.0) for r in group]
        avg_conf = _safe_div(sum(confs), len(confs))

        out[key] = {
            **asdict(m),
            "coverage_pct":           cov["coverage_pct"],
            "avg_confidence":         round(avg_conf, 4),
            "hallucination_rate_pct": cov["hallucination_rate_pct"],
        }

    return out


# ---------------------------------------------------------------------------
# Confidence calibration
# ---------------------------------------------------------------------------

def confidence_distribution(results: list[dict]) -> dict[str, Any]:
    """
    Analyse whether the model's confidence score actually correlates with
    being correct. High confidence on wrong answers = bad calibration.

    Returns stats split by correct / incorrect predictions.
    """
    all_confs   = []
    correct_c   = []
    incorrect_c = []

    for r in results:
        lr = r.get("llm_result")
        if lr is None:
            continue
        conf    = lr.get("confidence", 0.0)
        correct = r["ground_truth_vulnerable"] == lr["vulnerability_found"]
        all_confs.append(conf)
        (correct_c if correct else incorrect_c).append(conf)

    def _stats(vals: list[float]) -> dict:
        if not vals:
            return {"mean": 0.0, "min": 0.0, "max": 0.0, "n": 0}
        return {
            "mean": round(sum(vals) / len(vals), 4),
            "min":  round(min(vals), 4),
            "max":  round(max(vals), 4),
            "n":    len(vals),
        }

    return {
        "overall":        _stats(all_confs),
        "when_correct":   _stats(correct_c),
        "when_incorrect": _stats(incorrect_c),
    }