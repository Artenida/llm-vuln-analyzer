"""
src/evaluation/loader.py

Loads and validates the JSON result files produced by cli.py.
All I/O for the evaluation pipeline lives here — metrics.py stays pure.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Single-file loading
# ---------------------------------------------------------------------------

def load_result_file(path: str | Path) -> dict[str, Any]:
    """
    Load a single result JSON produced by cli.py.

    Returns the full dict:
        {
            "metadata": { ... },
            "results":  [ ... ]
        }

    Raises:
        FileNotFoundError  — if the file does not exist
        ValueError         — if required top-level keys are missing
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Result file not found: {path}")

    with open(p, encoding="utf-8") as f:
        data = json.load(f)

    _validate(data, path)
    return data


def _validate(data: dict, path: Any) -> None:
    for key in ("results", "metadata"):
        if key not in data:
            raise ValueError(f"Result file '{path}' is missing the '{key}' key.")
    if not isinstance(data["results"], list):
        raise ValueError(f"'results' in '{path}' must be a list.")


# ---------------------------------------------------------------------------
# Multi-file loading (for cross-run comparisons)
# ---------------------------------------------------------------------------

def load_multiple_result_files(
    paths: list[str | Path],
) -> tuple[dict[str, Any], list[dict]]:
    """
    Load and merge multiple result files into a single flat list.

    Useful when you want to evaluate across different runs or CWE batches.

    Returns:
        merged_metadata  — dict summarising all source files
        flat_results     — combined list of all result dicts
    """
    all_results:  list[dict]       = []
    all_metadata: list[dict]       = []

    for p in paths:
        data = load_result_file(p)
        all_results.extend(data["results"])
        all_metadata.append(data["metadata"])

    merged_meta = {
        "source_files":   [str(p) for p in paths],
        "total_samples":  len(all_results),
        "models_used":    sorted({m.get("model", "unknown") for m in all_metadata}),
        "providers_used": sorted({m.get("provider", "unknown") for m in all_metadata}),
    }

    return merged_meta, all_results


# ---------------------------------------------------------------------------
# Filtering helpers
# ---------------------------------------------------------------------------

def filter_results(
    results: list[dict],
    cwe_id:   str | None = None,
    language: str | None = None,
    model:    str | None = None,
    only_valid: bool = False,
) -> list[dict]:
    """
    Return a filtered subset of results.

    Args:
        results:     flat results list
        cwe_id:      e.g. "CWE-78"
        language:    e.g. "java"
        model:       e.g. "gpt-4o-mini"
        only_valid:  if True, drop samples where llm_result is None or errored
    """
    out = results

    if cwe_id:
        out = [r for r in out if r.get("cwe_id") == cwe_id]

    if language:
        out = [r for r in out if r.get("language") == language]

    if model:
        out = [
            r for r in out
            if r.get("llm_result", {}).get("model_used") == model
        ]

    if only_valid:
        out = [
            r for r in out
            if r.get("llm_result") is not None
            and not r["llm_result"].get("explanation", "").startswith("API error")
            and not r["llm_result"].get("explanation", "").startswith("Failed to parse")
        ]

    return out