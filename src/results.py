"""
Results persistence.
Saves analysis runs to timestamped JSON files under experiments/results/.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from src.llm.client import VulnerabilityReport
from src.models import CodeSample

logger = logging.getLogger(__name__)


def _make_run_id(model: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"analysis_{model.replace('-', '_')}_{ts}"


def save_run(
    reports: list[VulnerabilityReport],
    samples: list[CodeSample],
    source_path: str,
    model: str,
    results_folder: str = "experiments/results",
    extra_meta: dict | None = None,
) -> Path:
    """
    Saves a full analysis run to a timestamped JSON file.
    Returns the path to the saved file.
    """
    run_id = _make_run_id(model)
    folder = Path(results_folder)
    folder.mkdir(parents=True, exist_ok=True)
    out_path = folder / f"{run_id}.json"

    # summary stats
    total = len(reports)
    found = sum(1 for r in reports if r.vulnerability_found)
    errors = sum(1 for r in reports if r.error is not None)
    hallucinated = sum(1 for r in reports if r.hallucination_flag)

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "run_id": run_id,
        "model": model,
        "source_path": source_path,
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_functions": total,
            "vulnerabilities_found": found,
            "clean": total - found - errors,
            "errors": errors,
            "hallucinated": hallucinated,
        },
        "findings": [],
    }

    if extra_meta:
        payload["meta"] = extra_meta

    for report in reports:
        payload["findings"].append({
            "function_name":      report.function_name,
            "file_path":          report.file_path,
            "language":           report.language,
            "vulnerability_found": report.vulnerability_found,
            "cwe_id":             report.cwe_id,
            "affected_lines":     report.affected_lines,
            "severity":           report.severity,
            "explanation":        report.explanation,
            "patch_suggestion":   report.patch_suggestion,
            "confidence":         report.confidence,
            "hallucination_flag": report.hallucination_flag,
            "analysis_mode":      report.analysis_mode,
            "error":              report.error,
        })

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    logger.info("Run saved → %s", out_path)
    return out_path

def save_extraction_results(
    samples: list[CodeSample],
    source_path: str,
    output_folder: str,
) -> Path:
    """
    Saves extracted functions before analysis phase.
    """

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    out_dir = Path(output_folder)
    out_dir.mkdir(parents=True, exist_ok=True)

    out_path = out_dir / f"extraction_{ts}.json"

    results = []

    for sample in samples:
        results.append({
            "file_path": sample.file_path,
            "function_name": sample.function_name,
            "start_line": sample.start_line,
            "end_line": sample.end_line,
            "language": sample.language.value,
            "code": sample.code,
        })

    payload = {
        "metadata": {
            "source_path": source_path,
            "generated_at": datetime.now().isoformat(),
        },
        "summary": {
            "functions_found": len(samples),
        },
        "results": results,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    return out_path

def save_call_graph(
    graph: dict,
    output_folder: str,
    source_path: str,
) -> Path:
    """
    Saves call graph output as JSON.
    """

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    out_dir = Path(output_folder)
    out_dir.mkdir(parents=True, exist_ok=True)

    out_path = out_dir / f"call_graph_{ts}.json"

    payload = {
        "source_path": source_path,
        "timestamp": datetime.now().isoformat(),
        "total_nodes": len(graph),
        "graph": {},
    }

    for name, node in graph.items():
        payload["graph"][name] = {
            "function_name": node.function_name,
            "file_path": node.file_path,
            "callers": node.callers,
            "callees": node.callees,
            "is_entry_point": node.is_entry_point,
        }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    return out_path