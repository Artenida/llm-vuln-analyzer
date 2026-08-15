"""
Results persistence.
Saves analysis runs to timestamped JSON files under experiments/results/.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from src.llm.client import VulnerabilityReport
from src.llm.pricing import TokenUsage, estimate_cost
from src.models import CodeSample

logger = logging.getLogger(__name__)


def make_run_id(model: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"analysis_{model.replace('-', '_')}_{ts}"


def save_run(
    reports: list[VulnerabilityReport],
    samples: list[CodeSample],
    source_path: str,
    model: str,
    results_folder: str = "experiments/results",
    extra_meta: dict | None = None,
    filename: str | None = None,
    run_id: str | None = None,
) -> Path:
    """
    Saves a full analysis run to a timestamped JSON file.
    Returns the path to the saved file.

    Pass `run_id` when the caller already generated one up front (e.g. to
    attribute cost-ledger rows recorded during analysis to the same run
    before the run itself is saved) — otherwise one is generated here.
    """
    run_id = run_id or make_run_id(model)
    folder = Path(results_folder)
    folder.mkdir(parents=True, exist_ok=True)
    out_path = folder / (filename if filename else f"{run_id}.json")

    # build a lookup: (function_name, file_path) -> (start_line, end_line)
    # used to clamp affected_lines to the actual function range
    line_range: dict[tuple[str, str], tuple[int, int]] = {}
    for s in samples:
        if s.function_name and s.file_path and s.start_line and s.end_line:
            line_range[(s.function_name, s.file_path)] = (s.start_line, s.end_line)

    total = len(reports)
    found = sum(1 for r in reports if r.vulnerability_found)
    errors = sum(1 for r in reports if r.error is not None)
    hallucinated = sum(1 for r in reports if r.hallucination_flag)

    total_usage = TokenUsage()
    for r in reports:
        total_usage = total_usage + (r.token_usage or TokenUsage())
    # Recomputed from the summed usage rather than summing each report's
    # cost_usd — avoids float drift, and stays None (not a wrong number) if
    # the model isn't in the pricing table.
    total_cost_usd = estimate_cost(model, total_usage)

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
            "total_prompt_tokens": total_usage.prompt_tokens,
            "total_completion_tokens": total_usage.completion_tokens,
            "total_tokens": total_usage.total_tokens,
            "total_cost_usd": round(total_cost_usd, 6) if total_cost_usd is not None else None,
        },
        "findings": [],
    }

    if extra_meta:
        payload["meta"] = extra_meta

    # Build duplicate groups: same (function_name, cwe_id) flagged across different files.
    # Assign a shared group ID so evaluation can deduplicate without suppressing findings.
    dup_groups: dict[tuple, int] = {}
    group_counter = 0
    finding_groups: list[int | None] = []
    for report in reports:
        if report.vulnerability_found and report.cwe_id and report.function_name:
            dk = (report.function_name, report.cwe_id)
            if dk not in dup_groups:
                dup_groups[dk] = group_counter
                group_counter += 1
            finding_groups.append(dup_groups[dk])
        else:
            finding_groups.append(None)

    # Count groups that have more than one member (actual duplicates)
    from collections import Counter
    group_counts = Counter(g for g in finding_groups if g is not None)
    duplicate_groups = {g for g, c in group_counts.items() if c > 1}

    for report, group_id in zip(reports, finding_groups):
        # clamp affected_lines to the actual line range of the function
        raw_lines = report.affected_lines or []
        key = (report.function_name, report.file_path)
        if key in line_range and raw_lines:
            start, end = line_range[key]
            in_range = [l for l in raw_lines if start <= l <= end]
            if in_range:
                clamped_lines = in_range
            else:
                # attempt function-relative correction
                offset = start - 1
                corrected = [l + offset for l in raw_lines]
                clamped_lines = [l for l in corrected if start <= l <= end]
                if not clamped_lines:
                    clamped_lines = raw_lines
                    logger.debug(
                        "affected_lines %s for %s couldn't be clamped to [%d, %d]",
                        raw_lines,
                        report.function_name,
                        start,
                        end,
                    )
        else:
            clamped_lines = raw_lines

        is_dup = group_id is not None and group_id in duplicate_groups
        payload["findings"].append({
            "function_name":       report.function_name,
            "file_path":           report.file_path,
            "language":            report.language,
            "vulnerability_found": report.vulnerability_found,
            "cwe_id":              report.cwe_id,
            "affected_lines":      clamped_lines,
            "severity":            report.severity,
            "explanation":         report.explanation,
            "patch_suggestion":    report.patch_suggestion,
            "confidence":          report.confidence,
            "hallucination_flag":  report.hallucination_flag,
            "analysis_mode":       report.analysis_mode,
            "error":               report.error,
            "duplicate_group":     group_id if is_dup else None,
            "unified_diff":        report.unified_diff,
            "patch_valid":         report.patch_valid,
            "patch_error":         report.patch_error,
            "prompt_tokens":       report.token_usage.prompt_tokens if report.token_usage else 0,
            "completion_tokens":   report.token_usage.completion_tokens if report.token_usage else 0,
            "cost_usd":            round(report.cost_usd, 6) if report.cost_usd is not None else None,
        })

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    logger.info("Run saved → %s", out_path)
    return out_path


def save_extraction_results(
    samples: list[CodeSample],
    source_path: str,
    output_folder: str,
    filename: str | None = None,
    skipped: list | None = None,
) -> Path:
    """Saves extracted functions before analysis phase.

    `skipped` records functions too long to analyse, so a run's coverage can be
    stated exactly rather than inferred from the extracted count alone.
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(output_folder)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / (filename if filename else f"extraction_{ts}.json")

    results = []
    for sample in samples:
        results.append({
            "file_path":     sample.file_path,
            "function_name": sample.function_name,
            "start_line":    sample.start_line,
            "end_line":      sample.end_line,
            "language":      sample.language.value,
            "code":          sample.code,
        })

    skipped = skipped or []
    total_seen = len(samples) + len(skipped)

    payload = {
        "metadata": {
            "source_path":  source_path,
            "generated_at": datetime.now().isoformat(),
        },
        "summary": {
            "functions_found": len(samples),
            "functions_skipped_oversized": len(skipped),
            "coverage": round(len(samples) / total_seen, 4) if total_seen else 1.0,
        },
        "results": results,
        "skipped_oversized": [
            {
                "function_name": sk.name,
                "file_path":     sk.file_path,
                "start_line":    sk.start_line,
                "end_line":      sk.end_line,
                "line_count":    sk.line_count,
            }
            for sk in skipped
        ],
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    return out_path


def save_patches(
    patches: list[dict],
    run_id: str,
    source_path: str,
    output_folder: str = "experiments/results/patches",
    filename: str | None = None,
) -> Path:
    """
    Saves generated+validated patches for a completed run.
    Never touches the analyzed source project — this is a standalone reviewable
    artifact (diffs + validity), source project untouched unless --apply is used.
    """
    folder = Path(output_folder)
    folder.mkdir(parents=True, exist_ok=True)
    out_path = folder / (filename if filename else f"{run_id}_patches.json")

    total = len(patches)
    valid = sum(1 for p in patches if p.get("patch_valid"))

    total_prompt_tokens = sum(p.get("prompt_tokens", 0) for p in patches)
    total_completion_tokens = sum(p.get("completion_tokens", 0) for p in patches)
    known_costs = [p.get("cost_usd") for p in patches if p.get("cost_usd") is not None]
    # None (not 0) if ANY patch's cost is unknown — a partial sum would understate spend
    total_cost_usd = sum(known_costs) if len(known_costs) == total else None

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "run_id": run_id,
        "source_path": source_path,
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_patches": total,
            "valid": valid,
            "invalid": total - valid,
            "total_prompt_tokens": total_prompt_tokens,
            "total_completion_tokens": total_completion_tokens,
            "total_cost_usd": round(total_cost_usd, 6) if total_cost_usd is not None else None,
        },
        "patches": patches,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    logger.info("Patches saved → %s", out_path)
    return out_path


def save_call_graph(
    graph: dict,
    output_folder: str,
    source_path: str,
    filename: str | None = None,
) -> Path:
    """Saves call graph output as JSON."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(output_folder)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / (filename if filename else f"call_graph_{ts}.json")

    # Delegated rather than duplicated: this function used to hand-copy the node
    # fields, so a field added to CallGraphNode reached the in-memory graph and
    # the HTML export but silently vanished from the saved JSON.
    # `route_registrations` was lost that way.
    from src.context.call_graph import nodes_to_dict

    payload = {
        "source_path": source_path,
        "timestamp":   datetime.now().isoformat(),
        "total_nodes": len(graph),
        "graph":       nodes_to_dict(graph),
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    return out_path
