"""
Reading a result bundle.

A bundle is one directory holding whatever an analysis produced:
`analysis.json`, `extraction.json`, `call_graph.json`, the graph HTML/DOT, a
`checkpoint.jsonl`, and a patch artifact once patches have been generated.

Every field of every artifact is exposed. Nothing is summarised away — the UI
decides what to show, this module decides nothing.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from src.web import paths


def _mtime(path: Path) -> Optional[str]:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")
    except OSError:
        return None


def patch_file(directory: Path) -> Optional[Path]:
    """The patch artifact in a bundle.

    `patch` names its output `<run_id>_patches.json`, so it is found by suffix
    rather than by a fixed name. Newest wins if a run was patched twice.
    """
    candidates = sorted(
        directory.glob("*_patches.json"),
        key=lambda p: p.stat().st_mtime if p.exists() else 0,
        reverse=True,
    )
    if candidates:
        return candidates[0]
    fallback = directory / "patches.json"
    return fallback if fallback.is_file() else None


def summary(directory: Path) -> dict:
    """Everything the Results summary tab needs, in one read."""
    analysis = paths.read_json(directory / "analysis.json")
    extraction = paths.read_json(directory / "extraction.json")
    graph = paths.read_json(directory / "call_graph.json")
    checkpoint = paths.read_jsonl(directory / "checkpoint.jsonl")
    patches = patch_file(directory)
    patch_data = paths.read_json(patches) if patches else None

    findings = (analysis or {}).get("findings") or []
    flagged = [f for f in findings if f.get("vulnerability_found")]

    meta = (analysis or {}).get("meta") or {}

    result: dict[str, Any] = {
        "output_dir": str(directory),
        "display_dir": paths.display_path(directory),
        "modified_at": _mtime(directory),

        "has_analysis": analysis is not None,
        "has_extraction": extraction is not None,
        "has_graph": graph is not None,
        "has_graph_html": (directory / "call_graph.html").is_file(),
        "has_annotated_html": (directory / "call_graph_annotated.html").is_file(),
        "has_dot": (directory / "call_graph.dot").is_file(),
        "has_checkpoint": bool(checkpoint),
        "has_patches": patch_data is not None,

        "run_id": (analysis or {}).get("run_id"),
        "model": (analysis or {}).get("model"),
        "source_path": (analysis or {}).get("source_path")
                       or ((extraction or {}).get("metadata") or {}).get("source_path"),
        "timestamp": (analysis or {}).get("timestamp"),
        "schema_version": (analysis or {}).get("schema_version"),
        "analysis_mode": _dominant_mode(findings),

        "totals": (analysis or {}).get("summary") or {},
        "extraction_totals": (extraction or {}).get("summary") or {},
        "meta": meta,
        # Surfaced as its own flag rather than buried in meta: a partial run
        # scored as if complete reads as catastrophic recall, not an unfinished
        # run, and nothing else in the file reveals the difference.
        "partial": bool(meta.get("partial_run")),
        "partial_reason": meta.get("partial_reason"),

        "severity_counts": dict(Counter(f.get("severity") or "unknown" for f in flagged)),
        "cwe_counts": dict(Counter(f["cwe_id"] for f in flagged if f.get("cwe_id"))),
        "graph_nodes": (graph or {}).get("total_nodes") or len((graph or {}).get("graph") or {}),
        "checkpoint_records": len(checkpoint),

        "patch_summary": (patch_data or {}).get("summary"),
        "patch_file": patches.name if patches else None,

        "artifacts": artifacts(directory),
    }
    return result


def _dominant_mode(findings: list[dict]) -> Optional[str]:
    """`analysis_mode` is per finding, not per run — read it back as the mode."""
    modes = Counter(f.get("analysis_mode") for f in findings if f.get("analysis_mode"))
    return modes.most_common(1)[0][0] if modes else None


def findings(directory: Path) -> list[dict]:
    analysis = paths.read_json(directory / "analysis.json")
    return (analysis or {}).get("findings") or []


def extraction(directory: Path) -> dict:
    return paths.read_json(directory / "extraction.json") or {}


def graph(directory: Path) -> dict:
    return paths.read_json(directory / "call_graph.json") or {}


def checkpoint(directory: Path) -> list[dict]:
    return paths.read_jsonl(directory / "checkpoint.jsonl")


def patches(directory: Path) -> Optional[dict]:
    path = patch_file(directory)
    return paths.read_json(path) if path else None


def artifacts(directory: Path) -> list[dict]:
    entries: list[dict] = []
    try:
        children = sorted(directory.iterdir())
    except OSError:
        return entries
    for child in children:
        if not child.is_file():
            continue
        try:
            stat = child.stat()
        except OSError:
            continue
        entries.append({
            "name": child.name,
            "size_bytes": stat.st_size,
            "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
            "kind": child.suffix.lstrip(".").lower() or "other",
            # Only whitelisted names are readable through the API; the rest are
            # listed so the directory contents are never misrepresented.
            "readable": child.name in paths.RUN_ARTIFACTS
                        or child.name.endswith("_patches.json"),
        })
    return entries


def function_source(directory: Path, file_path: str, function_name: str) -> Optional[dict]:
    """The extracted source of one function, for the finding detail view.

    Read from `extraction.json` rather than from the analysed project, so the
    source shown is exactly what was sent to the model — even if the project has
    changed since, and even if it is no longer on this machine.
    """
    data = extraction(directory)
    normalised = file_path.replace("\\", "/") if file_path else ""
    fallback = None
    for entry in data.get("results") or []:
        if entry.get("function_name") != function_name:
            continue
        entry_path = (entry.get("file_path") or "").replace("\\", "/")
        if normalised and (entry_path == normalised or entry_path.endswith(normalised)):
            return entry
        fallback = fallback or entry
    return fallback
