"""
Graph persistence utilities.
Handles serialisation and deserialisation of call graphs.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def load_call_graph(path: str | Path) -> dict:
    """
    Loads a previously saved call graph JSON back into a plain dict.
    Returns the graph dict keyed by node_id, or empty dict on failure.
    """
    p = Path(path)
    if not p.exists():
        logger.error("Call graph file not found: %s", p)
        return {}

    try:
        with open(p, encoding="utf-8") as f:
            payload = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Could not load call graph from %s: %s", p, e)
        return {}

    return payload.get("graph", {})


def merge_call_graphs(graphs: list[dict]) -> dict:
    """
    Merges multiple call graph dicts into one.
    Callers and callees lists are union-merged per node; duplicates removed.
    Used when analysing a project split across multiple partial runs.
    """
    merged: dict = {}

    for graph in graphs:
        for node_id, node in graph.items():
            if node_id not in merged:
                merged[node_id] = {
                    "function_name":     node.get("function_name", ""),
                    "file_path":         node.get("file_path", ""),
                    "callers":           [],
                    "callees":           [],
                    "is_entry_point":    node.get("is_entry_point", False),
                    "is_infrastructure": node.get("is_infrastructure", False),
                    "is_external":       node.get("is_external", False),
                }

            existing = merged[node_id]
            existing["callers"] = sorted(set(existing["callers"]) | set(node.get("callers", [])))
            existing["callees"] = sorted(set(existing["callees"]) | set(node.get("callees", [])))

    return merged


def graph_stats(graph: dict) -> dict:
    """Returns summary statistics for a call graph dict."""
    total = len(graph)
    entry_points = sum(1 for n in graph.values() if n.get("is_entry_point"))
    infrastructure = sum(1 for n in graph.values() if n.get("is_infrastructure"))
    external = sum(1 for n in graph.values() if n.get("is_external"))
    internal = total - external

    edge_count = sum(len(n.get("callees", [])) for n in graph.values())

    return {
        "total_nodes":    total,
        "internal_nodes": internal,
        "external_nodes": external,
        "entry_points":   entry_points,
        "infrastructure": infrastructure,
        "total_edges":    edge_count,
    }
