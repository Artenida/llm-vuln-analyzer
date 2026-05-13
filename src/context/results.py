"""
Context persistence.
Saves call graph and context analysis outputs.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from src.context.models import CallGraphNode


def save_call_graph(
    graph: dict[str, CallGraphNode],
    output_folder: str,
    source_path: str,
) -> Path:

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
        json.dump(payload, f, indent=2)

    return out_path