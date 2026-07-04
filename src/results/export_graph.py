"""
Call graph export to external formats.
Currently supports DOT (Graphviz) for visualisation.
"""
from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Severity → DOT colour used when annotating vulnerability findings on nodes
_SEVERITY_COLOURS = {
    "critical": "red",
    "high":     "orangered",
    "medium":   "orange",
    "low":      "gold",
}


def export_dot(
    graph: dict,
    output_path: str | Path,
    findings: list[dict] | None = None,
) -> Path:
    """
    Exports a call graph to DOT format for Graphviz visualisation.

    graph       - call graph dict as returned by save_call_graph / load_call_graph
    output_path - destination .dot file
    findings    - optional list of finding dicts from a run JSON to colour vulnerable nodes

    Render with:
        dot -Tpng output.dot -o output.png
        dot -Tsvg output.dot -o output.svg
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    # Build a set of vulnerable node_ids → colour from findings
    vuln_nodes: dict[str, str] = {}
    if findings:
        for f in findings:
            if not f.get("vulnerability_found"):
                continue
            fn = f.get("function_name", "")
            fp = f.get("file_path", "")
            node_id = f"{fp}::{fn}"
            sev = (f.get("severity") or "low").lower()
            vuln_nodes[node_id] = _SEVERITY_COLOURS.get(sev, "gold")

    lines = ["digraph call_graph {"]
    lines.append('  graph [rankdir=LR fontname="Helvetica"];')
    lines.append('  node  [shape=box fontname="Helvetica" fontsize=10];')
    lines.append('  edge  [fontname="Helvetica" fontsize=8];')
    lines.append("")

    for node_id, node in graph.items():
        if node.get("is_external"):
            continue

        label = _dot_label(node)
        attrs = [f'label="{label}"']

        if node_id in vuln_nodes:
            attrs.append(f'style=filled fillcolor={vuln_nodes[node_id]}')
        elif node.get("is_entry_point"):
            attrs.append('style=filled fillcolor=lightblue')
        elif node.get("is_infrastructure"):
            attrs.append('style=filled fillcolor=lightyellow')

        safe_id = _dot_id(node_id)
        lines.append(f'  {safe_id} [{", ".join(attrs)}];')

    lines.append("")

    for node_id, node in graph.items():
        if node.get("is_external"):
            continue
        src = _dot_id(node_id)
        for callee_id in node.get("callees", []):
            if callee_id.startswith("external::"):
                continue
            tgt = _dot_id(callee_id)
            lines.append(f"  {src} -> {tgt};")

    lines.append("}")

    out.write_text("\n".join(lines), encoding="utf-8")
    logger.info("DOT graph exported → %s (%d nodes)", out, len(graph))
    return out


def _dot_label(node: dict) -> str:
    name = node.get("function_name", "?")
    fp = node.get("file_path", "")
    # show only the filename, not the full path
    short = Path(fp).name if fp else ""
    return f"{name}\\n{short}" if short else name


def _dot_id(node_id: str) -> str:
    # DOT node IDs must be quoted strings; escape backslashes and quotes
    safe = node_id.replace("\\", "/").replace('"', '\\"')
    return f'"{safe}"'
