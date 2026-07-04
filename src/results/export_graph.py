"""
Call graph export to external formats.
Supports DOT (Graphviz) and interactive HTML (pyvis/vis.js).
"""
from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Severity → colour used when annotating vulnerability findings on nodes
_SEVERITY_COLOURS = {
    "critical": "#CC0000",
    "high":     "#FF4444",
    "medium":   "#FF9900",
    "low":      "#FFCC00",
}

_SEVERITY_COLOURS_DOT = {
    "critical": "red",
    "high":     "orangered",
    "medium":   "orange",
    "low":      "gold",
}

# Node role → vis.js colour (background)
_ROLE_COLOURS = {
    "vulnerable_critical": "#CC0000",
    "vulnerable_high":     "#FF4444",
    "vulnerable_medium":   "#FF9900",
    "vulnerable_low":      "#FFCC00",
    "taint_sink":          "#FF6666",
    "taint_source":        "#44BB99",
    "entry_point":         "#6699CC",
    "infrastructure":      "#FFCC44",
    "default":             "#D2D2D2",
}


# ─────────────────────────────────────────────────────────────────────────────
# HTML (pyvis)
# ─────────────────────────────────────────────────────────────────────────────

def export_html(
    graph: dict,
    output_path: str | Path,
    findings: list[dict] | None = None,
) -> Path:
    """
    Exports an interactive HTML call graph using pyvis/vis.js.

    graph        - plain dict as returned by nodes_to_dict() or load_call_graph()
    output_path  - destination .html file
    findings     - optional list of finding dicts from a run JSON to colour
                   vulnerable nodes; each entry should have function_name,
                   file_path, vulnerability_found, severity

    Node colour legend (shown in page):
      Steel blue  — HTTP entry point / route handler
      Teal        — Taint source (entry point that feeds user data into the graph)
      Red         — Taint sink (passes data to dangerous operations)
      Orange/Red  — Vulnerable (coloured by severity)
      Amber       — Infrastructure (DB / IO layer)
      Grey        — Regular internal function
    """
    try:
        from pyvis.network import Network
    except ImportError:
        raise ImportError(
            "pyvis is required for HTML export: pip install pyvis"
        )

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    # ── build vuln_nodes: node_id → hex colour ────────────────────────────────
    vuln_nodes: dict[str, str] = {}
    if findings:
        for f in findings:
            if not f.get("vulnerability_found"):
                continue
            fn = f.get("function_name", "")
            fp = f.get("file_path", "")
            node_id = f"{fp}::{fn}"
            sev = (f.get("severity") or "low").lower()
            vuln_nodes[node_id] = _SEVERITY_COLOURS.get(sev, _SEVERITY_COLOURS["low"])

    # ── vis.js network options ────────────────────────────────────────────────
    net = Network(
        height="780px",
        width="100%",
        directed=True,
        bgcolor="#1a1a2e",
        font_color="#e0e0e0",
        notebook=False,
    )
    net.set_options("""
    {
      "nodes": {
        "borderWidth": 2,
        "borderWidthSelected": 4,
        "font": { "size": 13, "face": "monospace" },
        "shape": "box"
      },
      "edges": {
        "arrows": { "to": { "enabled": true, "scaleFactor": 0.7 } },
        "color": { "color": "#555577", "highlight": "#aaaaff" },
        "smooth": { "type": "cubicBezier", "forceDirection": "horizontal" }
      },
      "layout": {
        "hierarchical": {
          "enabled": false
        }
      },
      "physics": {
        "stabilization": { "iterations": 200 },
        "barnesHut": {
          "gravitationalConstant": -8000,
          "centralGravity": 0.3,
          "springLength": 120
        }
      },
      "interaction": {
        "hover": true,
        "tooltipDelay": 150,
        "navigationButtons": true,
        "keyboard": true
      }
    }
    """)

    # ── add nodes ─────────────────────────────────────────────────────────────
    internal_node_ids: set[str] = set()

    for node_id, node in graph.items():
        if node.get("is_external"):
            continue

        fn_name  = node.get("function_name", "?")
        fp       = node.get("file_path", "")
        short_fp = Path(fp).name if fp else ""

        label    = fn_name
        tooltip  = f"<b>{fn_name}</b><br>{fp}"

        badges: list[str] = []
        if node_id in vuln_nodes:
            color = vuln_nodes[node_id]
            # find severity label for badge
            for sev, col in _SEVERITY_COLOURS.items():
                if col == color:
                    badges.append(f"[{sev.upper()}]")
        elif node.get("is_taint_sink"):
            color = _ROLE_COLOURS["taint_sink"]
            badges.append("[SINK]")
        elif node.get("is_taint_source"):
            color = _ROLE_COLOURS["taint_source"]
            badges.append("[SOURCE]")
        elif node.get("is_entry_point"):
            color = _ROLE_COLOURS["entry_point"]
            badges.append("[ENTRY]")
        elif node.get("is_infrastructure"):
            color = _ROLE_COLOURS["infrastructure"]
            badges.append("[INFRA]")
        else:
            color = _ROLE_COLOURS["default"]

        if badges:
            tooltip += "<br>" + " ".join(badges)
        if short_fp:
            tooltip += f"<br><i>{short_fp}</i>"

        callers_count = len(node.get("callers", []))
        callees_count = len(node.get("callees", []))
        tooltip += f"<br>callers: {callers_count} | callees: {callees_count}"

        net.add_node(
            node_id,
            label=label,
            title=tooltip,
            color={
                "background": color,
                "border":     "#ffffff",
                "highlight":  {"background": "#ffffff", "border": "#ffffff"},
            },
            font={"color": "#111111" if color in ("#FFCC00", "#FFCC44", _ROLE_COLOURS["infrastructure"]) else "#ffffff"},
        )
        internal_node_ids.add(node_id)

    # ── add edges ─────────────────────────────────────────────────────────────
    for node_id, node in graph.items():
        if node.get("is_external"):
            continue
        for callee_id in node.get("callees", []):
            if callee_id.startswith("external::"):
                continue
            if callee_id not in internal_node_ids:
                continue
            net.add_edge(node_id, callee_id)

    # ── inject legend HTML + write file ──────────────────────────────────────
    net.write_html(str(out))
    _inject_legend(out)

    logger.info("HTML graph exported → %s (%d nodes)", out, len(internal_node_ids))
    return out


def _inject_legend(html_path: Path) -> None:
    """Appends a colour legend div just before </body>."""
    legend = """
<div id="llm-vuln-legend" style="
    position:fixed; bottom:16px; left:16px; z-index:9999;
    background:#1a1a2e; border:1px solid #555; border-radius:8px;
    padding:12px 16px; font-family:monospace; font-size:12px; color:#e0e0e0;
    max-width:220px;">
  <b>Node Legend</b><br><br>
  <span style="color:#FF4444">&#9632;</span> Vulnerable (high/critical)<br>
  <span style="color:#FF9900">&#9632;</span> Vulnerable (medium)<br>
  <span style="color:#FFCC00">&#9632;</span> Vulnerable (low)<br>
  <span style="color:#FF6666">&#9632;</span> Taint sink (dangerous op)<br>
  <span style="color:#44BB99">&#9632;</span> Taint source (user input)<br>
  <span style="color:#6699CC">&#9632;</span> Entry point / HTTP handler<br>
  <span style="color:#FFCC44">&#9632;</span> Infrastructure (DB / IO)<br>
  <span style="color:#D2D2D2">&#9632;</span> Internal function<br>
</div>
"""
    text = html_path.read_text(encoding="utf-8")
    text = text.replace("</body>", legend + "\n</body>")
    html_path.write_text(text, encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# DOT (Graphviz)
# ─────────────────────────────────────────────────────────────────────────────

def export_dot(
    graph: dict,
    output_path: str | Path,
    findings: list[dict] | None = None,
) -> Path:
    """
    Exports a call graph to DOT format for Graphviz visualisation.

    graph       - plain dict as returned by nodes_to_dict() or load_call_graph()
    output_path - destination .dot file
    findings    - optional list of finding dicts to colour vulnerable nodes

    Render with:
        dot -Tpng output.dot -o output.png
        dot -Tsvg output.dot -o output.svg
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    vuln_nodes: dict[str, str] = {}
    if findings:
        for f in findings:
            if not f.get("vulnerability_found"):
                continue
            fn = f.get("function_name", "")
            fp = f.get("file_path", "")
            node_id = f"{fp}::{fn}"
            sev = (f.get("severity") or "low").lower()
            vuln_nodes[node_id] = _SEVERITY_COLOURS_DOT.get(sev, "gold")

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
        elif node.get("is_taint_sink"):
            attrs.append('style=filled fillcolor=tomato')
        elif node.get("is_taint_source"):
            attrs.append('style=filled fillcolor=mediumaquamarine')
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
    short = Path(fp).name if fp else ""
    return f"{name}\\n{short}" if short else name


def _dot_id(node_id: str) -> str:
    safe = node_id.replace("\\", "/").replace('"', '\\"')
    return f'"{safe}"'
