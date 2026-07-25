"""
Call graph export to external formats.
Supports DOT (Graphviz) and interactive HTML (pyvis/vis.js).
"""
from __future__ import annotations

import json
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

def _finding_node_ids(findings: list[dict] | None) -> set:
    """Node ids of everything a run flagged as vulnerable."""
    ids = set()
    for f in findings or []:
        if f.get("vulnerability_found"):
            ids.add(f"{f.get('file_path', '')}::{f.get('function_name', '')}")
    return ids


def _neighbourhood(graph: dict, seeds: set, hops: int) -> set:
    """Seeds plus everything within `hops` call-graph steps, in either
    direction — a vulnerable function's callers matter as much as its callees
    when the question is how user input reaches it."""
    keep = {s for s in seeds if s in graph}
    frontier = set(keep)

    for _ in range(max(0, hops)):
        nxt = set()
        for node_id in frontier:
            node = graph.get(node_id, {})
            for nb in list(node.get("callees", [])) + list(node.get("callers", [])):
                if nb in graph and nb not in keep and not nb.startswith("external::"):
                    nxt.add(nb)
        if not nxt:
            break
        keep |= nxt
        frontier = nxt

    return keep


def select_subgraph(
    graph: dict,
    findings: list[dict] | None = None,
    focus: str | None = None,
    hops: int = 1,
    only_findings: bool = False,
    hide_isolated: bool = False,
) -> dict:
    """Cuts a large call graph down to something a person can actually read.

    A few-hundred-function repository renders as an undifferentiated hairball:
    every node is drawn, every label overlaps, and nothing is legible. The
    honest fix is to draw less, not to restyle the same mess — so this returns
    the sub-graph worth looking at, with each kept node's callers/callees
    pruned to the kept set so no edge dangles.

    focus         - keep only this function (matched on name or file::name)
                    and its neighbourhood
    only_findings - keep only flagged functions and their neighbourhood
    hops          - how far to expand around those seeds (0 = seeds alone)
    hide_isolated - drop nodes with no remaining edges
    """
    internal = {k: v for k, v in graph.items() if not v.get("is_external")}

    seeds: set | None = None
    if focus:
        seeds = {
            node_id for node_id, node in internal.items()
            if node_id == focus or node.get("function_name") == focus
        }
        if not seeds:
            raise ValueError(
                f"No function matching {focus!r} in this graph. Pass a function name "
                "as it appears in the run, or 'file/path.ts::functionName'."
            )
    elif only_findings:
        seeds = _finding_node_ids(findings) & set(internal)
        if not seeds:
            raise ValueError(
                "No flagged functions to focus on — pass --results with a run that "
                "found something, or drop --only-findings."
            )

    keep = _neighbourhood(internal, seeds, hops) if seeds is not None else set(internal)

    out: dict = {}
    for node_id in keep:
        node = dict(internal[node_id])
        node["callees"] = [c for c in node.get("callees", []) if c in keep]
        node["callers"] = [c for c in node.get("callers", []) if c in keep]
        out[node_id] = node

    if hide_isolated:
        out = {
            k: v for k, v in out.items()
            if v["callees"] or v["callers"] or k in (seeds or set())
        }

    return out


def export_html(
    graph: dict,
    output_path: str | Path,
    findings: list[dict] | None = None,
    label_mode: str = "auto",
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
    # Settings that work for 30 nodes actively harm 1000: curved edges turn
    # into visual mush, every label overlaps, and the layout never settles.
    # Scale the rendering to the graph actually being drawn.
    n_nodes = sum(1 for v in graph.values() if not v.get("is_external"))
    large = n_nodes > 150

    net.set_options(json.dumps({
        "nodes": {
            "borderWidth": 2,
            "borderWidthSelected": 4,
            "font": {"size": 13, "face": "monospace", "strokeWidth": 3,
                     "strokeColor": "#1a1a2e"},
            "shape": "dot" if large else "box",
            "scaling": {"min": 8, "max": 40},
        },
        "edges": {
            "arrows": {"to": {"enabled": True, "scaleFactor": 0.5 if large else 0.7}},
            "color": {"color": "#4a4a6a" if large else "#555577",
                      "highlight": "#aaaaff", "opacity": 0.5 if large else 0.9},
            # Straight edges on a big graph: curves overlap into noise and cost
            # a great deal of layout time for no readability gain.
            "smooth": False if large else {"type": "cubicBezier",
                                           "forceDirection": "horizontal"},
            "width": 0.5 if large else 1,
        },
        "layout": {
            "hierarchical": {"enabled": False},
            # vis.js's "improved" layout is O(n^2)-ish and stalls on big graphs.
            "improvedLayout": not large,
        },
        "physics": {
            "stabilization": {"iterations": 400 if large else 200,
                              "updateInterval": 25},
            # forceAtlas2 separates clusters far better than barnesHut at scale.
            "solver": "forceAtlas2Based" if large else "barnesHut",
            "forceAtlas2Based": {
                "gravitationalConstant": -120,
                "centralGravity": 0.005,
                "springLength": 220,
                "springConstant": 0.05,
                "damping": 0.6,
                "avoidOverlap": 0.6,
            },
            "barnesHut": {
                "gravitationalConstant": -8000,
                "centralGravity": 0.3,
                "springLength": 120,
            },
            # Freeze once settled — a graph that never stops drifting cannot be
            # read, and cannot be screenshotted for a thesis figure.
            "adaptiveTimestep": True,
        },
        "interaction": {
            "hover": True,
            "tooltipDelay": 150,
            "navigationButtons": True,
            "keyboard": True,
            "multiselect": True,
        },
    }))

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

        # Labelling every node is what makes a big graph unreadable — the text
        # collides long before the nodes do. Above the threshold only the nodes
        # you are actually looking for keep a permanent label; the rest carry
        # the same information on hover.
        important = (
            node_id in vuln_nodes
            or node.get("is_entry_point")
            or node.get("is_taint_sink")
            or (callers_count + callees_count) >= 8
        )
        if label_mode == "none":
            show_label = False
        elif label_mode == "important":
            show_label = important
        elif label_mode == "all":
            show_label = True
        else:                                    # auto
            show_label = important if large else True

        net.add_node(
            node_id,
            label=label if show_label else " ",
            title=tooltip,
            # Size by connectedness so hubs read as hubs instead of every node
            # looking equally significant.
            value=1 + callers_count + callees_count,
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
