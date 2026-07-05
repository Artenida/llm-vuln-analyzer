"""
CLI entry point.

Commands:
  analyze    Run vulnerability analysis on a path or snippet
  show       Pretty-print a saved results JSON file
  graph      Build and/or visualize a call graph
  patch      Generate + validate fixes for flagged functions in a completed run

Key flags:
  --react           Use ReAct agent loop (reason->act->observe) instead of single-pass
  --dry-run         Extract + build graph only, no LLM calls
  patch --apply     Opt-in: write validated patches into the actual source files
                    (default `patch` behavior only saves a reviewable JSON artifact)

Analysis always builds the call graph and injects context into the prompt.
Use --react to switch from single-pass semantic to the agentic ReAct loop.
"""
from __future__ import annotations

import json

# Load .env automatically so users don't have to export env vars manually
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv optional — fall back to manually set env vars
import logging
from pathlib import Path
from typing import Dict, List, Optional

import typer

from src.config import load_config
from src.context.call_graph import CallGraphBuilder
from src.ingestion.extractor import CodeExtractor
from src.results import save_extraction_results, save_run, save_call_graph, save_patches
from src.results.patch_generator import PatchGenerator
from src.results.patch_validator import PatchValidator
from src.results.export_graph import export_dot, export_html
from src.results.save_graph import load_call_graph
from src.context.call_graph import nodes_to_dict
from src.llm.client import LLMClient
from src.agent.react_loop import ReActAgent, MAX_STEPS
from src.agent.tools import ToolSet
from src.models import CodeSample

app = typer.Typer(add_completion=False, pretty_exceptions_show_locals=False)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# analyze
# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def analyze(
    path: Optional[str] = typer.Option(
        None, "--path", "-p", help="File or directory to analyse."
    ),
    snippet: Optional[str] = typer.Option(
        None, "--snippet", "-s", help="Inline code string. Requires --language."
    ),
    language: Optional[str] = typer.Option(
        None, "--language", "-l", help="Language for --snippet (python, javascript, c, cpp)."
    ),
    config_path: Optional[str] = typer.Option(
        None, "--config", "-c", help="Path to YAML config file."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Extract + build graph only, no LLM calls."
    ),
    react: bool = typer.Option(
        False, "--react",
        help="Use ReAct agent loop (reason->act->observe) instead of single-pass semantic."
    ),
    visualize: bool = typer.Option(
        False, "--visualize", "-v",
        help="Export interactive HTML + DOT call graph after analysis."
    ),
    run_name: Optional[str] = typer.Option(
        None, "--run-name", "-n",
        help="Named experiment run. Outputs go to experiments/runs/<name>/ with fixed filenames."
    ),
):
    """Analyse source code for security vulnerabilities."""

    if path is None and snippet is None:
        typer.echo("Error: provide --path or --snippet", err=True)
        raise typer.Exit(1)

    config = load_config(config_path)

    # ── named run: redirect all outputs to experiments/runs/<name>/ ──────────
    if run_name:
        run_dir = f"experiments/runs/{run_name}"
        config.output.extraction_folder = run_dir
        config.output.context_folder    = run_dir
        config.output.analysis_folder   = run_dir

    extractor = CodeExtractor(max_function_lines=config.ingestion.max_function_lines)

    # ── extraction ────────────────────────────────────────────────────────────
    if path:
        typer.echo(f"\nIngesting {path}")
        samples = extractor.from_path(path)
        source_label = path
    else:
        if not language:
            typer.echo("Error: --language is required with --snippet", err=True)
            raise typer.Exit(1)
        samples = extractor.from_snippet(snippet, language)
        source_label = "<snippet>"

    if not samples:
        typer.echo("No functions extracted.")
        raise typer.Exit(1)

    lang_counts: dict = {}
    for s in samples:
        lang_counts[s.language.value] = lang_counts.get(s.language.value, 0) + 1

    typer.echo("\nExtraction summary")
    typer.echo(f"  Functions : {len(samples)}")
    for lang, count in sorted(lang_counts.items()):
        typer.echo(f"  {lang:<12}: {count}")

    extraction_out = save_extraction_results(
        samples=samples,
        source_path=source_label,
        output_folder=config.output.extraction_folder,
        filename="extraction.json" if run_name else None,
    )
    typer.echo(f"\nExtraction saved → {extraction_out}")

    # ── call graph ────────────────────────────────────────────────────────────
    graph: dict = {}
    name_index: dict = {}
    tools: Optional[ToolSet] = None

    typer.echo("\nBuilding call graph...")
    builder = CallGraphBuilder(api_key=config.openai_api_key, model=config.llm.model)
    graph, name_index = builder.build(samples, routes=extractor.all_routes)

    context_out = save_call_graph(
        graph=graph,
        output_folder=config.output.context_folder,
        source_path=source_label,
        filename="call_graph.json" if run_name else None,
    )
    typer.echo(f"Call graph built successfully ({len(graph)} nodes)")
    typer.echo(f"Call graph saved → {context_out}")
    tools = ToolSet(graph, name_index)

    if visualize:
        plain = nodes_to_dict(graph)
        dot_out = export_dot(
            plain,
            Path(config.output.context_folder) / "call_graph.dot",
        )
        html_out = export_html(
            plain,
            Path(config.output.context_folder) / "call_graph.html",
        )
        typer.echo(f"DOT  graph  → {dot_out}")
        typer.echo(f"HTML graph  → {html_out} (open in browser)")

    # ── dry run ───────────────────────────────────────────────────────────────
    if dry_run:
        typer.echo("\nDry run complete — no LLM calls made.")
        raise typer.Exit(0)

    # ── LLM + agent setup ─────────────────────────────────────────────────────
    client = LLMClient(config.llm)
    agent = ReActAgent(llm=client, tools=tools, max_steps=config.agent.max_steps)

    if react:
        mode_label = f"ReAct loop — reason→act→observe (max {config.agent.max_steps} tool calls per function)"
    else:
        mode_label = "single-pass with call graph context injected into prompt"

    typer.echo(f"\nAnalyzing {len(samples)} functions with {config.llm.model}")
    typer.echo(f"  Mode: {mode_label}\n")

    reports = []

    # ── analysis loop ─────────────────────────────────────────────────────────
    for i, sample in enumerate(samples, 1):
        typer.echo(f"  [{i:>2}/{len(samples)}] {sample.function_name:<30}", nl=False)

        try:
            if react and tools is not None:
                report = agent.run(sample, graph, all_samples=samples)
            else:
                hop = tools.trace_one_hop(sample.function_name, sample.file_path)
                prompt = _build_context_prompt(sample, hop, tools, samples)
                report = client.analyze(sample, context_prompt=prompt)
                report.analysis_mode = "call_graph_context"

            reports.append(report)

            status = "VULN" if report.vulnerability_found else "clean"
            sev = f" [{report.severity}]" if report.vulnerability_found and report.severity else ""
            err = f" ERR:{report.error}" if report.error else ""
            typer.echo(f" → {status}{sev} (conf:{report.confidence:.2f}){err}")

        except Exception as e:
            typer.echo(" → ERROR")
            logger.error("Analysis failed for %s: %s", sample.function_name, e)

    # ── save results ──────────────────────────────────────────────────────────
    out_path = save_run(
        reports=reports,
        samples=samples,
        source_path=source_label,
        model=config.llm.model,
        results_folder=config.output.analysis_folder,
        filename="analysis.json" if run_name else None,
    )

    # ── summary ───────────────────────────────────────────────────────────────
    found = [r for r in reports if r.vulnerability_found]
    errors = [r for r in reports if r.error]

    typer.echo("\n" + "─" * 50)
    typer.echo(f"Total analysed : {len(reports)}")
    typer.echo(f"Vulnerabilities: {len(found)}")
    typer.echo(f"Clean          : {len(reports) - len(found) - len(errors)}")
    typer.echo(f"Errors         : {len(errors)}")
    typer.echo(f"Results saved  → {out_path}")

    if found:
        typer.echo("\nFindings:")
        for r in found:
            sev = r.severity or "?"
            cwe = r.cwe_id or "unknown CWE"
            mode = r.analysis_mode or "?"
            typer.echo(f"  [{sev.upper():>8}] {r.function_name} ({cwe}) [{mode}]")
            if r.file_path:
                typer.echo(f"             {r.file_path}")
            if r.explanation:
                typer.echo(f"             {r.explanation[:120]}")

    # ── re-export HTML with findings overlaid ─────────────────────────────────
    if visualize and graph:
        findings_dicts = [
            {
                "function_name":     r.function_name,
                "file_path":         r.file_path,
                "vulnerability_found": r.vulnerability_found,
                "severity":          r.severity,
            }
            for r in reports
        ]
        plain = nodes_to_dict(graph)
        html_out = export_html(
            plain,
            Path(config.output.context_folder) / "call_graph_annotated.html",
            findings=findings_dicts,
        )
        typer.echo(f"\nAnnotated graph → {html_out}")


# ─────────────────────────────────────────────────────────────────────────────
# Context prompt builder (single-pass with graph, no ReAct)
# ─────────────────────────────────────────────────────────────────────────────

def _build_context_prompt(
    sample: CodeSample,
    hop: dict,
    tools: ToolSet,
    all_samples: List[CodeSample],
) -> str:
    code_map: Dict[str, str] = {}
    for s in all_samples:
        code_map[f"{s.file_path}::{s.function_name}"] = s.code
        code_map[s.function_name] = s.code

    lang = sample.language.value
    callers = hop.get("callers", [])
    callees = hop.get("callees", [])

    lines = []
    lines.append(
        f"You are an expert security code reviewer. The code is written in {lang}.\n\n"
        "TASK: Find security vulnerabilities DIRECTLY present in the TARGET FUNCTION only.\n\n"
        "CRITICAL RULE: For each category below, assume NOT VULNERABLE unless you see direct\n"
        "evidence in the TARGET FUNCTION code itself.\n"
        "  - A function that calls another function is NOT itself vulnerable for what that callee does.\n"
        "  - A function that receives a parameter and passes it along is NOT missing input\n"
        "    validation — validation belongs at the layer that first receives untrusted data.\n"
        "  - A config.X reference is NOT a hardcoded secret.\n"
        "  - A thin controller/handler that delegates to a service is clean unless it adds unsafe logic.\n"
    )
    lines.append("=" * 60)
    lines.append(f"TARGET FUNCTION: {sample.function_name}")
    lines.append(f"File: {sample.file_path}  Lines: {sample.start_line}–{sample.end_line}")
    lines.append("=" * 60)
    lines.append(f"```{lang}\n{sample.code}\n```\n")

    internal_callers = [c for c in callers if not c.startswith("external::")]
    if internal_callers:
        lines.append("CALLED BY (shown to trace input origin — do NOT flag these):")
        for cid in internal_callers:
            code = code_map.get(cid) or code_map.get(cid.split("::")[-1])
            lines.append(f"\n> {cid.split('::')[-1]}")
            if code:
                lines.append(f"```{lang}\n{code}\n```")

    internal_callees = [c for c in callees if not c.startswith("external::")]
    external_callees = [c for c in callees if c.startswith("external::")]
    if internal_callees:
        lines.append("\nCALLS INTO (shown for data flow — do NOT flag vulnerabilities inside these):")
        for cid in internal_callees:
            code = code_map.get(cid) or code_map.get(cid.split("::")[-1])
            lines.append(f"\n> {cid.split('::')[-1]}")
            if code:
                lines.append(f"```{lang}\n{code}\n```")
    if external_callees:
        lines.append("\nExternal calls: " + ", ".join(
            c.replace("external::", "") for c in external_callees
        ))

    lines.append(
        "\nCWE assignment rules — use the MOST SPECIFIC applicable CWE:\n"
        "  CWE-89   SQL/NoSQL built by string concat or template literal interpolation\n"
        "  CWE-347  JWT or token accepted without signature verification\n"
        "  CWE-798  Hardcoded credentials, secrets, API keys, or static bypass codes\n"
        "  CWE-20   Security decision based on a client-supplied header (e.g. X-Forwarded-For)\n"
        "  CWE-306  Security step skipped (e.g. current-password not verified before change)\n"
        "  CWE-208  Non-constant-time comparison of secrets (timing attack)\n"
        "  CWE-269  Role or privilege accepted directly from user-controlled input\n"
        "  NOTE: CWE-290 is for relay/reflection attacks — NOT for static bypass codes; use CWE-798.\n"
        "\nSeverity rules — consistent for the same CWE:\n"
        "  high   → CWE-89, CWE-347, CWE-798\n"
        "  medium → CWE-20, CWE-208, CWE-269, CWE-306\n"
        "  low    → informational / defence-in-depth only\n"
        "  Deviate only when you can state a concrete amplifying or mitigating factor.\n"
        "\nRespond with this EXACT JSON — no markdown, no extra text:\n"
        "{\n"
        '  "vulnerability_found": boolean,\n'
        '  "cwe_id": string (e.g. "CWE-89") or null,\n'
        '  "affected_lines": [integers — file-relative line numbers in TARGET only],\n'
        '  "severity": "low" | "medium" | "high" | "critical" | null,\n'
        '  "explanation": string — what is wrong in the TARGET and why it is exploitable,\n'
        '  "patch_suggestion": string — concrete fix for the TARGET function,\n'
        '  "confidence": float 0.0–1.0 — probability that a vulnerability EXISTS.\n'
        '               MUST be > 0.5 when vulnerability_found is true.\n'
        '               MUST be < 0.5 when vulnerability_found is false.,\n'
        '  "hallucination_flag": boolean\n'
        "}"
    )
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# show
# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def show(
    result_file: str = typer.Argument(...),
    only_vulns: bool = typer.Option(False, "--vulns-only"),
):
    p = Path(result_file)
    if not p.exists():
        typer.echo(f"File not found: {p}", err=True)
        raise typer.Exit(1)

    with open(p, encoding="utf-8") as f:
        data = json.load(f)

    typer.echo(f"\nRun:    {data.get('run_id')}")
    typer.echo(f"Model:  {data.get('model')}")
    typer.echo(f"Source: {data.get('source_path')}")
    typer.echo(f"Time:   {data.get('timestamp')}")

    summary = data.get("summary", {})
    typer.echo("\nSummary")
    typer.echo(f"  Total       : {summary.get('total_functions')}")
    typer.echo(f"  Vulnerable  : {summary.get('vulnerabilities_found')}")
    typer.echo(f"  Clean       : {summary.get('clean')}")
    typer.echo(f"  Errors      : {summary.get('errors')}")

    findings = data.get("findings", [])
    if only_vulns:
        findings = [f for f in findings if f.get("vulnerability_found")]

    typer.echo(f"\nFindings ({len(findings)}):")
    for f in findings:
        marker = "VULN" if f.get("vulnerability_found") else "clean"
        mode = f.get("analysis_mode", "?")
        typer.echo(
            f"  [{marker}] {f.get('function_name')} "
            f"cwe={f.get('cwe_id')} "
            f"conf={f.get('confidence', 0):.2f} "
            f"sev={f.get('severity')} "
            f"mode={mode}"
        )
        if f.get("explanation"):
            typer.echo(f"       {f['explanation'][:120]}")


# ─────────────────────────────────────────────────────────────────────────────
# graph — build and/or visualize a call graph
# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def graph(
    path: Optional[str] = typer.Option(
        None, "--path", "-p",
        help="Source code path to build a call graph from (file or directory)."
    ),
    graph_file: Optional[str] = typer.Option(
        None, "--graph-file", "-g",
        help="Path to a previously saved call_graph_*.json to visualize without re-analysis."
    ),
    results_file: Optional[str] = typer.Option(
        None, "--results", "-r",
        help="Path to an analysis run JSON to overlay vulnerability findings on the graph."
    ),
    output_dir: str = typer.Option(
        "experiments/results/context",
        "--output-dir", "-o",
        help="Directory to write graph files into."
    ),
    html: bool = typer.Option(True,  "--html/--no-html", help="Emit interactive HTML graph."),
    dot:  bool = typer.Option(False, "--dot",            help="Also emit a Graphviz DOT file."),
    config_path: Optional[str] = typer.Option(
        None, "--config", "-c", help="Path to YAML config file."
    ),
):
    """Build and visualize a call graph from source code or a saved graph JSON."""

    if path is None and graph_file is None:
        typer.echo("Error: provide --path or --graph-file", err=True)
        raise typer.Exit(1)

    # ── load findings for overlay (optional) ──────────────────────────────────
    findings_dicts: list = []
    if results_file:
        import json as _json
        rp = Path(results_file)
        if not rp.exists():
            typer.echo(f"Results file not found: {rp}", err=True)
            raise typer.Exit(1)
        with open(rp, encoding="utf-8") as f:
            run_data = _json.load(f)
        findings_dicts = run_data.get("findings", [])
        typer.echo(f"Loaded {len(findings_dicts)} findings from {rp.name}")

    # ── load or build graph ───────────────────────────────────────────────────
    if graph_file:
        plain = load_call_graph(graph_file)
        if not plain:
            typer.echo("Could not load call graph.", err=True)
            raise typer.Exit(1)
        typer.echo(f"Loaded graph with {len(plain)} nodes from {graph_file}")
    else:
        config = load_config(config_path)
        extractor = CodeExtractor(max_function_lines=config.ingestion.max_function_lines)
        typer.echo(f"\nIngesting {path} ...")
        samples = extractor.from_path(path)
        if not samples:
            typer.echo("No functions extracted.")
            raise typer.Exit(1)
        typer.echo(f"  {len(samples)} functions extracted")

        typer.echo("Building call graph ...")
        builder = CallGraphBuilder(api_key=config.openai_api_key, model=config.llm.model)
        g_nodes, name_index = builder.build(samples, routes=extractor.all_routes)

        plain = nodes_to_dict(g_nodes)

        context_out = save_call_graph(
            graph=g_nodes,
            output_folder=output_dir,
            source_path=path,
        )
        typer.echo(f"Call graph saved → {context_out}")

        # print summary
        tools_tmp = ToolSet(g_nodes, name_index)
        stats = tools_tmp.get_graph_summary()
        typer.echo(
            f"\nGraph summary: {stats['total_nodes']} nodes, {stats['total_edges']} edges\n"
            f"  Entry points : {stats['entry_points']}\n"
            f"  Taint sources: {stats['taint_sources']}\n"
            f"  Taint sinks  : {stats['taint_sinks']}\n"
            f"  Infrastructure: {stats['infrastructure']}\n"
            f"  External refs: {stats['external_nodes']}"
        )

    # ── export ────────────────────────────────────────────────────────────────
    out_dir = Path(output_dir)

    if html:
        html_name = "call_graph_annotated.html" if findings_dicts else "call_graph.html"
        html_out = export_html(
            plain,
            out_dir / html_name,
            findings=findings_dicts or None,
        )
        typer.echo(f"HTML graph → {html_out}")
        typer.echo("  Open in a browser to explore interactively.")

    if dot:
        dot_out = export_dot(
            plain,
            out_dir / "call_graph.dot",
            findings=findings_dicts or None,
        )
        typer.echo(f"DOT  graph → {dot_out}")
        typer.echo("  Render: dot -Tpng call_graph.dot -o call_graph.png")


# ─────────────────────────────────────────────────────────────────────────────
# patch — generate + validate fixes for flagged functions in a completed run
# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def patch(
    results_file: str = typer.Option(
        ..., "--results", "-r", help="Path to a completed analysis run JSON."
    ),
    path: Optional[str] = typer.Option(
        None, "--path", "-p",
        help="Source path override for re-extracting function bodies "
             "(defaults to the run's recorded source_path)."
    ),
    output_dir: str = typer.Option(
        "experiments/results/patches", "--output-dir", "-o",
        help="Directory to write the patches JSON into."
    ),
    config_path: Optional[str] = typer.Option(
        None, "--config", "-c", help="Path to YAML config file."
    ),
    apply: bool = typer.Option(
        False, "--apply",
        help="Write validated patches into the actual source files. "
             "Opt-in only — never the default. Prompts for confirmation."
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y",
        help="Skip the confirmation prompt when using --apply (non-interactive)."
    ),
):
    """
    Generate and validate security patches for the flagged functions in a
    completed analysis run. By default this only writes a reviewable JSON
    artifact (diffs + validity) — the analyzed project is never modified
    unless --apply is explicitly passed.
    """
    rp = Path(results_file)
    if not rp.exists():
        typer.echo(f"Results file not found: {rp}", err=True)
        raise typer.Exit(1)

    with open(rp, encoding="utf-8") as f:
        run_data = json.load(f)

    run_id = run_data.get("run_id", rp.stem)
    source_path = path or run_data.get("source_path")
    findings = [f for f in run_data.get("findings", []) if f.get("vulnerability_found")]

    if not findings:
        typer.echo("No vulnerabilities found in this run — nothing to patch.")
        raise typer.Exit(0)

    if not source_path or source_path == "<snippet>":
        typer.echo(
            "Error: cannot re-extract source for this run "
            "(source_path missing or a snippet run). Pass --path explicitly.",
            err=True,
        )
        raise typer.Exit(1)

    config = load_config(config_path)

    typer.echo(f"\nRe-extracting source from {source_path} to recover function bodies...")
    extractor = CodeExtractor(max_function_lines=config.ingestion.max_function_lines)
    samples = extractor.from_path(source_path)
    sample_index = {(s.function_name, s.file_path): s for s in samples}

    generator = PatchGenerator(api_key=config.openai_api_key, model=config.llm.model)
    validator = PatchValidator()

    patches: list = []
    typer.echo(f"Generating patches for {len(findings)} flagged function(s)...\n")

    for i, finding in enumerate(findings, 1):
        fn_name = finding.get("function_name")
        file_path = finding.get("file_path")
        typer.echo(f"  [{i:>2}/{len(findings)}] {fn_name:<30}", nl=False)

        sample = sample_index.get((fn_name, file_path))
        if sample is None:
            typer.echo(" → SKIP (source not found)")
            patches.append({
                "function_name": fn_name, "file_path": file_path,
                "cwe_id": finding.get("cwe_id"), "severity": finding.get("severity"),
                "start_line": None, "end_line": None,
                "unified_diff": "", "patch_valid": False,
                "patch_error": "source_not_found", "patched_code": None,
            })
            continue

        result = generator.generate(
            code=sample.code,
            explanation=finding.get("explanation", ""),
            cwe_id=finding.get("cwe_id"),
            function_name=fn_name,
            language=sample.language.value,
            patch_suggestion=finding.get("patch_suggestion", ""),
        )

        if result.error:
            typer.echo(f" → GEN-ERROR ({result.error})")
            patches.append({
                "function_name": fn_name, "file_path": file_path,
                "cwe_id": finding.get("cwe_id"), "severity": finding.get("severity"),
                "start_line": sample.start_line, "end_line": sample.end_line,
                "unified_diff": "", "patch_valid": False,
                "patch_error": result.error, "patched_code": None,
            })
            continue

        validation = validator.validate(sample.code, result.unified_diff, sample.language.value)
        status = "VALID" if validation.valid else f"INVALID ({validation.error})"
        typer.echo(f" → {status}")

        patches.append({
            "function_name": fn_name, "file_path": file_path,
            "cwe_id": finding.get("cwe_id"), "severity": finding.get("severity"),
            "start_line": sample.start_line, "end_line": sample.end_line,
            "unified_diff": result.unified_diff,
            "patch_valid": validation.valid,
            "patch_error": validation.error,
            "patched_code": validation.patched_code,
        })

    out_path = save_patches(
        patches=patches,
        run_id=run_id,
        source_path=source_path,
        output_folder=output_dir,
    )

    valid_count = sum(1 for p in patches if p["patch_valid"])
    typer.echo("\n" + "─" * 50)
    typer.echo(f"Total patches : {len(patches)}")
    typer.echo(f"Valid         : {valid_count}")
    typer.echo(f"Invalid       : {len(patches) - valid_count}")
    typer.echo(f"Patches saved → {out_path}")

    if not apply:
        typer.echo("\nSource project untouched. Re-run with --apply to write validated patches to disk.")
        return

    # ── opt-in: write validated patches into the actual source files ─────────
    applicable = [p for p in patches if p["patch_valid"]]
    if not applicable:
        typer.echo("\n--apply requested but no valid patches to write.")
        return

    typer.echo(f"\n--apply requested: this will OVERWRITE {len(applicable)} function(s) in the source project:")
    for p in applicable:
        typer.echo(f"  {p['file_path']}  ::  {p['function_name']}")

    if not yes:
        confirmed = typer.confirm("\nProceed with writing these patches to disk?", default=False)
        if not confirmed:
            typer.echo("Aborted — no files were modified.")
            raise typer.Exit(0)

    written = 0
    for p in applicable:
        try:
            _write_patch_to_file(p)
            written += 1
        except Exception as e:
            typer.echo(f"  Failed to apply to {p['file_path']}::{p['function_name']}: {e}", err=True)

    typer.echo(f"\n{written}/{len(applicable)} patch(es) written to disk.")


def _write_patch_to_file(patch_record: dict) -> None:
    """Replaces a function's line range in its source file with validated patched code."""
    file_path = Path(patch_record["file_path"])
    start_line = patch_record["start_line"]
    end_line = patch_record["end_line"]

    original = file_path.read_text(encoding="utf-8")
    lines = original.splitlines(keepends=True)
    patched_lines = patch_record["patched_code"].splitlines(keepends=True)

    lines[start_line - 1:end_line] = patched_lines
    file_path.write_text("".join(lines), encoding="utf-8")


if __name__ == "__main__":
    app()