"""
CLI entry point.

Commands:
  analyze    Run vulnerability analysis on a path or snippet
  show       Pretty-print a saved results JSON file
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import typer

from src.config import load_config
from src.context.call_graph import CallGraphBuilder
from src.ingestion.extractor import CodeExtractor
from src.results import save_extraction_results, save_run, save_call_graph
from src.llm.client import LLMClient
from src.agent.react_loop import ReActAgent
from src.agent.tools import ToolSet

app = typer.Typer(
    add_completion=False,
    pretty_exceptions_show_locals=False,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# analyze
# ─────────────────────────────────────────────────────────────

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
        False, "--dry-run", help="Extract and report stats without calling the LLM."
    ),
    build_context: bool = typer.Option(
        False, "--build-context", help="Build call graph context before analysis."
    ),
):
    """Analyse source code for security vulnerabilities."""

    if path is None and snippet is None:
        typer.echo("Error: provide --path or --snippet", err=True)
        raise typer.Exit(1)

    config = load_config(config_path)
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

    # ── extraction summary ────────────────────────────────────────────────────
    lang_counts: dict = {}
    for s in samples:
        lang_counts[s.language.value] = lang_counts.get(s.language.value, 0) + 1

    typer.echo("\nExtraction summary")
    typer.echo(f"  Functions : {len(samples)}")
    for lang, count in sorted(lang_counts.items()):
        typer.echo(f"  {lang:<12}: {count}")

    # ── save extraction ───────────────────────────────────────────────────────
    extraction_out = save_extraction_results(
        samples=samples,
        source_path=source_label,
        output_folder=config.output.extraction_folder,
    )
    typer.echo(f"\nExtraction saved → {extraction_out}")

    # ── call graph ────────────────────────────────────────────────────────────
    graph: dict = {}
    name_index: dict = {}
    tools: Optional[ToolSet] = None

    if build_context:
        typer.echo("\nBuilding call graph...")
        builder = CallGraphBuilder(api_key=config.openai_api_key)
        graph, name_index = builder.build(samples)

        context_out = save_call_graph(
            graph=graph,
            output_folder=config.output.context_folder,
            source_path=source_label,
        )
        typer.echo(f"Call graph built successfully ({len(graph)} nodes)")
        typer.echo(f"Call graph saved → {context_out}")

        tools = ToolSet(graph, name_index)

    # ── dry run ───────────────────────────────────────────────────────────────
    if dry_run:
        typer.echo("\nDry run complete — no LLM calls made.")
        raise typer.Exit(0)

    # ── LLM setup ─────────────────────────────────────────────────────────────
    typer.echo(f"\nAnalyzing with {config.llm.model}...")
    if build_context:
        typer.echo("  Mode: call-graph-aware (callers + callees injected into each prompt)\n")
    else:
        typer.echo("  Mode: single-function (no call graph context)\n")

    client = LLMClient(config.llm)
    agent = ReActAgent(llm=client, tools=tools)

    reports = []

    # ── analysis loop ─────────────────────────────────────────────────────────
    for i, sample in enumerate(samples, 1):
        typer.echo(f"  [{i}/{len(samples)}] {sample.function_name}", nl=False)

        try:
            if build_context and tools is not None:
                # Pass all_samples so the agent can embed caller/callee source code
                report = agent.run(sample, graph, all_samples=samples)
            else:
                report = client.analyze(sample)

            reports.append(report)

            status = "VULN" if report.vulnerability_found else "clean"
            sev = f" [{report.severity}]" if report.vulnerability_found and report.severity else ""
            typer.echo(f" → {status}{sev} (conf: {report.confidence:.2f})")

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
    )

    # ── summary ───────────────────────────────────────────────────────────────
    found = [r for r in reports if r.vulnerability_found]

    typer.echo("\n" + "─" * 50)
    typer.echo(f"Total analysed : {len(reports)}")
    typer.echo(f"Vulnerabilities: {len(found)}")
    typer.echo(f"Clean          : {len(reports) - len(found)}")
    typer.echo(f"Results saved  → {out_path}")

    if found:
        typer.echo("\nFindings:")
        for r in found:
            sev = r.severity or "?"
            cwe = r.cwe_id or "unknown CWE"
            typer.echo(f"  [{sev.upper():>8}] {r.function_name} ({cwe})")
            if r.file_path:
                typer.echo(f"             {r.file_path}")
            if r.explanation:
                typer.echo(f"             {r.explanation[:120]}")


# ─────────────────────────────────────────────────────────────
# show
# ─────────────────────────────────────────────────────────────

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
        typer.echo(
            f"  [{marker}] {f.get('function_name')} "
            f"cwe={f.get('cwe_id')} "
            f"conf={f.get('confidence', 0):.2f} "
            f"sev={f.get('severity')}"
        )
        if f.get("explanation"):
            typer.echo(f"       {f['explanation'][:120]}")


if __name__ == "__main__":
    app()