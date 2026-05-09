"""
CLI entry point.

Commands:
  analyze   Run vulnerability analysis on a path or snippet
  show      Pretty-print a saved results JSON file
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Optional

import typer

from src.config import load_config
from src.ingestion.extractor import CodeExtractor
from src.llm.client import LLMClient
from src.results import save_run

app = typer.Typer(add_completion=False, pretty_exceptions_show_locals=False)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── analyze ───────────────────────────────────────────────────────────────────

@app.command()
def analyze(
    path: Optional[str] = typer.Option(
        None, "--path", "-p",
        help="File or directory to analyse."
    ),
    snippet: Optional[str] = typer.Option(
        None, "--snippet", "-s",
        help="Inline code string. Requires --language."
    ),
    language: Optional[str] = typer.Option(
        None, "--language", "-l",
        help="Language for --snippet (python, javascript, c, cpp)."
    ),
    config_path: Optional[str] = typer.Option(
        None, "--config", "-c",
        help="Path to YAML config file."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="Extract and report stats without calling the LLM."
    ),
):
    """
    Analyse source code for security vulnerabilities.
    """
    if path is None and snippet is None:
        typer.echo("Error: provide --path or --snippet", err=True)
        raise typer.Exit(1)

    config = load_config(config_path)
    extractor = CodeExtractor(
        max_function_lines=config.ingestion.max_function_lines
    )

    # ── extract ───────────────────────────────────────────────────────────────
    if path:
        typer.echo(f"\nIngesting  {path}")
        samples = extractor.from_path(path)
        source_label = path
    else:
        if not language:
            typer.echo("Error: --language is required with --snippet", err=True)
            raise typer.Exit(1)
        samples = extractor.from_snippet(snippet, language)
        source_label = "<snippet>"

    if not samples:
        typer.echo("No functions extracted. Check the path and language support.")
        raise typer.Exit(1)

    # ── dry-run report ────────────────────────────────────────────────────────
    lang_counts: dict[str, int] = {}
    for s in samples:
        lang_counts[s.language.value] = lang_counts.get(s.language.value, 0) + 1

    typer.echo(f"\nExtraction summary")
    typer.echo(f"  Functions : {len(samples)}")
    for lang, count in sorted(lang_counts.items()):
        typer.echo(f"  {lang:<12}: {count}")

    if dry_run:
        typer.echo("\nDry run — no LLM calls made.")
        raise typer.Exit(0)

    # ── analyse ───────────────────────────────────────────────────────────────
    typer.echo(f"\nAnalysing {len(samples)} function(s) with {config.llm.model}…\n")
    client = LLMClient(config.llm)
    reports = []

    for i, sample in enumerate(samples, 1):
        label = f"{sample.function_name or '?'} ({sample.language.value})"
        typer.echo(f"  [{i:>3}/{len(samples)}]  {label}", nl=False)
        report = client.analyze(sample)
        reports.append(report)

        status = "VULN" if report.vulnerability_found else "clean"
        conf   = f"{report.confidence:.2f}"
        typer.echo(f"  →  {status}  conf={conf}")

    # ── save results ──────────────────────────────────────────────────────────
    out_path = save_run(
        reports=reports,
        samples=samples,
        source_path=source_label,
        model=config.llm.model,
        results_folder=config.output.results_folder,
    )

    # ── print summary ─────────────────────────────────────────────────────────
    found = [r for r in reports if r.vulnerability_found]
    typer.echo(f"\n{'─'*50}")
    typer.echo(f"  Total analysed : {len(reports)}")
    typer.echo(f"  Vulnerabilities: {len(found)}")
    typer.echo(f"  Clean          : {len(reports) - len(found)}")
    typer.echo(f"  Results saved  → {out_path}")

    if found:
        typer.echo(f"\nFindings:")
        for r in found:
            sev = r.severity or "?"
            cwe = r.cwe_id or "unknown CWE"
            typer.echo(f"  [{sev.upper():>8}]  {r.function_name}  ({cwe})")
            typer.echo(f"             {r.file_path}")
            typer.echo(f"             {r.explanation[:120]}…" if len(r.explanation) > 120 else f"             {r.explanation}")


# ── show ──────────────────────────────────────────────────────────────────────

@app.command()
def show(
    result_file: str = typer.Argument(..., help="Path to a results JSON file."),
    only_vulns: bool = typer.Option(
        False, "--vulns-only", help="Only show vulnerable findings."
    ),
):
    """
    Pretty-print a saved results JSON file.
    """
    p = Path(result_file)
    if not p.exists():
        typer.echo(f"File not found: {p}", err=True)
        raise typer.Exit(1)

    with open(p) as f:
        data = json.load(f)

    typer.echo(f"\nRun:     {data.get('run_id')}")
    typer.echo(f"Model:   {data.get('model')}")
    typer.echo(f"Source:  {data.get('source_path')}")
    typer.echo(f"Time:    {data.get('timestamp')}")

    summary = data.get("summary", {})
    typer.echo(f"\nSummary")
    typer.echo(f"  Total     : {summary.get('total_functions')}")
    typer.echo(f"  Vulnerable: {summary.get('vulnerabilities_found')}")
    typer.echo(f"  Clean     : {summary.get('clean')}")
    typer.echo(f"  Errors    : {summary.get('errors')}")

    findings = data.get("findings", [])
    if only_vulns:
        findings = [f for f in findings if f.get("vulnerability_found")]

    typer.echo(f"\nFindings ({len(findings)}):")
    for f in findings:
        marker = "VULN " if f.get("vulnerability_found") else "clean"
        typer.echo(
            f"  [{marker}]  {f.get('function_name')}  "
            f"cwe={f.get('cwe_id')}  conf={f.get('confidence', 0):.2f}  "
            f"sev={f.get('severity')}"
        )
        if f.get("explanation"):
            typer.echo(f"           {f['explanation'][:100]}")


if __name__ == "__main__":
    app()