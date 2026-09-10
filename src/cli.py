"""
CLI entry point.

Commands:
  analyze    Run vulnerability analysis on a path or snippet
  show       Pretty-print a saved results JSON file
  graph      Build and/or visualize a call graph
  patch      Generate + validate fixes for flagged functions in a completed run
  evaluate   Score one or more analysis runs against a ground truth dataset
  cost       Show LLM spend from the persistent cost ledger (all-time or per-run)
  ui         Serve the web UI: pick a folder, analyse it, read the results
  bootstrap-ground-truth
             Scaffold a ground_truth.json covering every function in a repository

Key flags:
  --react           Use ReAct agent loop (reason->act->observe) instead of single-pass
  --dry-run         Extract + build graph only, no LLM calls
  --api-key-alias   Select a named API key (OPENAI_API_KEY_<ALIAS>) for setups with
                    more than one key for the same provider; on analyze/graph/patch
  patch --apply     Opt-in: write validated patches into the actual source files
                    (default `patch` behavior only saves a reviewable JSON artifact)

Every real LLM call (edge resolution, analysis, patch generation) is recorded to a
persistent SQLite ledger (experiments/cost_ledger.db) in addition to each run's own
JSON — run `cost` for cross-run/cross-phase/cross-key totals.

Analysis always builds the call graph and injects context into the prompt.
Use --react to switch from single-pass semantic to the agentic ReAct loop.
"""
from __future__ import annotations

import json
import sys

# Force UTF-8 on our own streams before anything prints. The default Windows
# console codepage is cp1252, which cannot encode the '→' this CLI writes in
# nearly every progress line — and an encoding crash mid-run used to abandon a
# paid analysis after the API calls had already been billed. errors="replace"
# is the belt-and-braces: no console can ever kill a run over a glyph.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass  # not a reconfigurable text stream (pytest capture, a pipe, ...)

# Windows: make a CTRL_BREAK from a parent process behave like Ctrl-C.
#
# The web UI's job runner cancels a run by sending CTRL_BREAK_EVENT — with
# CREATE_NEW_PROCESS_GROUP, Windows disables CTRL_C_EVENT for the child, so
# CTRL_BREAK is the only signal that can reach it. But Python's default SIGBREAK
# handler terminates the process outright (exit 0xC000013A), which would skip
# the KeyboardInterrupt path in `analyze` that saves the partial run — throwing
# away every function already analysed and paid for. Mapping it to
# KeyboardInterrupt is what makes "cancel keeps your results" true.
import os as _os

if _os.name == "nt":
    import signal as _signal

    def _raise_keyboard_interrupt(_signum, _frame):
        raise KeyboardInterrupt

    try:
        _signal.signal(_signal.SIGBREAK, _raise_keyboard_interrupt)
    except (AttributeError, ValueError):
        pass  # no SIGBREAK, or not on the main thread

# Load .env automatically so users don't have to export env vars manually
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv optional — fall back to manually set env vars
import logging
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

import typer

from src.config import load_config
from src.context.call_graph import CallGraphBuilder
from src.ingestion.extractor import CodeExtractor
from src.results import save_extraction_results, save_run, save_call_graph, save_patches, make_run_id
from src.results.checkpoint import CheckpointHeader, CheckpointMismatch, RunCheckpoint
from src.results.patch_generator import PatchGenerator
from src.results.patch_validator import PatchValidator
from src.results.export_graph import export_dot, export_html, select_subgraph
from src.results.save_graph import load_call_graph
from src.context.call_graph import nodes_to_dict
from src.context.route_context import format_chunk_note, format_route_block
from src.llm.attribution import ATTRIBUTION_PROMPT
from src.llm.client import LLMClient
from src.llm.cost_ledger import CostLedger
from src.llm.evidence_gate import EVIDENCE_GATE_PROMPT
from src.llm.taxonomy import CWE_TAXONOMY_PROMPT, FEATURE_FLAG_RULE, SEVERITY_RULES_PROMPT
from src.llm.pricing import TokenUsage, estimate_cost
from src.agent.flow_groups import build_flow_groups
from src.agent.flow_pass import run_flow_pass
from src.agent.react_loop import ReActAgent, MAX_STEPS
from src.agent.tools import ToolSet
from src.models import CodeSample
from src.evaluation import evaluate_run, save_evaluation_report, save_comparison_report, comparison_table, load_ground_truth
from src.evaluation.bootstrap import build_ground_truth, save_ground_truth_skeleton

app = typer.Typer(add_completion=False, pretty_exceptions_show_locals=False)


def _infer_dataset_from_path(file_path: Path) -> Optional[str]:
    """
    Recovers the dataset name from a results file living under
    experiments/datasets/<dataset>/runs/<run_name>/..., so patch/evaluate
    outputs default to the same dataset folder without an extra flag.
    """
    parts = file_path.resolve().parts
    for i, part in enumerate(parts):
        if part == "datasets" and i + 1 < len(parts):
            return parts[i + 1]
    return None

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
    resume: bool = typer.Option(
        False, "--resume",
        help="Continue an interrupted run from its checkpoint, re-analysing only the "
             "functions it never reached. Requires the same --run-name (that is where "
             "the checkpoint lives), source, model and mode as the run being resumed."
    ),
    budget_usd: Optional[float] = typer.Option(
        None, "--budget-usd",
        help="Stop starting new function analyses once this run's spend reaches this "
             "many dollars, then save what completed. The ceiling is checked between "
             "functions, so the final total can exceed it by at most one function's cost."
    ),
    run_name: Optional[str] = typer.Option(
        None, "--run-name", "-n",
        help="Named experiment run. Outputs go to experiments/datasets/<dataset>/runs/<name>/ "
             "(or experiments/runs/<name>/ if --dataset is omitted) with fixed filenames."
    ),
    dataset: Optional[str] = typer.Option(
        None, "--dataset", "-d",
        help="Test dataset this run belongs to (e.g. nodegoat, auth-service) — matches "
             "experiments/datasets/<dataset>/ground_truth.json. Only used together with --run-name."
    ),
    output_dir: Optional[str] = typer.Option(
        None, "--output-dir", "-o",
        help="Write every artifact of this run (extraction.json, call_graph.json, "
             "analysis.json, checkpoint.jsonl, graph HTML/DOT) into this directory. "
             "Takes precedence over --run-name/--dataset."
    ),
    chunk_oversized: Optional[bool] = typer.Option(
        None, "--chunk-oversized/--no-chunk-oversized",
        help="Whether a function longer than max_function_lines is analysed as a "
             "series of chunks or dropped entirely. Omit to use the config file's "
             "setting. Dropping is what a ground truth built before chunking "
             "assumed, so --no-chunk-oversized is how a run is made comparable "
             "to one."
    ),
    flow_pass: bool = typer.Option(
        False, "--flow-pass",
        help="After the per-function pass, run a second pass over GROUPS of related "
             "functions (producer/consumer pairs, route clusters, model writers) "
             "looking for defects that only exist between functions — a value one "
             "mints and another trusts, a check each assumes the other performs. "
             "Costs roughly $1-2 more per run."
    ),
    flow_max_groups: Optional[int] = typer.Option(
        None, "--flow-max-groups",
        help="Cap how many workflow groups the flow pass analyses. Omit for all."
    ),
    api_key_alias: Optional[str] = typer.Option(
        None, "--api-key-alias",
        help="Which API key to use, for setups with more than one key for the same "
             "provider (e.g. separate billing budgets). Reads OPENAI_API_KEY_<ALIAS> "
             "(uppercased). Omit to use the default OPENAI_API_KEY. Cost is attributed "
             "to this alias in the cost ledger regardless."
    ),
):
    """Analyse source code for security vulnerabilities."""

    if path is None and snippet is None:
        typer.echo("Error: provide --path or --snippet", err=True)
        raise typer.Exit(1)

    config = load_config(config_path)
    # A flag beats the file, and omitting the flag leaves the file alone: the
    # config stays the default for everyone who does not ask, and the run that
    # does ask records the asking in its own argv.
    if chunk_oversized is not None:
        config.ingestion.chunk_oversized = chunk_oversized
    resolved_key, key_alias = config.resolve_api_key(api_key_alias)
    ledger = CostLedger()
    run_id = make_run_id(config.llm.model)

    # ── where this run's artifacts go ─────────────────────────────────────────
    # --output-dir writes anywhere the caller wants; --run-name keeps the
    # dataset-scoped layout the thesis experiments use. Either way every
    # artifact lands in one directory under fixed names, so a run folder is
    # self-describing regardless of how it was produced.
    run_dir = None
    if output_dir:
        run_dir = output_dir
    elif run_name:
        run_dir = (
            f"experiments/datasets/{dataset}/runs/{run_name}"
            if dataset else f"experiments/runs/{run_name}"
        )

    if run_dir:
        Path(run_dir).mkdir(parents=True, exist_ok=True)
        config.output.extraction_folder = run_dir
        config.output.context_folder    = run_dir
        config.output.analysis_folder   = run_dir

    extractor = CodeExtractor(
        max_function_lines=config.ingestion.max_function_lines,
        skip_dirs=config.ingestion.skip_dirs,
        chunk_oversized=config.ingestion.chunk_oversized,
    )

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

    skipped = extractor.skipped_functions

    typer.echo("\nExtraction summary")
    whole = [s for s in samples if not s.chunk_of]
    chunk_samples = [s for s in samples if s.chunk_of]
    typer.echo(f"  Functions : {len(whole)}")
    for lang, count in sorted(lang_counts.items()):
        typer.echo(f"  {lang:<12}: {count}")
    if chunk_samples:
        typer.echo(
            f"  Chunks    : {len(chunk_samples)} slice(s) of oversized function(s), "
            "analysed separately"
        )
    if skipped:
        chunked = [sk for sk in skipped if sk.chunked]
        uncovered = [sk for sk in skipped if not sk.chunked]
        covered = (len(whole) + len(chunked)) / (len(whole) + len(skipped))
        typer.echo(
            f"  Oversized : {len(skipped)} function(s) over "
            f"{config.ingestion.max_function_lines} lines — "
            f"{len(chunked)} analysed as chunks, {len(uncovered)} NOT analysed "
            f"({covered:.1%} coverage)"
        )
        for sk in skipped[:5]:
            how = f"→ {sk.chunk_count} chunks" if sk.chunked else "→ not analysed"
            typer.echo(f"    {sk.name} ({sk.line_count} lines) {how}  {sk.file_path}")
        if len(skipped) > 5:
            typer.echo(f"    ... and {len(skipped) - 5} more (see extraction JSON)")

    extraction_out = save_extraction_results(
        samples=samples,
        source_path=source_label,
        output_folder=config.output.extraction_folder,
        filename="extraction.json" if run_dir else None,
        skipped=skipped,
    )
    typer.echo(f"\nExtraction saved → {extraction_out}")

    # ── call graph ────────────────────────────────────────────────────────────
    graph: dict = {}
    name_index: dict = {}
    tools: Optional[ToolSet] = None

    typer.echo("\nBuilding call graph...")
    if dry_run:
        typer.echo("  (dry run: edge resolution is cache-only — no LLM calls, no spend)")
    builder = CallGraphBuilder(
        api_key=resolved_key, model=config.llm.model,
        api_key_alias=key_alias, cost_ledger=ledger, run_id=run_id, dataset=dataset,
        offline_edges=dry_run,
        # The ceiling covers the whole run, this phase included. Without it here
        # --budget-usd bounds nothing until the analysis loop is reached, which
        # on a large codebase can be hours or days of paid calls away.
        budget_usd=budget_usd,
    )
    graph, name_index = builder.build(samples, routes=extractor.all_routes)

    context_out = save_call_graph(
        graph=graph,
        output_folder=config.output.context_folder,
        source_path=source_label,
        filename="call_graph.json" if run_dir else None,
    )
    typer.echo(f"Call graph built successfully ({len(graph)} nodes)")
    typer.echo(f"Call graph saved → {context_out}")

    edge_usage = builder.get_edge_resolution_usage()
    edge_cost = estimate_cost(config.llm.model, edge_usage) if edge_usage else None
    if edge_usage and edge_usage.total_tokens:
        cost_label = f"${edge_cost:.4f}" if edge_cost is not None else "unknown (model not in pricing table)"
        typer.echo(f"Edge resolution   : {edge_usage.total_tokens} tokens, {cost_label}")

    if budget_usd is not None and not builder.budget_enforceable:
        typer.echo(
            f"\n  --budget-usd cannot be enforced during edge resolution: {config.llm.model} "
            "is not in the pricing table, so spend is unknown. Continuing without a ceiling "
            "on this phase — treating unknown cost as $0 would be worse.\n"
        )

    if builder.budget_exhausted:
        # Said here and not left to the analysis loop: the loop reports a budget
        # stop after N functions, which reads as "the analysis ran out of money"
        # when in fact it never started. The graph is already saved above, and
        # every edge bought is in the edge cache, so nothing paid for is lost.
        spent = f"${edge_cost:.4f}" if edge_cost is not None else "the ceiling"
        typer.echo(
            f"\n!! Budget ceiling reached while building the call graph — {spent} of "
            f"${budget_usd:.4f} spent before analysis began.\n"
            f"   {builder.budget_skipped} edge(s) left unresolved; the graph above is "
            "incomplete and no functions will be analysed.\n"
            "   Re-run with a higher --budget-usd. Edges already resolved are cached and "
            "cost nothing the second time, so the next run starts where this one stopped."
        )

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
        misses = builder.get_offline_misses()
        if misses:
            typer.echo(
                f"\n{misses} ambiguous edge(s) left unresolved — resolving them needs the "
                "LLM, which a dry run does not call. The real run will resolve them "
                "(and pay for the ones not already cached)."
            )
        typer.echo("\nDry run complete — no LLM calls made.")
        raise typer.Exit(0)

    # ── LLM + agent setup ─────────────────────────────────────────────────────
    client = LLMClient(
        config.llm, api_key=resolved_key, api_key_alias=key_alias,
        cost_ledger=ledger, run_id=run_id, dataset=dataset,
    )
    agent = ReActAgent(llm=client, tools=tools, max_steps=config.agent.max_steps)

    if react:
        mode_label = f"ReAct loop — reason→act→observe (max {config.agent.max_steps} tool calls per function)"
    else:
        mode_label = "single-pass with call graph context injected into prompt"

    typer.echo(f"\nAnalyzing {len(samples)} functions with {config.llm.model}")
    typer.echo(f"  Mode: {mode_label}\n")

    # ── checkpoint ────────────────────────────────────────────────────────────
    # Written after every function so an interrupted run can be resumed instead
    # of re-paying for work already done.
    checkpoint = RunCheckpoint(config.output.analysis_folder)
    ck_header = CheckpointHeader(
        model=config.llm.model,
        source_path=source_label,
        analysis_mode="react_loop" if react else "call_graph_context",
        total_samples=len(samples),
    )
    completed: Dict[int, object] = {}

    if resume:
        if checkpoint.exists:
            try:
                completed = checkpoint.load_completed(ck_header, samples=samples)
            except CheckpointMismatch as e:
                typer.echo(f"\nCannot resume: {e}", err=True)
                raise typer.Exit(1)
            typer.echo(
                f"\nResuming from {checkpoint.path}: {len(completed)} function(s) already "
                f"analysed, {len(samples) - len(completed)} to go."
            )
        else:
            typer.echo(
                f"\n--resume passed but no checkpoint at {checkpoint.path} — starting from scratch."
            )
    elif checkpoint.exists:
        typer.echo(
            f"\nDiscarding an existing checkpoint at {checkpoint.path} "
            "(pass --resume to continue that run instead of starting over)."
        )
        checkpoint.clear()

    checkpoint.start(ck_header)

    # Spend already on this run's clock: resumed analysis + the edge resolution
    # paid for above. Both count against --budget-usd, otherwise a resumed run
    # would get a fresh budget every time it restarted.
    def _spend_so_far() -> Optional[float]:
        usage = TokenUsage()
        for r in completed.values():
            usage = usage + (r.token_usage or TokenUsage())
        analysed = estimate_cost(config.llm.model, usage)
        if analysed is None:
            return None
        return analysed + (edge_cost or 0.0)

    budget_enforceable = True
    stopped_early: Optional[str] = None

    # ── analysis loop ─────────────────────────────────────────────────────────
    try:
        for i, sample in enumerate(samples, 1):
            idx = i - 1
            if idx in completed:
                continue

            if budget_usd is not None and budget_enforceable:
                spend = _spend_so_far()
                if spend is None:
                    budget_enforceable = False
                    typer.echo(
                        f"\n  --budget-usd cannot be enforced: {config.llm.model} is not in the "
                        "pricing table, so spend is unknown. Continuing without a ceiling — "
                        "treating unknown cost as $0 would be worse.\n"
                    )
                elif spend >= budget_usd:
                    # Both figures at the same precision — a ceiling of $0.001
                    # rendered as "$0.00" reads like a bug in the ceiling.
                    stopped_early = (
                        f"budget ceiling reached — ${spend:.4f} of ${budget_usd:.4f} spent "
                        f"after {len(completed)} function(s)"
                    )
                    break

            typer.echo(f"  [{i:>2}/{len(samples)}] {sample.function_name:<30}", nl=False)

            try:
                if react and tools is not None:
                    report = agent.run(sample, graph, all_samples=samples)
                else:
                    hop = tools.trace_one_hop(sample.function_name, sample.file_path)
                    prompt = _build_context_prompt(sample, hop, tools, samples)
                    report = client.analyze(sample, context_prompt=prompt)
                    report.analysis_mode = "call_graph_context"

                completed[idx] = report
                checkpoint.append(idx, report)

                status = "VULN" if report.vulnerability_found else "clean"
                sev = f" [{report.severity}]" if report.vulnerability_found and report.severity else ""
                err = f" ERR:{report.error}" if report.error else ""
                typer.echo(f" → {status}{sev} (conf:{report.confidence:.2f}){err}")

            except Exception as e:
                typer.echo(" → ERROR")
                logger.error("Analysis failed for %s: %s", sample.function_name, e)

    except KeyboardInterrupt:
        # The LLM calls behind these results are already paid for — save them
        # rather than letting Ctrl-C throw the run away.
        stopped_early = f"interrupted by user after {len(completed)} function(s)"

    # Findings must be ordered by function, not by completion: a resumed run
    # fills in the gaps out of order.
    reports = [completed[k] for k in sorted(completed)]

    # ── flow pass ─────────────────────────────────────────────────────────────
    # A second pass over GROUPS of functions. The per-function pass cannot see a
    # defect whose two halves are individually defensible — juice-shop's
    # generateCoupon/discountFromCoupon pair was examined function by function
    # and both were correctly called clean.
    flow_meta = None
    if flow_pass and not stopped_early:
        groups = build_flow_groups(samples, graph, max_groups=flow_max_groups)
        if not groups:
            typer.echo("\nFlow pass: no workflow groups found — skipping.")
        else:
            typer.echo(f"\nFlow pass: {len(groups)} workflow group(s)\n")

            def _progress(i, total, group):
                typer.echo(f"  [{i:>2}/{total}] {group.kind:<18} {group.label[:52]}")

            flow_reports = run_flow_pass(client, groups, samples, progress=_progress)
            flow_usage = TokenUsage()
            for r in flow_reports:
                flow_usage = flow_usage + (r.token_usage or TokenUsage())
            flow_cost = estimate_cost(config.llm.model, flow_usage)

            typer.echo(
                f"\n  {len(flow_reports)} cross-function finding(s)"
                + (f", ${flow_cost:.4f}" if flow_cost is not None else "")
            )
            reports = reports + flow_reports
            flow_meta = {
                "flow_pass_groups": len(groups),
                "flow_pass_findings": len(flow_reports),
                "flow_pass_cost_usd": round(flow_cost, 6) if flow_cost is not None else None,
                "flow_pass_group_kinds": dict(Counter(g.kind for g in groups)),
            }

    # ── save results ──────────────────────────────────────────────────────────
    edge_meta = None
    if edge_usage and edge_usage.total_tokens:
        edge_meta = {
            "edge_resolution_prompt_tokens": edge_usage.prompt_tokens,
            "edge_resolution_completion_tokens": edge_usage.completion_tokens,
            "edge_resolution_cost_usd": round(edge_cost, 6) if edge_cost is not None else None,
        }

    if stopped_early:
        # Recorded in the run itself: a partial run scored as though it were
        # complete would read as catastrophic recall rather than an unfinished
        # run, and nothing else in analysis.json would reveal the difference.
        edge_meta = dict(edge_meta or {})
        edge_meta["partial_run"] = True
        edge_meta["partial_reason"] = stopped_early
        edge_meta["functions_analysed"] = len(reports)
        edge_meta["functions_total"] = len(samples)

    if flow_meta:
        edge_meta = dict(edge_meta or {})
        edge_meta.update(flow_meta)

    out_path = save_run(
        reports=reports,
        samples=samples,
        source_path=source_label,
        model=config.llm.model,
        results_folder=config.output.analysis_folder,
        filename="analysis.json" if run_dir else None,
        extra_meta=edge_meta,
        run_id=run_id,
    )

    if stopped_early:
        # Keep the checkpoint — it is what --resume reads.
        pass
    else:
        checkpoint.clear()

    # ── summary ───────────────────────────────────────────────────────────────
    found = [r for r in reports if r.vulnerability_found]
    errors = [r for r in reports if r.error]

    analysis_usage = TokenUsage()
    for r in reports:
        analysis_usage = analysis_usage + (r.token_usage or TokenUsage())
    analysis_cost = estimate_cost(config.llm.model, analysis_usage)
    cost_label = f"${analysis_cost:.4f}" if analysis_cost is not None else "unknown (model not in pricing table)"

    typer.echo("\n" + "─" * 50)
    if stopped_early:
        typer.echo(f"PARTIAL RUN — {stopped_early}.")
        typer.echo(
            f"  {len(reports)} of {len(samples)} function(s) analysed and saved. Resume with:\n"
            f"    python -m src.cli analyze --resume "
            + (f'--output-dir "{output_dir}" ' if output_dir else "")
            + (f"--run-name {run_name} " if run_name and not output_dir else "")
            + (f"--dataset {dataset} " if dataset and not output_dir else "")
            + "... (same --path/--config/mode flags as this run)"
        )
        typer.echo(
            "  Do NOT evaluate this run as if it were complete — every function it never "
            "reached scores as a miss.\n"
        )
    typer.echo(f"Total analysed : {len(reports)}")
    typer.echo(f"Vulnerabilities: {len(found)}")
    typer.echo(f"Clean          : {len(reports) - len(found) - len(errors)}")
    typer.echo(f"Errors         : {len(errors)}")
    typer.echo(f"Tokens used    : {analysis_usage.total_tokens} (prompt {analysis_usage.prompt_tokens} / completion {analysis_usage.completion_tokens})")
    typer.echo(f"Estimated cost : {cost_label}")
    typer.echo(f"Results saved  → {out_path}")

    phase_rows = ledger.by_phase(run_id=run_id)
    if phase_rows:
        typer.echo(f"\nCost by phase (run {run_id}):")
        for row in phase_rows:
            row_cost = f"${row.cost_usd:.4f}" if row.cost_usd is not None else "unknown"
            typer.echo(f"  {row.group_key:<20} {row.calls:>3} call(s)  {row.total_tokens:>7} tokens  {row_cost}")
    typer.echo(f"(Run 'python -m src.cli cost' for totals across every run.)")

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
        "  - A comment of the exact form `/* --- nested method 'X' analyzed separately --- */`\n"
        "    in place of a method body is expected and NOT obfuscated/suspicious code — X is a\n"
        "    nested method (e.g. a constructor's `this.foo = function() {...}`) analyzed\n"
        "    independently elsewhere. Do not flag the function containing this comment because of it.\n"
        "  - Middleware shown in ROUTE CONTEXT as running BEFORE the target has already run,\n"
        "    including anything it overwrites on the request object. A check performed by a\n"
        "    guard is not missing from the target. 'No route registration found' means\n"
        "    unknown, NOT unguarded.\n"
        + FEATURE_FLAG_RULE
    )
    lines.append("=" * 60)
    lines.append(f"TARGET FUNCTION: {sample.function_name}")
    lines.append(f"File: {sample.file_path}  Lines: {sample.start_line}–{sample.end_line}")
    lines.append("=" * 60)
    lines.append(f"```{lang}\n{sample.code}\n```\n")

    chunk_note = format_chunk_note(sample)
    if chunk_note:
        lines.append(chunk_note)
        lines.append("")

    # Same block the ReAct path renders, so the two modes see identical context
    # and a difference between them still means something about the modes.
    lines.append(
        format_route_block(
            tools.get_route_context(sample.function_name, sample.file_path),
            sample.function_name,
        )
    )
    lines.append("")

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
        # Shared with the ReAct prompt rather than restated. These two lists had
        # already drifted apart — the ReAct prompt named 18 CWEs and this one 7 —
        # so the modes were being compared as though they differed only in tool
        # access, when one of them could not name most of the classes.
        "\n" + CWE_TAXONOMY_PROMPT +
        "\n" + EVIDENCE_GATE_PROMPT +
        "\n" + ATTRIBUTION_PROMPT +
        "\n" + SEVERITY_RULES_PROMPT +
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
        '  "hallucination_flag": boolean,\n'
        '  "attributed_to": "<file>::<function>" where the defective code lives,\n'
        '                   or null when that is the target itself,\n'
        '  "also_implicates": [at most 3 node_ids unsafe as a consequence]\n'
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
    only_findings: bool = typer.Option(
        False, "--only-findings",
        help="Draw only flagged functions and their neighbours instead of the whole "
             "graph. Requires --results. On a few-hundred-function repo this is the "
             "difference between a readable figure and a hairball."
    ),
    focus: Optional[str] = typer.Option(
        None, "--focus",
        help="Draw only this function and its neighbours. Accepts a bare function "
             "name or 'path/to/file.ts::functionName'."
    ),
    hops: int = typer.Option(
        1, "--hops",
        help="How far to expand around --focus/--only-findings seeds, following "
             "callers and callees. 0 = seeds only."
    ),
    hide_isolated: bool = typer.Option(
        False, "--hide-isolated",
        help="Drop nodes left with no edges — usually noise in a call graph view."
    ),
    labels: str = typer.Option(
        "auto", "--labels",
        help="Permanent node labels: auto (all when small, only findings/entry "
             "points/hubs when large) | all | important | none. Hidden labels are "
             "still shown on hover."
    ),
    config_path: Optional[str] = typer.Option(
        None, "--config", "-c", help="Path to YAML config file."
    ),
    api_key_alias: Optional[str] = typer.Option(
        None, "--api-key-alias",
        help="Which API key to use for edge resolution (see 'analyze --help'). "
             "Omit to use the default OPENAI_API_KEY."
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
        extractor = CodeExtractor(
            max_function_lines=config.ingestion.max_function_lines,
            skip_dirs=config.ingestion.skip_dirs,
            chunk_oversized=config.ingestion.chunk_oversized,
        )
        typer.echo(f"\nIngesting {path} ...")
        samples = extractor.from_path(path)
        if not samples:
            typer.echo("No functions extracted.")
            raise typer.Exit(1)
        typer.echo(f"  {len(samples)} functions extracted")

        typer.echo("Building call graph ...")
        resolved_key, key_alias = config.resolve_api_key(api_key_alias)
        ledger = CostLedger()
        graph_run_id = f"graph_{make_run_id(config.llm.model)}"
        builder = CallGraphBuilder(
            api_key=resolved_key, model=config.llm.model,
            api_key_alias=key_alias, cost_ledger=ledger, run_id=graph_run_id,
        )
        g_nodes, name_index = builder.build(samples, routes=extractor.all_routes)

        plain = nodes_to_dict(g_nodes)

        context_out = save_call_graph(
            graph=g_nodes,
            output_folder=output_dir,
            source_path=path,
        )
        typer.echo(f"Call graph saved → {context_out}")

        edge_usage = builder.get_edge_resolution_usage()
        if edge_usage and edge_usage.total_tokens:
            edge_cost = estimate_cost(config.llm.model, edge_usage)
            cost_label = f"${edge_cost:.4f}" if edge_cost is not None else "unknown (model not in pricing table)"
            typer.echo(f"Edge resolution cost: {edge_usage.total_tokens} tokens, {cost_label}")

        # print summary
        tools_tmp = ToolSet(g_nodes, name_index)
        stats = tools_tmp.get_graph_summary()
        typer.echo(
            f"\nGraph summary: {stats['total_nodes']} nodes, {stats['total_edges']} edges\n"
            f"  Project functions: {stats['project_functions']}"
            f"  (nodes for functions in the analysed project)\n"
            f"  Entry points : {stats['entry_points']}\n"
            f"  Taint sources: {stats['taint_sources']}\n"
            f"  Taint sinks  : {stats['taint_sinks']}\n"
            f"  Infrastructure: {stats['infrastructure']}\n"
            f"  External refs: {stats['external_nodes']}"
        )

    # ── narrow the graph down to something readable ───────────────────────────
    out_dir = Path(output_dir)

    if only_findings or focus or hide_isolated:
        before = sum(1 for v in plain.values() if not v.get("is_external"))
        try:
            plain = select_subgraph(
                plain,
                findings=findings_dicts,
                focus=focus,
                hops=hops,
                only_findings=only_findings,
                hide_isolated=hide_isolated,
            )
        except ValueError as e:
            typer.echo(f"\n{e}", err=True)
            raise typer.Exit(1)
        typer.echo(f"Focused view: {len(plain)} of {before} node(s) drawn.")

    if labels not in ("auto", "all", "important", "none"):
        typer.echo(f"Unknown --labels {labels!r}: use auto, all, important or none.", err=True)
        raise typer.Exit(1)

    # ── export ────────────────────────────────────────────────────────────────
    if html:
        html_name = "call_graph_annotated.html" if findings_dicts else "call_graph.html"
        html_out = export_html(
            plain,
            out_dir / html_name,
            findings=findings_dicts or None,
            label_mode=labels,
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
    output_dir: Optional[str] = typer.Option(
        None, "--output-dir", "-o",
        help="Directory to write the patches JSON into. Defaults to "
             "experiments/datasets/<dataset>/patches/ when --results points into a "
             "dataset run folder, else experiments/results/patches."
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
    api_key_alias: Optional[str] = typer.Option(
        None, "--api-key-alias",
        help="Which API key to use for patch generation (see 'analyze --help'). "
             "Omit to use the default OPENAI_API_KEY."
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
    resolved_key, key_alias = config.resolve_api_key(api_key_alias)
    ledger = CostLedger()
    dataset = _infer_dataset_from_path(rp)

    typer.echo(f"\nRe-extracting source from {source_path} to recover function bodies...")
    extractor = CodeExtractor(
        max_function_lines=config.ingestion.max_function_lines,
        skip_dirs=config.ingestion.skip_dirs,
        chunk_oversized=config.ingestion.chunk_oversized,
    )
    samples = extractor.from_path(source_path)
    sample_index = {(s.function_name, s.file_path): s for s in samples}

    generator = PatchGenerator(
        api_key=resolved_key, model=config.llm.model,
        api_key_alias=key_alias, cost_ledger=ledger, run_id=run_id, dataset=dataset,
    )
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
                # no API call was made — genuinely $0, not unknown cost
                "prompt_tokens": 0, "completion_tokens": 0, "cost_usd": 0.0,
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
                "prompt_tokens": result.token_usage.prompt_tokens,
                "completion_tokens": result.token_usage.completion_tokens,
                "cost_usd": result.cost_usd,
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
            "prompt_tokens": result.token_usage.prompt_tokens,
            "completion_tokens": result.token_usage.completion_tokens,
            "cost_usd": result.cost_usd,
        })

    resolved_output_dir = output_dir or (
        f"experiments/datasets/{dataset}/patches" if dataset else "experiments/results/patches"
    )

    out_path = save_patches(
        patches=patches,
        run_id=run_id,
        source_path=source_path,
        output_folder=resolved_output_dir,
    )

    valid_count = sum(1 for p in patches if p["patch_valid"])
    patch_tokens = sum(p["prompt_tokens"] + p["completion_tokens"] for p in patches)
    known_costs = [p["cost_usd"] for p in patches if p["cost_usd"] is not None]
    patch_cost = sum(known_costs) if len(known_costs) == len(patches) else None
    cost_label = f"${patch_cost:.4f}" if patch_cost is not None else "unknown"
    typer.echo("\n" + "─" * 50)
    typer.echo(f"Total patches : {len(patches)}")
    typer.echo(f"Valid         : {valid_count}")
    typer.echo(f"Invalid       : {len(patches) - valid_count}")
    typer.echo(f"Patch generation cost: {patch_tokens} tokens, {cost_label}")
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


# ─────────────────────────────────────────────────────────────────────────────
# evaluate — score analysis run(s) against a ground truth dataset
# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def evaluate(
    results: List[str] = typer.Option(
        ..., "--results", "-r",
        help="Path to a completed analysis run JSON. Pass more than once to "
             "compare multiple runs (e.g. semantic vs agentic mode) side by side."
    ),
    ground_truth: str = typer.Option(
        ..., "--ground-truth", "-g",
        help="Path to a ground truth dataset JSON (experiments/datasets/<name>/ground_truth.json)."
    ),
    output_dir: Optional[str] = typer.Option(
        None, "--output-dir", "-o",
        help="Directory to write per-run evaluation JSON reports into. Defaults to "
             "experiments/datasets/<dataset>/evaluations/, inferred from the ground truth file."
    ),
):
    """
    Match a completed analysis run's findings against a ground truth dataset and
    compute precision/recall/F1, a per-CWE breakdown, and deduplicated
    (vuln-level) recall. Read-only — never touches the analyzed project or the
    run/ground-truth files.
    """
    gtp = Path(ground_truth)
    if not gtp.exists():
        typer.echo(f"Ground truth file not found: {gtp}", err=True)
        raise typer.Exit(1)

    # A bootstrap skeleton defaults every row to clean — scoring against one
    # yields plausible-looking but meaningless numbers, so say so loudly.
    _gt_probe = load_ground_truth(gtp)
    if _gt_probe.needs_curation:
        cs = _gt_probe.curation_status
        typer.echo(
            f"\n!! WARNING: {gtp.name} is an UNCURATED skeleton "
            f"(curation_status.reviewed is false).\n"
            f"   {cs.get('functions_unreviewed', '?')} row(s) are defaulted to clean and "
            f"{cs.get('functions_prefilled_vulnerable', '?')} are unconfirmed.\n"
            f"   Metrics computed from it are NOT valid — curate it first.\n",
            err=True,
        )

    reports_and_gt = []

    for results_file in results:
        rp = Path(results_file)
        if not rp.exists():
            typer.echo(f"Results file not found: {rp}", err=True)
            raise typer.Exit(1)

        report, gt = evaluate_run(rp, gtp)
        reports_and_gt.append((report, gt))

        resolved_output_dir = output_dir or f"experiments/datasets/{report.dataset}/evaluations"
        out_path = save_evaluation_report(report, gt, output_folder=resolved_output_dir)

        m = report.detection_metrics()
        ur = report.unique_recall(gt)

        typer.echo(f"\n{'-' * 60}")
        typer.echo(f"Run       : {report.run_id}")
        typer.echo(f"Mode      : {report.analysis_mode or '?'}")
        typer.echo(f"Dataset   : {report.dataset}")
        typer.echo(f"\nInstance-level detection (TP={m.tp} FP={m.fp} FN={m.fn} TN={m.tn}):")
        # Each point estimate is printed with its 95% band. A precision quoted
        # bare invites a comparison the row counts may not support — Semgrep's
        # 0.900 on this dataset rests on ten flagged rows and spans 0.60 to 0.98.
        md = m.to_dict()

        def _band(iv):
            return f"   [95% CI {iv['low']:.3f}-{iv['high']:.3f}, n={iv['n']}]" if iv else ""

        boot = report.metric_intervals()
        f1_band = (
            f"   [95% CI {boot['f1']['low']:.3f}-{boot['f1']['high']:.3f}, bootstrap]"
            if boot else ""
        )
        typer.echo(f"  Precision : {m.precision:.3f}{_band(md['precision_interval'])}")
        typer.echo(f"  Recall    : {m.recall:.3f}{_band(md['recall_interval'])}")
        typer.echo(f"  F1        : {m.f1:.3f}{f1_band}")

        lu = report.label_uncertainty()
        if lu:
            typer.echo(
                f"  {lu['disputed_rows']} ground truth rows are undecided; "
                f"counting them vulnerable instead of clean gives "
                f"P {lu['optimistic']['precision']:.3f} "
                f"R {lu['optimistic']['recall']:.3f} "
                f"F1 {lu['optimistic']['f1']:.3f}"
            )
        tiers = report.recall_by_evidence_tier()
        if tiers and len(tiers) > 1:
            typer.echo("  Recall by how the label was established:")
            for tier, row in sorted(tiers.items()):
                typer.echo(f"    {tier:<24} {row['detected']}/{row['total']}   {row['recall']:.3f}")

        tc = report.taxonomy_coverage(gt)
        if tc["ground_truth_cwes_not_offered"]:
            typer.echo(
                f"  WARNING: {tc['rows_labelled_with_an_unoffered_cwe']} vulnerable rows "
                f"are labelled with CWEs the prompt never offers "
                f"({', '.join(tc['ground_truth_cwes_not_offered'])}); "
                f"{tc['of_which_missed']} of them were missed. Recall ceiling if all "
                f"were recovered: {tc['recall_ceiling_if_all_recovered']}"
            )

        typer.echo(f"  CWE accuracy (on TPs) : {report.cwe_accuracy():.3f}")
        typer.echo(f"  Hallucination rate (on flagged) : {report.hallucination_rate():.3f}")
        # Printed right under the headline so the two are always read together —
        # an attribution-aware number quoted on its own is not defensible.
        am = report.attributed_detection_metrics()
        asum = report.attribution_summary()
        if (am.tp, am.fp, am.fn) != (m.tp, m.fp, m.fn):
            typer.echo(
                f"\nWith cross-function attribution credited "
                f"(TP={am.tp} FP={am.fp} FN={am.fn}):"
            )
            typer.echo(f"  Precision : {am.precision:.3f}")
            typer.echo(f"  Recall    : {am.recall:.3f}")
            typer.echo(f"  F1        : {am.f1:.3f}")
            typer.echo(
                f"  from {len(asum['rows_recovered'])} row(s) recovered, "
                f"{len(asum['false_positives_neutralized'])} false positive(s) neutralized"
            )

        gate = report.evidence_gate_breakdown()
        if gate:
            typer.echo("\nEvidence gate on flow CWEs (TP / FP / precision):")
            for verdict, row in gate.items():
                prec = f"{row['precision']:.3f}" if row["precision"] is not None else "n/a"
                typer.echo(f"  {verdict:<16} {row['tp']:>3} / {row['fp']:>3} / {prec}")

        scoped = report.scoped_metrics(gt)
        for label, row in scoped.items():
            typer.echo(
                f"\n{label.replace('_', ' ')} ({row['rows_excluded']} rows excluded, "
                f"TP={row['tp']} FP={row['fp']} FN={row['fn']}):"
            )
            typer.echo(f"  Precision : {row['precision']:.3f}")
            typer.echo(f"  Recall    : {row['recall']:.3f}")
            typer.echo(f"  F1        : {row['f1']:.3f}")

        typer.echo(f"\nDeduplicated vulnerability recall: {ur['detected']}/{ur['planted']} ({ur['recall']:.3f})")

        if report.total_cost_usd is not None:
            cost_per_tp = report.cost_per_tp()
            cost_per_tp_label = f"${cost_per_tp:.4f}" if cost_per_tp is not None else "n/a (0 true positives)"
            typer.echo(f"\nCost: ${report.total_cost_usd:.4f} total ({report.total_tokens} tokens), {cost_per_tp_label} per true positive")
        else:
            typer.echo("\nCost: n/a (run predates cost tracking, or model missing from pricing table)")

        breakdown = report.cwe_breakdown(gt)
        if breakdown:
            typer.echo("\nPer-CWE breakdown (planted / detected / correct-CWE):")
            for row in breakdown:
                typer.echo(
                    f"  {row['cwe_id']:<10} {row['planted']:>2} / {row['detected']:>2} / {row['cwe_correct']:>2}"
                )

        if report.unmatched_findings:
            typer.echo(f"\nUnmatched findings ({len(report.unmatched_findings)}) — not in ground truth, unscored:")
            for uf in report.unmatched_findings[:10]:
                typer.echo(f"  {uf['function_name']} ({uf['file_path']})")

        if report.unresolved_findings:
            typer.echo(f"\nAmbiguous matches ({len(report.unresolved_findings)}) — file couldn't disambiguate:")
            for rf in report.unresolved_findings[:10]:
                typer.echo(f"  {rf['function_name']} expected {rf['expected_file']}")

        typer.echo(f"\nEvaluation report saved -> {out_path}")

    if len(reports_and_gt) > 1:
        typer.echo(f"\n{'-' * 60}")
        typer.echo("Comparison across runs:\n")
        typer.echo(comparison_table(reports_and_gt))

        comparison_dir = output_dir or f"experiments/datasets/{reports_and_gt[0][0].dataset}/evaluations"
        cmp_path = save_comparison_report(reports_and_gt, output_folder=comparison_dir)
        typer.echo(f"\nComparison saved -> {cmp_path}")


# ─────────────────────────────────────────────────────────────────────────────
# bootstrap-ground-truth — scaffold a ground_truth.json for a real repository
# ─────────────────────────────────────────────────────────────────────────────

@app.command("bootstrap-ground-truth")
def bootstrap_ground_truth(
    path: str = typer.Option(
        ..., "--path", "-p", help="Repository to scaffold ground truth for."
    ),
    dataset: str = typer.Option(
        ..., "--dataset", "-d",
        help="Dataset name — output goes to experiments/datasets/<name>/ground_truth.json."
    ),
    fix_commit: List[str] = typer.Option(
        None, "--fix-commit",
        help="SHA of a vulnerability-fixing commit; functions it touches are pre-marked "
             "vulnerable for review. Repeatable. Requires --path to be a git checkout of "
             "the VULNERABLE (pre-fix) state."
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Override the output path."
    ),
    description: Optional[str] = typer.Option(
        None, "--description", help="Dataset description recorded in the file."
    ),
    config_path: Optional[str] = typer.Option(
        None, "--config", "-c", help="Path to YAML config file."
    ),
    force: bool = typer.Option(
        False, "--force",
        help="Overwrite an existing ground_truth.json. Destroys hand-curated labels."
    ),
):
    """
    Generate a ground_truth.json skeleton covering EVERY function in a repository.

    `evaluate` only counts a false positive when a clean function has a ground
    truth row — findings with no row are excluded from the confusion matrix — so
    precision cannot be computed unless clean functions are labelled too. This
    emits all of them defaulted to vulnerable=false for you to curate, rather
    than leaving you to transcribe hundreds of rows by hand.
    """
    repo = Path(path)
    if not repo.exists():
        typer.echo(f"Path does not exist: {repo}", err=True)
        raise typer.Exit(1)

    config = load_config(config_path)
    extractor = CodeExtractor(
        max_function_lines=config.ingestion.max_function_lines,
        skip_dirs=config.ingestion.skip_dirs,
        chunk_oversized=config.ingestion.chunk_oversized,
    )

    typer.echo(f"\nExtracting functions from {repo} ...")
    samples = extractor.from_path(str(repo))
    if not samples:
        typer.echo("No functions extracted — nothing to scaffold.", err=True)
        raise typer.Exit(1)

    skipped = extractor.skipped_functions
    payload = build_ground_truth(
        samples=samples,
        skipped=skipped,
        repo_root=repo,
        dataset=dataset,
        source_path=str(path),
        fix_commits=list(fix_commit or []),
        description=description or "",
    )

    out_path = Path(output) if output else Path(
        f"experiments/datasets/{dataset}/ground_truth.json"
    )

    try:
        saved = save_ground_truth_skeleton(payload, out_path, force=force)
    except FileExistsError as e:
        typer.echo(f"\n{e}", err=True)
        raise typer.Exit(1)

    cur = payload["curation_status"]
    cov = payload["coverage"]

    typer.echo(f"\nGround truth skeleton → {saved}")
    typer.echo(f"  Functions            : {payload['summary']['total_functions']}")
    typer.echo(f"  Pre-marked vulnerable: {cur['functions_prefilled_vulnerable']} (from {len(cur['fix_commits'])} fix commit(s))")
    typer.echo(f"  Unreviewed (clean)   : {cur['functions_unreviewed']}")
    if cov["functions_skipped_oversized"]:
        typer.echo(
            f"  Skipped oversized    : {cov['functions_skipped_oversized']} "
            f"— outside all metrics ({cov['coverage']:.1%} coverage)"
        )

    typer.echo(
        "\nNEXT: curate the file before evaluating.\n"
        "  1. Confirm each 'REVIEW REQUIRED' row is genuinely the vulnerability\n"
        "     (fix commits also carry refactoring and tests).\n"
        "  2. Set cwe_id + severity on every vulnerable row — both are left null here\n"
        "     deliberately; guessing them would corrupt the CWE-accuracy metric.\n"
        "  3. Spot-check the UNREVIEWED rows; any left mislabelled becomes a\n"
        "     false positive against the analyzer.\n"
        "  4. Set curation_status.reviewed = true when done."
    )


# ─────────────────────────────────────────────────────────────────────────────
# cost — cross-run spend, from the persistent cost ledger
# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def cost(
    run_id: Optional[str] = typer.Option(
        None, "--run-id",
        help="Scope the breakdown to a single run_id instead of all-time totals."
    ),
    by_run: bool = typer.Option(
        False, "--by-run",
        help="List totals per run_id instead of the default phase/key breakdown "
             "(ignored together with --run-id)."
    ),
    limit: int = typer.Option(
        20, "--limit", help="Max rows to show with --by-run."
    ),
):
    """
    Show LLM spend recorded in the persistent cost ledger
    (experiments/cost_ledger.db) — every real API call across every phase
    (call-graph edge resolution, vulnerability analysis, patch generation)
    and every run, regardless of which API key paid for it. Read-only.
    """
    ledger = CostLedger()

    def _fmt(row) -> str:
        cost_label = f"${row.cost_usd:.4f}" if row.cost_usd is not None else "unknown"
        return (
            f"  {row.group_key:<28} {row.calls:>5} call(s)  "
            f"{row.total_tokens:>8} tokens  {cost_label}"
        )

    if by_run and not run_id:
        typer.echo(f"Cost by run (most recent {limit}):")
        rows = ledger.by_run(limit=limit)
        if not rows:
            typer.echo("  (no runs recorded yet)")
        for row in rows:
            typer.echo(_fmt(row))
        return

    scope_label = f"run {run_id}" if run_id else "all runs"
    typer.echo(f"Cost — {scope_label}\n")

    total = ledger.total(run_id=run_id)
    total_label = f"${total.cost_usd:.4f}" if total.cost_usd is not None else "unknown"
    typer.echo(f"TOTAL: {total.calls} call(s), {total.total_tokens} tokens, {total_label}\n")

    phase_rows = ledger.by_phase(run_id=run_id)
    typer.echo("By phase:")
    if not phase_rows:
        typer.echo("  (nothing recorded yet)")
    for row in phase_rows:
        typer.echo(_fmt(row))

    key_rows = ledger.by_api_key(run_id=run_id)
    if len(key_rows) > 1:
        typer.echo("\nBy API key:")
        for row in key_rows:
            typer.echo(_fmt(row))


@app.command()
def ui(
    host: str = typer.Option(
        "127.0.0.1", "--host",
        help="Interface to bind. Localhost by default — this is an unauthenticated "
             "single-user research tool, not a deployable service."
    ),
    port: int = typer.Option(8000, "--port", help="Port to serve on."),
    dev: bool = typer.Option(
        False, "--dev",
        help="Serve the API only and enable autoreload, for use alongside "
             "`npm run dev` in frontend/ (Vite on :5173 proxies /api here)."
    ),
    open_browser: bool = typer.Option(
        True, "--open/--no-open", help="Open the UI in the default browser."
    ),
    replace: bool = typer.Option(
        False, "--replace",
        help="Stop the UI server that is already running and take its place, "
             "instead of refusing to start."
    ),
):
    """
    Serve the read-only web UI over the experiments tree.

    Reads the same artifacts the other commands write (analysis.json,
    extraction.json, call_graph.json, evaluations, patches, cost_ledger.db) —
    it never writes to experiments/, the analyzed project, or the ledger.

    Refuses to start when a UI server is already running: nothing used to stop a
    second one, and abandoned servers accumulated silently — each one still able
    to launch paid analysis jobs.
    """
    try:
        import uvicorn
    except ImportError:
        typer.echo(
            "The web UI needs fastapi + uvicorn:\n"
            "  pip install -r requirements.txt",
            err=True,
        )
        raise typer.Exit(code=1)

    from src.web import instance_lock
    from src.web.app import FRONTEND_DIST

    # ── single instance ───────────────────────────────────────────────────────
    existing = instance_lock.running_instance()
    if existing and not replace:
        typer.echo(
            f"A UI server is already running.\n"
            f"  pid     : {existing.pid}\n"
            f"  address : {existing.url}\n"
            f"  started : {existing.started_at}\n\n"
            "Use it, or start again with --replace to stop it and take over.\n"
            "Running several is what left seventeen abandoned servers behind, each one "
            "still able to launch paid analysis jobs.",
            err=True,
        )
        raise typer.Exit(code=1)

    if existing and replace:
        typer.echo(f"Stopping the UI server already running (pid {existing.pid})…")
        if not instance_lock.terminate(existing.pid):
            typer.echo(
                f"Could not stop pid {existing.pid}. Stop it yourself, then start again.",
                err=True,
            )
            raise typer.Exit(code=1)
        instance_lock.release()

    # A free port is checked separately: the lock catches our own servers, this
    # catches everything else, and an "address already in use" traceback out of
    # uvicorn tells the user nothing about which is which.
    if instance_lock.port_in_use(host, port):
        typer.echo(
            f"Port {port} is already in use by something else. "
            f"Pick another with --port.",
            err=True,
        )
        raise typer.Exit(code=1)

    url = f"http://{'localhost' if host == '127.0.0.1' else host}:{port}"

    if dev:
        typer.echo(f"API  → {url}/api/docs  (autoreload)")
        typer.echo("UI   → http://localhost:5173  (run `npm run dev` in frontend/)")
    elif FRONTEND_DIST.is_dir():
        typer.echo(f"UI   → {url}")
        typer.echo(f"API  → {url}/api/docs")
    else:
        # Serving an unbuilt SPA silently would look like a broken app, so say
        # exactly what is missing and how to fix it.
        typer.echo(f"API  → {url}/api/docs")
        typer.echo(
            "UI   → not built. Either:\n"
            "         cd frontend && npm install && npm run dev   (then use :5173)\n"
            "         cd frontend && npm run build                (then reload this URL)"
        )
        open_browser = False

    if open_browser and not dev:
        import threading
        import webbrowser

        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    instance_lock.acquire(host, port)
    try:
        uvicorn.run(
            "src.web.app:app",
            host=host,
            port=port,
            reload=dev,
            log_level="info",
        )
    finally:
        # Released on every exit path, including Ctrl-C. A lock left behind is
        # not fatal — running_instance() discards one whose process is gone —
        # but clearing it keeps the next start from having to work that out.
        instance_lock.release()


@app.command()
def groundedness(
    run_dir: str = typer.Option(
        ..., "--run", "-r",
        help="A completed run directory containing analysis.json, extraction.json "
             "and call_graph.json."
    ),
    evaluation: Optional[str] = typer.Option(
        None, "--evaluation", "-e",
        help="Optional evaluation JSON for the same run. Adds the cross-tabulation "
             "of groundedness against scored outcomes — the only part of this "
             "command that needs a ground truth."
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Write the full per-finding report to this path."
    ),
    recheck_patches: bool = typer.Option(
        False, "--recheck-patches",
        help="Re-analyse each validated patch to see whether the finding survives it. "
             "COSTS MONEY: one model call per patched function. Off by default; "
             "every other check in this command is free."
    ),
    max_rechecks: int = typer.Option(
        20, "--max-rechecks",
        help="Cap on re-analysis calls when --recheck-patches is passed. Findings "
             "beyond the cap are reported as skipped, not dropped."
    ),
    yes: bool = typer.Option(False, "--yes", help="Skip the spend confirmation."),
):
    """
    Score a run's findings against the program rather than against an answer key.

    Checks that each finding's lines fall inside its function, that line numbers
    cited in the explanation exist, that a flow CWE is reported on code some
    taint source can reach, that the CWE was one the prompt offered, and that
    identifiers quoted in the explanation appear in the code. Needs no ground
    truth and makes no model calls, so it runs on any codebase and costs nothing.
    """
    from src.evaluation.groundedness import cross_tabulate, score_findings

    base = Path(run_dir)
    missing = [f for f in ("analysis.json", "extraction.json", "call_graph.json")
               if not (base / f).exists()]
    if missing:
        typer.echo(f"Missing in {base}: {', '.join(missing)}", err=True)
        raise typer.Exit(1)

    def _load(name):
        return json.loads((base / name).read_text(encoding="utf-8"))

    # The patch check scores whatever `patch` already produced for this run. No
    # patches file simply means that check reports not-applicable throughout —
    # nothing here generates one, because generating patches costs money.
    patches = None
    found = sorted(base.glob("*_patches.json"))
    if found:
        patches = json.loads(found[0].read_text(encoding="utf-8"))
        typer.echo(f"Scoring patches from {found[0].name}")

    report = score_findings(_load("analysis.json"), _load("extraction.json"),
                            _load("call_graph.json"), patches=patches)

    typer.echo(f"\n{'-' * 60}")
    typer.echo(f"Findings scored : {report['findings_scored']}")
    typer.echo(f"Fully grounded  : {report['grounded']}  ({report['groundedness_rate']})")
    typer.echo(f"Ungrounded      : {report['ungrounded']}")
    typer.echo("\nPer check (pass / fail / not applicable):")
    for name, row in report["per_check"].items():
        rate = "-" if row["pass_rate"] is None else f"{row['pass_rate']:.3f}"
        typer.echo(f"  {name:<18} {row['pass']:>4} / {row['fail']:>4} / "
                   f"{row['not_applicable']:>4}   pass rate {rate}")

    if evaluation:
        ev = json.loads(Path(evaluation).read_text(encoding="utf-8"))
        x = cross_tabulate(report, ev)
        typer.echo("\nAgainst the scored outcomes:")
        for bucket in ("grounded", "ungrounded"):
            counts = x["table"][bucket]
            p = x[f"{bucket}_precision"]
            typer.echo(f"  {bucket:<12} TP={counts['TP']:<4} FP={counts['FP']:<4} "
                       f"precision {'-' if p is None else f'{p:.3f}'}")
        typer.echo(f"  {x['findings_not_in_ground_truth']} findings lie outside the "
                   f"ground truth's rows and are excluded from the table.")
        report["cross_tabulation"] = x

    if recheck_patches:
        report["patch_recheck"] = _recheck_patches(report, patches, max_rechecks, yes)

    if output:
        Path(output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        typer.echo(f"\nFull report -> {output}")


def _recheck_patches(report: dict, patches: Optional[dict], limit: int, yes: bool) -> dict:
    """C6 — re-analyse each validated patch. The one paid part of `groundedness`.

    Kept in its own function, and behind its own confirmation, so that the
    default path of this command cannot spend anything: every other check reads
    files that already exist.
    """
    from src.evaluation.patch_recheck import recheck_run
    from src.models.code_sample import CodeSample, Language

    candidates = sum(
        1 for row in (patches or {}).get("patches", []) if row.get("patch_valid") is True
    )
    billable = min(candidates, limit)
    if not billable:
        typer.echo("\nNo validated patches to re-check.")
        return {"calls_made": 0, "counts": {}, "resolution_rate": None, "rows": []}

    typer.echo(f"\n--recheck-patches will make up to {billable} model calls "
               f"({candidates} validated patches, cap {limit}).")
    if not yes and not typer.confirm("Proceed?", default=False):
        typer.echo("Skipped — no calls made.")
        return {"calls_made": 0, "counts": {}, "resolution_rate": None, "rows": []}

    config = load_config(None)
    resolved_key, key_alias = config.resolve_api_key(None)
    client = LLMClient(config.llm, api_key=resolved_key, api_key_alias=key_alias)

    def analyze(patched_code: str, finding: dict) -> dict:
        # No context prompt: the question is whether the patched function still
        # reads as vulnerable on its own terms, and re-injecting the call graph
        # would let a neighbour's defect keep the verdict alive.
        sample = CodeSample(
            function_name=finding.get("function_name") or "patched",
            file_path=finding.get("file_path") or "",
            code=patched_code,
            language=Language(finding.get("language") or "typescript"),
            start_line=1,
            end_line=max(1, patched_code.count("\n") + 1),
        )
        result = client.analyze(sample, phase="patch_recheck")
        return {"vulnerability_found": result.vulnerability_found, "cwe_id": result.cwe_id}

    out = recheck_run(report, patches or {}, analyze, limit=limit)
    counts = out["counts"]
    typer.echo(f"\nPatch re-check ({out['calls_made']} calls):")
    typer.echo(f"  resolved   {counts.get('resolved', 0)}   (finding gone after the patch)")
    typer.echo(f"  unresolved {counts.get('unresolved', 0)}   (same CWE still reported)")
    typer.echo(f"  displaced  {counts.get('displaced', 0)}   (a different CWE now reported)")
    typer.echo(f"  skipped    {counts.get('skipped', 0)}")
    if out["resolution_rate"] is not None:
        typer.echo(f"  resolution rate {out['resolution_rate']:.3f} over the "
                   f"{out['calls_made']} re-checked")
    return out


if __name__ == "__main__":
    try:
        app()
    except KeyboardInterrupt:
        # `analyze` handles Ctrl-C inside its analysis loop, where there are
        # paid-for results to save. This catches it during every other phase
        # (extraction, graph building) where there is nothing to save — so a
        # cancel prints one line instead of a traceback.
        typer.echo("\nCancelled.", err=True)
        sys.exit(130)