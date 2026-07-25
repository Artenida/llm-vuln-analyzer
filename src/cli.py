"""
CLI entry point.

Commands:
  analyze    Run vulnerability analysis on a path or snippet
  show       Pretty-print a saved results JSON file
  graph      Build and/or visualize a call graph
  patch      Generate + validate fixes for flagged functions in a completed run
  evaluate   Score one or more analysis runs against a ground truth dataset
  cost       Show LLM spend from the persistent cost ledger (all-time or per-run)
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
from src.results import save_extraction_results, save_run, save_call_graph, save_patches, make_run_id
from src.results.checkpoint import CheckpointHeader, CheckpointMismatch, RunCheckpoint
from src.results.patch_generator import PatchGenerator
from src.results.patch_validator import PatchValidator
from src.results.export_graph import export_dot, export_html, select_subgraph
from src.results.save_graph import load_call_graph
from src.context.call_graph import nodes_to_dict
from src.llm.client import LLMClient
from src.llm.cost_ledger import CostLedger
from src.llm.pricing import TokenUsage, estimate_cost
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
    resolved_key, key_alias = config.resolve_api_key(api_key_alias)
    ledger = CostLedger()
    run_id = make_run_id(config.llm.model)

    # ── named run: redirect all outputs to experiments/datasets/<dataset>/runs/<name>/ ──
    if run_name:
        run_dir = (
            f"experiments/datasets/{dataset}/runs/{run_name}"
            if dataset else f"experiments/runs/{run_name}"
        )
        config.output.extraction_folder = run_dir
        config.output.context_folder    = run_dir
        config.output.analysis_folder   = run_dir

    extractor = CodeExtractor(
        max_function_lines=config.ingestion.max_function_lines,
        skip_dirs=config.ingestion.skip_dirs,
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
    typer.echo(f"  Functions : {len(samples)}")
    for lang, count in sorted(lang_counts.items()):
        typer.echo(f"  {lang:<12}: {count}")
    if skipped:
        covered = len(samples) / (len(samples) + len(skipped))
        typer.echo(
            f"  Skipped   : {len(skipped)} function(s) over "
            f"{config.ingestion.max_function_lines} lines — NOT analysed "
            f"({covered:.1%} coverage)"
        )
        for sk in skipped[:5]:
            typer.echo(f"    {sk.name} ({sk.line_count} lines) {sk.file_path}")
        if len(skipped) > 5:
            typer.echo(f"    ... and {len(skipped) - 5} more (see extraction JSON)")

    extraction_out = save_extraction_results(
        samples=samples,
        source_path=source_label,
        output_folder=config.output.extraction_folder,
        filename="extraction.json" if run_name else None,
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
    )
    graph, name_index = builder.build(samples, routes=extractor.all_routes)

    context_out = save_call_graph(
        graph=graph,
        output_folder=config.output.context_folder,
        source_path=source_label,
        filename="call_graph.json" if run_name else None,
    )
    typer.echo(f"Call graph built successfully ({len(graph)} nodes)")
    typer.echo(f"Call graph saved → {context_out}")

    edge_usage = builder.get_edge_resolution_usage()
    edge_cost = estimate_cost(config.llm.model, edge_usage) if edge_usage else None
    if edge_usage and edge_usage.total_tokens:
        cost_label = f"${edge_cost:.4f}" if edge_cost is not None else "unknown (model not in pricing table)"
        typer.echo(f"Edge resolution   : {edge_usage.total_tokens} tokens, {cost_label}")

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

    out_path = save_run(
        reports=reports,
        samples=samples,
        source_path=source_label,
        model=config.llm.model,
        results_folder=config.output.analysis_folder,
        filename="analysis.json" if run_name else None,
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
            + (f"--run-name {run_name} " if run_name else "")
            + (f"--dataset {dataset} " if dataset else "")
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
        typer.echo(f"  Precision : {m.precision:.3f}")
        typer.echo(f"  Recall    : {m.recall:.3f}")
        typer.echo(f"  F1        : {m.f1:.3f}")
        typer.echo(f"  CWE accuracy (on TPs) : {report.cwe_accuracy():.3f}")
        typer.echo(f"  Hallucination rate (on flagged) : {report.hallucination_rate():.3f}")
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


if __name__ == "__main__":
    app()