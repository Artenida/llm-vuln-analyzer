import json
import typer
from datetime import datetime
from pathlib import Path
from src.config import load_config
from src.preprocessing.data_loader import load_juliet_folder, dataset_summary, CodeSample
from src.preprocessing.bigvul_loader import load_bigvul_csv
from src.llm.client import LLMClient, VulnerabilityReport
from src.evaluation import evaluate_result_file, load_multiple_result_files, build_report, save_report, print_summary

app = typer.Typer()


def report_to_dict(sample: CodeSample, report: VulnerabilityReport) -> dict:
    return {
        "file": sample.file_path,
        "method": sample.function_name,
        "cwe_id": sample.cwe_id,
        "ground_truth_vulnerable": sample.is_vulnerable,
        "language": sample.language,
        "llm_result": {
            "vulnerability_found": report.vulnerability_found,
            "cwe_id": report.cwe_id,
            "affected_lines": report.affected_lines,
            "severity": report.severity,
            "explanation": report.explanation,
            "patch_suggestion": report.patch_suggestion,
            "confidence": report.confidence,
            "hallucination_flag": report.hallucination_flag,
            "model_used": report.model_used,
        }
    }


@app.command()
def analyze(
    config_path: str = typer.Option(
        "experiments/configs/default.yaml",
        "--config", "-c",
        help="Path to config YAML file",
    ),
    evaluate_after: bool = typer.Option(
        True,
        "--evaluate/--no-evaluate",
        help="Run evaluation automatically after analysis finishes",
    ),
    dataset: str = typer.Option(
        "all",
        "--dataset", "-d",
        help="Which dataset to run: 'juliet', 'bigvul', or 'all'",
    ),
):
    """
    Analyze code samples for vulnerabilities using config file settings.

    Examples:

      # Run Juliet only (default)
      python cli.py analyze --dataset juliet

      # Run BigVul only
      python cli.py analyze --dataset bigvul

      # Run both (requires bigvul.enabled: true in config)
      python cli.py analyze --dataset all
    """
    config = load_config(config_path)
    typer.echo(f"Config loaded: {config_path}")
    typer.echo(f"Model:         {config.llm.provider} / {config.llm.model}")

    samples: list[CodeSample] = []

    # ------------------------------------------------------------------ Juliet
    if dataset in ("juliet", "all"):
        typer.echo(f"\n[Juliet] Loading from {config.dataset.folder}")
        juliet_samples = load_juliet_folder(
            config.dataset.folder,
            limit=config.dataset.limit,
            limit_per_cwe=config.dataset.limit_per_cwe,
        )
        summary = dataset_summary(juliet_samples)
        typer.echo(f"[Juliet] {summary['total']} samples  "
                   f"({summary['vulnerable']} vulnerable, {summary['safe']} safe)")
        typer.echo("  CWE breakdown:")
        for cwe, count in summary["by_cwe"].items():
            typer.echo(f"    {cwe:<12} {count} samples")
        samples.extend(juliet_samples)

    # ------------------------------------------------------------------ BigVul
    if dataset in ("bigvul", "all"):
        if not config.bigvul.enabled and dataset == "all":
            typer.echo("\n[BigVul] Skipped (set bigvul.enabled: true in config to include)")
        else:
            typer.echo(f"\n[BigVul] Loading from {config.bigvul.csv_path}")
            langs = set(config.bigvul.languages) if config.bigvul.languages else None
            bigvul_samples = load_bigvul_csv(
                csv_path=config.bigvul.csv_path,
                limit_per_cwe=config.bigvul.limit_per_cwe,
                limit=config.bigvul.limit,
                languages=langs,
            )
            bv_summary = dataset_summary(bigvul_samples)
            typer.echo(f"[BigVul] {bv_summary['total']} samples  "
                       f"({bv_summary['vulnerable']} vulnerable, {bv_summary['safe']} safe)")
            typer.echo("  CWE breakdown:")
            for cwe, count in bv_summary["by_cwe"].items():
                typer.echo(f"    {cwe:<12} {count} samples")
            samples.extend(bigvul_samples)

    if not samples:
        typer.echo("\nNo samples loaded. Check your config and --dataset flag.")
        raise typer.Exit(1)

    typer.echo(f"\nTotal samples to analyze: {len(samples)}")

    # ------------------------------------------------------------------ Run LLM
    client = LLMClient(
        model=config.llm.model,
        max_tokens=config.llm.max_tokens,
        temperature=config.llm.temperature,
    )
    results = []

    for i, sample in enumerate(samples, 1):
        typer.echo(f"[{i}/{len(samples)}] {sample.function_name}")
        report = client.analyze(sample)
        results.append(report_to_dict(sample, report))

    # ------------------------------------------------------------------ Save
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"{config.output.folder}/analysis_{config.llm.model}_{timestamp}.json"
    Path(config.output.folder).mkdir(parents=True, exist_ok=True)

    result_data = {
        "metadata": {
            "model": config.llm.model,
            "provider": config.llm.provider,
            "total_samples": len(results),
            "timestamp": datetime.now().isoformat(),
            "datasets_used": dataset,
            "config_used": config_path,
        },
        "results": results,
    }

    with open(output_path, "w") as f:
        json.dump(result_data, f, indent=2)

    typer.echo(f"\nDone. Results saved to: {output_path}")

    # --------------------------------------------------------- Auto-evaluate
    if evaluate_after:
        typer.echo("\nRunning evaluation...")
        eval_output = (
            output_path
            .replace(config.output.folder, f"{config.output.folder}/evaluations")
            .replace("analysis_", "eval_")
        )
        evaluate_result_file(
            result_path=output_path,
            output_path=eval_output,
            print_to_console=True,
        )


@app.command()
def evaluate(
    result_path: str = typer.Argument(
        ...,
        help="Path to an analysis JSON file produced by the 'analyze' command",
    ),
    output_path: str = typer.Option(
        None,
        "--output", "-o",
        help="Where to save the evaluation report JSON (optional)",
    ),
    compare: list[str] = typer.Option(
        None,
        "--compare",
        help="Additional result files to merge and evaluate together",
    ),
):
    """
    Evaluate a result file and print a metrics report.

    Examples:

      # Evaluate a single result file
      python cli.py evaluate experiments/results/analysis_gpt-4o-mini_20260502.json

      # Evaluate and save the report
      python cli.py evaluate experiments/results/analysis_gpt-4o-mini_20260502.json \\
          --output experiments/results/evaluations/eval_20260502.json

      # Merge and compare two runs (e.g. Juliet vs BigVul)
      python cli.py evaluate experiments/results/juliet_run.json \\
          --compare experiments/results/bigvul_run.json
    """
    if compare:
        all_paths = [result_path] + list(compare)
        typer.echo(f"Merging {len(all_paths)} result files...")
        merged_meta, results = load_multiple_result_files(all_paths)
        report = build_report(results, metadata=merged_meta)

        if output_path:
            saved = save_report(report, output_path)
            typer.echo(f"Report saved to: {saved}")

        print_summary(report)
    else:
        if output_path is None:
            p = Path(result_path)
            output_path = str(
                p.parent / "evaluations" / p.name.replace("analysis_", "eval_")
            )

        evaluate_result_file(
            result_path=result_path,
            output_path=output_path,
            print_to_console=True,
        )


if __name__ == "__main__":
    app()