import json
import typer
from datetime import datetime
from pathlib import Path
from src.config import load_config
from src.preprocessing.data_loader import load_juliet_folder, CodeSample
from src.llm.client import LLMClient, VulnerabilityReport

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
        help="Path to config YAML file"
    ),
):
    """Analyze code samples for vulnerabilities using config file settings."""

    # Load config
    config = load_config(config_path)
    typer.echo(f"Config loaded: {config_path}")
    typer.echo(f"Model:         {config.llm.provider} / {config.llm.model}")
    typer.echo(f"Dataset:       {config.dataset.folder}")
    typer.echo(f"Limit:         {config.dataset.limit or 'all'}")

    # Load samples
    typer.echo(f"\nLoading samples...")
    samples = load_juliet_folder(config.dataset.folder)
    if config.dataset.limit:
        samples = samples[:config.dataset.limit]
    typer.echo(f"Loaded {len(samples)} samples")

    # Run analysis
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

    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"{config.output.folder}/analysis_{config.llm.model}_{timestamp}.json"
    Path(config.output.folder).mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump({
            "metadata": {
                "model": config.llm.model,
                "provider": config.llm.provider,
                "total_samples": len(results),
                "timestamp": datetime.now().isoformat(),
                "folder": config.dataset.folder,
                "config_used": config_path,
            },
            "results": results,
        }, f, indent=2)

    typer.echo(f"\nDone. Results saved to: {output_path}")

if __name__ == "__main__":
    typer.run(analyze)