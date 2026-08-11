"""
Reading — and producing — evaluation reports.

`evaluate` scores a completed run against a ground truth dataset and writes
`eval_<run_id>.json` into `experiments/datasets/<dataset>/evaluations/`, plus a
`comparison_<stamp>.md` when more than one run was scored together. Until now
those files were only reachable from a terminal; this module is what the UI
reads them through.

Two things are deliberate:

* **The curation warning travels with the numbers.** A bootstrap ground truth
  defaults every row to clean, so scoring against one produces plausible
  metrics that mean nothing. The report JSON does not record that, so it is
  looked up from the dataset on read — a report shown without the warning is
  worse than no report.
* **Scoring is a pure read.** `evaluate_run` never touches the analysed project,
  the run, or the ground truth. The only file written is the report itself.
"""
from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from src.web import paths

logger = logging.getLogger(__name__)

# How far below a registered root to look for `evaluations/` directories.
# experiments/datasets/<name>/evaluations/<file> is four levels; anything deeper
# is not a layout this tool produces, and unbounded recursion over a root the
# user registered could mean walking a whole drive.
_MAX_DEPTH = 5

# The field that distinguishes a report from any other JSON that happens to
# share the directory.
_REPORT_MARKER = "detection_metrics"


def _mtime(path: Path) -> Optional[str]:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")
    except OSError:
        return None


def _evaluation_dirs() -> list[Path]:
    """Every `evaluations/` directory reachable from a registered root."""
    found: dict[Path, None] = {}
    for root in paths.registered_roots():
        if not root.is_dir():
            continue
        _collect(root, depth=0, found=found)
    return list(found)


def _collect(directory: Path, depth: int, found: dict[Path, None]) -> None:
    if depth > _MAX_DEPTH:
        return
    try:
        children = [c for c in directory.iterdir() if c.is_dir()]
    except OSError:
        return
    for child in children:
        if child.name == paths.EVALUATION_DIR_NAME:
            try:
                found.setdefault(child.resolve(), None)
            except OSError:
                continue
            continue  # nothing nests below an evaluations/ directory
        _collect(child, depth + 1, found)


# ── curation status ───────────────────────────────────────────────────────────


_UNKNOWN_CURATION = {
    "known": False, "scaffolded": None, "reviewed": None, "needs_curation": None,
}


def _curation_of(gt_path: Path, data: dict) -> dict:
    """Mirrors `GroundTruthDataset.needs_curation`.

    A dataset with no `curation_status` block at all was written by hand, not
    scaffolded, so it is not flagged — only a *scaffold* that has not been
    reviewed is. Diverging from that rule would make the UI contradict the CLI
    on which numbers are quotable.
    """
    status = data.get("curation_status") or {}
    reviewed = bool(status.get("reviewed", False))
    return {
        "known": True,
        "scaffolded": bool(status),
        "reviewed": reviewed,
        "needs_curation": bool(status) and not reviewed,
        "functions_unreviewed": status.get("functions_unreviewed"),
        "functions_prefilled_vulnerable": status.get("functions_prefilled_vulnerable"),
        "ground_truth_path": str(gt_path),
    }


def _curation(dataset: Optional[str]) -> dict:
    """Whether the ground truth these numbers came from has been reviewed.

    Reported as unknown, never as curated, when the dataset is no longer on this
    machine — an unwarned invalid number is worse than an unavailable one.
    """
    if not dataset:
        return dict(_UNKNOWN_CURATION)
    gt_path = paths.datasets_root() / dataset / "ground_truth.json"
    data = paths.read_json(gt_path)
    if not isinstance(data, dict):
        return dict(_UNKNOWN_CURATION)
    return _curation_of(gt_path, data)


# ── listing ───────────────────────────────────────────────────────────────────


def _summarise(path: Path, report: dict) -> dict:
    """A report minus its two long arrays — enough for a list row and the header."""
    unique = report.get("unique_vulnerability_recall") or {}
    return {
        "path": str(path),
        "display_path": paths.display_path(path),
        "name": path.name,
        "modified_at": _mtime(path),

        "run_id": report.get("run_id"),
        "dataset": report.get("dataset"),
        "model": report.get("model"),
        "analysis_mode": report.get("analysis_mode"),
        "source_path": report.get("source_path"),
        "generated_at": report.get("generated_at"),
        "schema_version": report.get("schema_version"),

        "detection_metrics": report.get("detection_metrics") or {},
        "cwe_accuracy_on_true_positives": report.get("cwe_accuracy_on_true_positives"),
        "unique_vulnerability_recall": unique,
        "hallucination_rate_on_flagged": report.get("hallucination_rate_on_flagged"),
        "total_cost_usd": report.get("total_cost_usd"),
        "total_tokens": report.get("total_tokens"),
        "cost_per_tp_usd": report.get("cost_per_tp_usd"),

        "instance_count": len(report.get("instances") or []),
        "unmatched_count": len(report.get("unmatched_findings") or []),
        "unresolved_count": len(report.get("unresolved_findings") or []),
        "curation": _curation(report.get("dataset")),
    }


def discover() -> dict:
    """Every evaluation report and comparison this install can see."""
    reports: list[dict] = []
    comparisons: list[dict] = []

    for directory in _evaluation_dirs():
        try:
            children = sorted(directory.iterdir())
        except OSError:
            continue
        for child in children:
            if not child.is_file():
                continue
            if child.suffix.lower() == ".md":
                comparisons.append({
                    "path": str(child),
                    "display_path": paths.display_path(child),
                    "name": child.name,
                    "dataset": _dataset_of(child),
                    "modified_at": _mtime(child),
                })
                continue
            if child.suffix.lower() != ".json":
                continue
            data = paths.read_json(child)
            # A malformed or unrelated file is skipped rather than failing the
            # whole listing — one bad file must not hide every other report.
            if not isinstance(data, dict) or _REPORT_MARKER not in data:
                continue
            reports.append(_summarise(child, data))

    reports.sort(key=lambda r: (r.get("generated_at") or r.get("modified_at") or ""), reverse=True)
    comparisons.sort(key=lambda c: c.get("modified_at") or "", reverse=True)
    return {"reports": reports, "comparisons": comparisons}


def _dataset_of(path: Path) -> Optional[str]:
    """`experiments/datasets/<name>/evaluations/x` -> `<name>`."""
    parent = path.parent.parent
    return parent.name if parent != parent.parent else None


def report(path: Path) -> dict:
    """One full report, including instances and the per-CWE breakdown."""
    data = paths.read_json(path)
    if not isinstance(data, dict):
        raise ValueError(f"{path.name} could not be parsed as an evaluation report.")
    return {**data, **_summarise(path, data)}


def comparison(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"{path.name} could not be read: {exc}") from exc


# ── ground truth datasets ─────────────────────────────────────────────────────


def datasets() -> list[dict]:
    """Datasets a run can be scored against, with their curation state."""
    root = paths.datasets_root()
    if not root.is_dir():
        return []
    entries: list[dict] = []
    try:
        children = sorted(root.iterdir())
    except OSError:
        return entries
    for child in children:
        gt_path = child / "ground_truth.json"
        data = paths.read_json(gt_path)
        if not isinstance(data, dict):
            continue
        functions = data.get("functions") or []
        name = data.get("dataset") or child.name
        entries.append({
            "name": name,
            "folder": child.name,
            "path": str(gt_path),
            "description": data.get("description") or "",
            "source_path": data.get("source_path") or "",
            "function_count": len(functions),
            "vulnerable_count": sum(1 for f in functions if f.get("vulnerable")),
            "curation": _curation_of(gt_path, data),
        })
    return entries


# ── running an evaluation ─────────────────────────────────────────────────────


def evaluate(run_dir: Path, ground_truth_path: Path) -> dict:
    """Score a run against a dataset and persist the report.

    Mirrors `cli evaluate` exactly, including where the report lands: the output
    directory is derived from the *dataset name inside the ground truth file*,
    not from the file's location, so a report written here and one written by
    the CLI end up in the same place under the same name.
    """
    analysis = run_dir / "analysis.json"
    if not analysis.is_file():
        raise ValueError(
            "This run has no analysis.json — there are no findings to score."
        )

    from src.evaluation import evaluate_run, save_evaluation_report

    result, gt = evaluate_run(analysis, ground_truth_path)
    output_folder = paths.datasets_root() / result.dataset / paths.EVALUATION_DIR_NAME
    out_path = save_evaluation_report(result, gt, output_folder=str(output_folder))
    logger.info("Evaluation of %s -> %s", run_dir, out_path)
    return report(out_path)


def for_run(run_id: Optional[str]) -> list[dict]:
    """Existing reports for a given run id — the Results page's cross-link."""
    if not run_id:
        return []
    return [r for r in discover()["reports"] if r.get("run_id") == run_id]
