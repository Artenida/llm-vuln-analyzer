"""
Evaluation reports.

Listing and reading are by full path — reports live beside the dataset they
scored, not inside a run's output directory — validated by
`paths.resolve_evaluation_file`. Scoring a run is a POST because it writes a
report file; it makes no API calls and costs nothing.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from src.web import evaluations, paths

router = APIRouter(prefix="/evaluations", tags=["evaluations"])


def _report_file(path: str):
    try:
        return paths.resolve_evaluation_file(path)
    except paths.UnsafePathError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("")
def list_evaluations() -> dict:
    """Every evaluation report and comparison reachable from a registered root."""
    return evaluations.discover()


@router.get("/datasets")
def list_datasets() -> list[dict]:
    """Ground truth datasets a run can be scored against."""
    return evaluations.datasets()


@router.get("/for-run")
def evaluations_for_run(run_id: Optional[str] = Query(None)) -> list[dict]:
    """Reports already produced for a run id — the Results page's cross-link."""
    return evaluations.for_run(run_id)


@router.get("/report")
def get_report(path: str = Query(..., description="Path to an eval_*.json report.")) -> dict:
    try:
        return evaluations.report(_report_file(path))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/comparison", response_class=PlainTextResponse)
def get_comparison(path: str = Query(..., description="Path to a comparison_*.md.")) -> str:
    try:
        return evaluations.comparison(_report_file(path))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


class EvaluateRequest(BaseModel):
    path: str          # the run's output directory
    ground_truth: str  # experiments/datasets/<name>/ground_truth.json


@router.post("/run")
def run_evaluation(request: EvaluateRequest) -> dict:
    """Score one run against one ground truth dataset, and save the report.

    Read-only with respect to the run and the dataset: the report file is the
    only thing written.
    """
    try:
        run_dir = paths.resolve_result_dir(request.path)
        ground_truth = paths.resolve_ground_truth(request.ground_truth)
    except paths.UnsafePathError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    try:
        return evaluations.evaluate(run_dir, ground_truth)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except (OSError, KeyError, TypeError) as exc:
        # A malformed analysis.json or ground truth surfaces here; report it as
        # a bad input rather than a server fault the user can do nothing about.
        raise HTTPException(status_code=422, detail=f"Could not evaluate this run: {exc}")
