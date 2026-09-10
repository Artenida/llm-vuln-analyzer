"""
Running analyses and patch generation.

The only endpoints in this app that cause anything to happen. Every one of them
spends money, so `POST /jobs/estimate` exists to answer "how much?" before the
user commits.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from src.web import jobs as job_module
from src.web import paths, settings_store
from src.web.jobs import ArgumentError, manager
from src.web.routers import configs as configs_router

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/jobs", tags=["jobs"])


class AnalyzeRequest(BaseModel):
    source_path: str
    output_dir: Optional[str] = None
    react: bool = True
    visualize: bool = True
    dry_run: bool = False
    resume: bool = False
    config_path: Optional[str] = None
    # None = whatever the chosen config says.
    chunk_oversized: Optional[bool] = None
    budget_usd: Optional[float] = None
    api_key_alias: Optional[str] = None
    label: Optional[str] = None


class PatchRequest(BaseModel):
    output_dir: str
    source_path: Optional[str] = None
    api_key_alias: Optional[str] = None


class EstimateRequest(BaseModel):
    functions: Optional[int] = None
    react: bool = True


def _suggest_output_dir(source_path: str) -> Path:
    """`<results root>/<folder name>-<timestamp>`.

    Timestamped so a second analysis of the same folder never silently
    overwrites the first — results are paid for.
    """
    settings = settings_store.load_settings()
    root = Path(settings.results_root or paths.default_results_root())
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", Path(source_path).name).strip("-") or "scan"
    return root / f"{stem}-{datetime.now().strftime('%Y%m%d_%H%M%S')}"


@router.post("/analyze")
def start_analyze(request: AnalyzeRequest) -> dict:
    settings = settings_store.load_settings()

    alias = request.api_key_alias or settings.api_key_alias
    api_key = None
    if not request.dry_run:
        api_key, source = settings_store.resolve_key(alias)
        if not api_key:
            raise HTTPException(
                status_code=400,
                detail=f"No OpenAI API key set for '{alias}'. Add one on the "
                       "Settings page before running an analysis.",
            )
        logger.debug("Analysis will use the %s key from %s", alias, source)

    # Normalised once, here, and used for the argv, the registry and the job
    # record alike — a relative path recorded anywhere would resolve against
    # whatever the current directory happened to be when it was later read.
    try:
        output_dir = (
            paths.normalise(request.output_dir)
            if request.output_dir
            else _suggest_output_dir(request.source_path).resolve()
        )
    except paths.UnsafePathError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Resolved through the same helper `/fs/inspect` uses, and passed on even
    # when the request named none. An explicit `--config` costs nothing and puts
    # the scope in `job.command`, where the progress panel shows it — a run
    # whose scope is implicit is a run nobody can check afterwards.
    try:
        config_file = configs_router.resolve(request.config_path)
    except paths.UnsafePathError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    try:
        argv = job_module.build_analyze_argv(
            source_path=request.source_path,
            output_dir=str(output_dir),
            react=request.react,
            visualize=request.visualize,
            dry_run=request.dry_run,
            resume=request.resume,
            config_path=str(config_file),
            chunk_oversized=request.chunk_oversized,
            budget_usd=request.budget_usd,
            api_key_alias=alias,
        )
    except (ArgumentError, paths.UnsafePathError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"Could not create the output folder: {exc}")
    # Registered up front, not on completion, so a run that is cancelled or
    # fails halfway is still readable.
    paths.register_root(output_dir)

    label = request.label or Path(request.source_path).name
    try:
        job = manager.start(
            "analyze", argv,
            label=label,
            output_dir=str(output_dir),
            source_path=request.source_path,
            api_key=api_key,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return job.public()


@router.post("/patch")
def start_patch(request: PatchRequest) -> dict:
    try:
        directory = paths.resolve_result_dir(request.output_dir)
    except paths.UnsafePathError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    analysis = directory / "analysis.json"
    if not analysis.is_file():
        raise HTTPException(
            status_code=400,
            detail="This result has no analysis.json, so there is nothing to patch.",
        )

    settings = settings_store.load_settings()
    alias = request.api_key_alias or settings.api_key_alias
    api_key, _ = settings_store.resolve_key(alias)
    if not api_key:
        raise HTTPException(
            status_code=400,
            detail=f"No OpenAI API key set for '{alias}'. Patch generation makes LLM calls.",
        )

    try:
        argv = job_module.build_patch_argv(
            results_path=str(analysis),
            output_dir=str(directory),
            source_path=request.source_path,
            api_key_alias=alias,
        )
    except (ArgumentError, paths.UnsafePathError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    try:
        job = manager.start(
            "patch", argv,
            label=f"patches for {directory.name}",
            output_dir=str(directory),
            api_key=api_key,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return job.public()


@router.post("/estimate")
def estimate(request: EstimateRequest) -> dict:
    """Project a run's cost from measured per-function spend.

    Derived from the cost ledger's own history for the chosen mode. If the
    ledger has nothing for that mode, this says so — a fabricated rate on a
    screen that asks you to authorise spending would be worse than no number.
    """
    if not request.functions:
        return {"known": False, "reason": "Function count unknown for this folder."}

    phase = "react_loop" if request.react else "call_graph_context"

    if not paths.cost_ledger_path().is_file():
        return {"known": False, "reason": "No cost history yet — nothing has been run on this machine."}

    try:
        from src.llm.cost_ledger import CostLedger

        ledger = CostLedger(str(paths.cost_ledger_path()))
        rows = {row.group_key: row for row in ledger.by_phase()}
    except Exception as exc:
        return {"known": False, "reason": f"Could not read the cost ledger: {exc}"}

    analysis_row = rows.get(phase)
    if analysis_row is None or analysis_row.cost_usd is None or not analysis_row.calls:
        return {
            "known": False,
            "reason": f"No measured cost yet for {'agentic' if request.react else 'semantic'} mode.",
        }

    # Per *function*, not per call: an agentic verdict costs several calls, and
    # dividing by calls would understate a ReAct run by roughly that factor.
    functions_seen = _functions_seen_for_phase(phase)
    if not functions_seen:
        return {"known": False, "reason": "Not enough history to derive a per-function rate."}

    per_function = analysis_row.cost_usd / functions_seen
    edge_row = rows.get("edge_resolution")
    edge_note = None
    if edge_row is not None and edge_row.cost_usd:
        edge_note = (
            "Call-graph edge resolution is billed separately and is cached — a folder "
            "analysed before costs much less the second time."
        )

    return {
        "known": True,
        "functions": request.functions,
        "per_function_usd": per_function,
        "estimate_usd": per_function * request.functions,
        "based_on_functions": functions_seen,
        "mode": phase,
        "note": edge_note,
    }


def _functions_seen_for_phase(phase: str) -> int:
    """How many distinct functions the ledger has analysed in this mode."""
    try:
        import sqlite3
        from contextlib import closing

        with closing(sqlite3.connect(paths.cost_ledger_path())) as conn:
            row = conn.execute(
                "SELECT COUNT(DISTINCT run_id || '::' || COALESCE(function_name, rowid)) "
                "FROM cost_events WHERE phase = ?",
                (phase,),
            ).fetchone()
        return int(row[0]) if row and row[0] else 0
    except Exception:
        return 0


@router.get("")
def list_jobs() -> list[dict]:
    return manager.list()


@router.get("/active")
def active_job() -> Optional[dict]:
    job = manager.active()
    return job.public() if job else None


@router.get("/{job_id}")
def get_job(job_id: str) -> dict:
    job = manager.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No such job.")
    return job.public()


@router.get("/{job_id}/log")
def get_job_log(job_id: str) -> dict:
    job = manager.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No such job.")
    return {"id": job.id, "state": job.state, "lines": list(job.log)}


@router.post("/{job_id}/cancel")
def cancel_job(job_id: str) -> dict:
    job = manager.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No such job.")
    if not manager.cancel(job_id):
        raise HTTPException(status_code=409, detail="That job is not running.")
    return {"cancelled": True, "id": job_id}


@router.get("/{job_id}/events")
def job_events(job_id: str) -> StreamingResponse:
    job = manager.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No such job.")

    def event_stream():
        for event in manager.stream(job):
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            # Without this an intermediary can buffer the whole stream and the
            # progress bar only moves when the run is already finished.
            "X-Accel-Buffering": "no",
        },
    )
