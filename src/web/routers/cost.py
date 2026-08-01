"""
The cost dashboard.

Straight from `CostLedger`, which is already the source of truth for the CLI's
`cost` command — so the dashboard can never quote a figure the CLI would
disagree with.

The ledger's rule that a group's cost is `None` when *any* event in it used a
model missing from the pricing table is preserved end to end: a partial sum
would understate spend while looking like a real number.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from src.web import jobs as job_module
from src.web import paths

router = APIRouter(prefix="/cost", tags=["cost"])


def _ledger():
    """Open the ledger, or None if it does not exist.

    `CostLedger.__init__` creates the database, so constructing one just to read
    would mean opening the dashboard writes a file. An absent ledger is reported
    as absent instead.
    """
    if not paths.cost_ledger_path().is_file():
        return None
    try:
        from src.llm.cost_ledger import CostLedger

        return CostLedger(str(paths.cost_ledger_path()))
    except Exception:
        return None


def _row(row) -> dict:
    return {
        "group_key": row.group_key,
        "calls": row.calls,
        "prompt_tokens": row.prompt_tokens,
        "completion_tokens": row.completion_tokens,
        "total_tokens": row.total_tokens,
        "cost_usd": row.cost_usd,
    }


@router.get("")
def cost_summary(run_id: Optional[str] = Query(None)) -> dict:
    ledger = _ledger()
    if ledger is None:
        return {
            "available": False,
            "ledger_path": str(paths.cost_ledger_path()),
            "total": None,
            "by_phase": [],
            "by_model": [],
            "by_api_key": [],
        }
    return {
        "available": True,
        "ledger_path": str(paths.cost_ledger_path()),
        "total": _row(ledger.total(run_id=run_id)),
        "by_phase": [_row(r) for r in ledger.by_phase(run_id=run_id)],
        "by_model": [_row(r) for r in ledger.by_model(run_id=run_id)],
        "by_api_key": [_row(r) for r in ledger.by_api_key(run_id=run_id)],
    }


@router.get("/runs")
def cost_by_run(limit: int = Query(25, ge=1, le=200)) -> list[dict]:
    ledger = _ledger()
    return [_row(r) for r in ledger.by_run(limit=limit)] if ledger else []


# ── history ───────────────────────────────────────────────────────────────────
# Lives here rather than in its own module: History is the dashboard's "what did
# I run" half, and it is a dozen lines.

history_router = APIRouter(prefix="/history", tags=["history"])


class OpenRequest(BaseModel):
    path: str


@history_router.get("")
def list_history() -> list[dict]:
    """Every result this install can see.

    Merges what was recorded with a scan of the workspace, so losing the
    registry file — or copying a workspace over from another machine — does not
    make results disappear.
    """
    return job_module.discover_history()


@history_router.post("/open")
def open_results(request: OpenRequest) -> dict:
    """Add a results folder produced elsewhere (another machine, or the CLI)."""
    try:
        directory = paths.normalise(request.path)
    except paths.UnsafePathError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    try:
        return job_module.remember_result_dir(directory)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@history_router.delete("/{entry_id}")
def forget(entry_id: str) -> dict:
    """Remove an entry from the list. The result files are never deleted."""
    return {"forgotten": job_module.forget_history(entry_id)}
