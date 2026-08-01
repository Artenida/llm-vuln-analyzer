"""
Persistent, cross-run, cross-phase cost ledger.

Every REAL LLM API call this project makes, in every phase that spends money
(call-graph edge resolution, vulnerability analysis in any mode, patch
generation), gets exactly one row here — regardless of which CLI invocation
produced it, and regardless of which API key paid for it. This is the
cross-run view; a single run's own JSON stays the source of truth for that
run's own numbers.

Append-only: rows are inserted, never updated or deleted. A ledger write
failure (e.g. disk full, locked file) is logged and swallowed — cost
tracking must never be the reason an analysis run fails.
"""
from __future__ import annotations

import logging
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from src.llm.pricing import TokenUsage

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path(__file__).parent.parent.parent / "experiments" / "cost_ledger.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cost_events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           TEXT NOT NULL,
    provider            TEXT NOT NULL,
    api_key_alias       TEXT NOT NULL,
    model               TEXT NOT NULL,
    phase               TEXT NOT NULL,
    run_id              TEXT,
    dataset             TEXT,
    function_name       TEXT,
    prompt_tokens       INTEGER NOT NULL,
    completion_tokens   INTEGER NOT NULL,
    total_tokens        INTEGER NOT NULL,
    cost_usd            REAL
);
CREATE INDEX IF NOT EXISTS idx_cost_events_run_id        ON cost_events(run_id);
CREATE INDEX IF NOT EXISTS idx_cost_events_phase          ON cost_events(phase);
CREATE INDEX IF NOT EXISTS idx_cost_events_api_key_alias  ON cost_events(api_key_alias);
"""


@dataclass
class CostSummaryRow:
    group_key: str
    calls: int
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    # None if ANY event folded into this group has unknown cost (unpriced
    # model) — a partial sum would understate spend and look like a real
    # number, so the whole group degrades to "unknown" instead.
    cost_usd: Optional[float]


class CostLedger:
    """SQLite-backed event log. Cheap to construct — instantiate once per CLI
    invocation and share across LLMClient, PatchGenerator, and the call-graph
    edge resolver."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.executescript(_SCHEMA)
            conn.commit()

    # ── write ─────────────────────────────────────────────────────────────

    def record(
        self,
        provider: str,
        api_key_alias: str,
        model: str,
        phase: str,
        usage: TokenUsage,
        cost_usd: Optional[float],
        run_id: Optional[str] = None,
        dataset: Optional[str] = None,
        function_name: Optional[str] = None,
    ) -> None:
        try:
            with closing(sqlite3.connect(self.db_path)) as conn:
                conn.execute(
                    "INSERT INTO cost_events "
                    "(timestamp, provider, api_key_alias, model, phase, run_id, dataset, "
                    " function_name, prompt_tokens, completion_tokens, total_tokens, cost_usd) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        datetime.now().isoformat(),
                        provider, api_key_alias, model, phase, run_id, dataset, function_name,
                        usage.prompt_tokens, usage.completion_tokens, usage.total_tokens, cost_usd,
                    ),
                )
                conn.commit()
        except sqlite3.Error as e:
            logger.warning("Cost ledger write failed (%s) — continuing without it.", e)

    # ── read ──────────────────────────────────────────────────────────────

    def _query(self, group_col: str, where: str, params: tuple) -> list[CostSummaryRow]:
        sql = (
            f"SELECT {group_col}, COUNT(*), SUM(prompt_tokens), SUM(completion_tokens), "
            f"SUM(total_tokens), SUM(cost_usd), "
            f"SUM(CASE WHEN cost_usd IS NULL THEN 1 ELSE 0 END) "
            f"FROM cost_events {where} GROUP BY {group_col} ORDER BY {group_col}"
        )
        with closing(sqlite3.connect(self.db_path)) as conn:
            rows = conn.execute(sql, params).fetchall()
        return [
            CostSummaryRow(
                group_key=r[0] if r[0] is not None else "(unknown)",
                calls=r[1],
                prompt_tokens=r[2] or 0,
                completion_tokens=r[3] or 0,
                total_tokens=r[4] or 0,
                cost_usd=None if r[6] else (r[5] or 0.0),
            )
            for r in rows
        ]

    def by_phase(self, run_id: Optional[str] = None) -> list[CostSummaryRow]:
        if run_id:
            return self._query("phase", "WHERE run_id = ?", (run_id,))
        return self._query("phase", "", ())

    def by_api_key(self, run_id: Optional[str] = None) -> list[CostSummaryRow]:
        if run_id:
            return self._query("api_key_alias", "WHERE run_id = ?", (run_id,))
        return self._query("api_key_alias", "", ())

    def by_model(self, run_id: Optional[str] = None) -> list[CostSummaryRow]:
        if run_id:
            return self._query("model", "WHERE run_id = ?", (run_id,))
        return self._query("model", "", ())

    def by_run(self, limit: int = 20) -> list[CostSummaryRow]:
        """Most-recently-active run first. Ordered by each run's latest event
        timestamp, not by run_id — run_id embeds the model name before the
        timestamp, so sorting by it groups by model rather than by time."""
        sql = (
            "SELECT run_id, COUNT(*), SUM(prompt_tokens), SUM(completion_tokens), "
            "SUM(total_tokens), SUM(cost_usd), "
            "SUM(CASE WHEN cost_usd IS NULL THEN 1 ELSE 0 END), MAX(timestamp) AS last_seen "
            "FROM cost_events WHERE run_id IS NOT NULL "
            "GROUP BY run_id ORDER BY last_seen DESC"
        )
        if limit:
            sql += f" LIMIT {int(limit)}"
        with closing(sqlite3.connect(self.db_path)) as conn:
            rows = conn.execute(sql).fetchall()
        return [
            CostSummaryRow(
                group_key=r[0],
                calls=r[1],
                prompt_tokens=r[2] or 0,
                completion_tokens=r[3] or 0,
                total_tokens=r[4] or 0,
                cost_usd=None if r[6] else (r[5] or 0.0),
            )
            for r in rows
        ]

    def total(self, run_id: Optional[str] = None) -> CostSummaryRow:
        """Grand total across every event (optionally scoped to one run)."""
        where = "WHERE run_id = ?" if run_id else ""
        params = (run_id,) if run_id else ()
        sql = (
            f"SELECT COUNT(*), SUM(prompt_tokens), SUM(completion_tokens), SUM(total_tokens), "
            f"SUM(cost_usd), SUM(CASE WHEN cost_usd IS NULL THEN 1 ELSE 0 END) "
            f"FROM cost_events {where}"
        )
        with closing(sqlite3.connect(self.db_path)) as conn:
            r = conn.execute(sql, params).fetchone()
        if not r or r[0] == 0:
            return CostSummaryRow("total", 0, 0, 0, 0, 0.0)
        return CostSummaryRow(
            group_key="total",
            calls=r[0],
            prompt_tokens=r[1] or 0,
            completion_tokens=r[2] or 0,
            total_tokens=r[3] or 0,
            cost_usd=None if r[5] else (r[4] or 0.0),
        )
