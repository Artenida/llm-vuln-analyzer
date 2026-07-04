"""
Per-run cross-function memory for the ReAct agent.

Accumulated during a single analysis run so that later functions benefit from
findings already recorded for their callers/callees.  Not persisted to disk —
lifetime is one CLI invocation.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class FunctionFinding:
    node_id: str
    function_name: str
    vulnerability_found: bool
    cwe_id: str | None
    severity: str | None
    summary: str


class AgentMemory:
    """
    Stores lightweight vulnerability findings recorded during the current run.
    The agent can query this before analysing a new function to get context
    about already-analysed neighbours in the call graph.
    """

    def __init__(self) -> None:
        self._findings: dict[str, FunctionFinding] = {}

    # ── write ─────────────────────────────────────────────────────────────────

    def record(
        self,
        node_id: str,
        function_name: str,
        vulnerability_found: bool,
        cwe_id: str | None,
        severity: str | None,
        summary: str,
    ) -> None:
        self._findings[node_id] = FunctionFinding(
            node_id=node_id,
            function_name=function_name,
            vulnerability_found=vulnerability_found,
            cwe_id=cwe_id,
            severity=severity,
            summary=summary,
        )
        if vulnerability_found:
            logger.debug(
                "Memory recorded vuln in %s (%s %s)",
                function_name,
                cwe_id or "unknown CWE",
                severity or "?",
            )

    # ── read ──────────────────────────────────────────────────────────────────

    def get(self, node_id: str) -> FunctionFinding | None:
        return self._findings.get(node_id)

    def get_context_for(self, node_ids: list[str]) -> str:
        """
        Returns a human-readable summary of any prior findings for the given
        node_ids (callers or callees of the function being analysed).
        Returns empty string if none are recorded yet.
        """
        relevant = [
            f for nid in node_ids
            if (f := self._findings.get(nid)) is not None
        ]
        if not relevant:
            return ""

        lines = ["Prior findings for related functions:"]
        for f in relevant:
            status = f"VULNERABLE ({f.cwe_id}, {f.severity})" if f.vulnerability_found else "clean"
            lines.append(f"  {f.function_name}: {status} — {f.summary}")
        return "\n".join(lines)

    # ── introspection ─────────────────────────────────────────────────────────

    def vulnerable_count(self) -> int:
        return sum(1 for f in self._findings.values() if f.vulnerability_found)

    def __len__(self) -> int:
        return len(self._findings)
