"""
Ground truth dataset loading.
Mirrors the schema used by experiments/datasets/<name>/ground_truth.json (see docs/evaluation.md).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class GroundTruthEntry:
    function_name: str
    file: str
    vulnerable: bool
    cwe_id: Optional[str] = None
    severity: Optional[str] = None
    affected_lines: list = field(default_factory=list)
    notes: str = ""
    duplicate_of: Optional[str] = None  # "<file>::<function_name>" of the canonical instance
    # [start, end] of the function in the source. Optional: datasets written
    # before this existed have none, and everything falls back to name+file.
    source_lines: list = field(default_factory=list)

    @property
    def instance_id(self) -> str:
        # file::name is not unique in real code (four `set` setters in one
        # Juice Shop model). Where a line range is known, include it so each
        # row has an id of its own — without it, four rows share one id and a
        # single finding is scored against all four. Rows with no line range
        # keep the old format, so ids and `duplicate_of` references in
        # pre-existing datasets are untouched.
        if self.source_lines:
            return f"{self.file}::{self.function_name}@{self.source_lines[0]}-{self.source_lines[-1]}"
        return f"{self.file}::{self.function_name}"

    @property
    def vuln_id(self) -> str:
        """Groups duplicate plantings of the same logical vulnerability across files."""
        return self.duplicate_of or self.instance_id


@dataclass
class GroundTruthDataset:
    dataset: str
    description: str
    source_path: str
    entries: list  # list[GroundTruthEntry]
    # Present only on files scaffolded by `bootstrap-ground-truth`. A skeleton
    # defaults every row to clean, so scoring against one before curation
    # produces meaningless numbers rather than an obvious error.
    curation_status: dict = field(default_factory=dict)

    @property
    def needs_curation(self) -> bool:
        return bool(self.curation_status) and not self.curation_status.get("reviewed", False)


def load_ground_truth(path: str | Path) -> GroundTruthDataset:
    p = Path(path)
    with open(p, encoding="utf-8") as f:
        data = json.load(f)

    entries = [
        GroundTruthEntry(
            function_name=e["function_name"],
            file=e["file"],
            vulnerable=bool(e.get("vulnerable", False)),
            cwe_id=e.get("cwe_id"),
            severity=e.get("severity"),
            affected_lines=e.get("affected_lines") or [],
            notes=e.get("notes", ""),
            duplicate_of=e.get("duplicate_of"),
            source_lines=e.get("source_lines") or [],
        )
        for e in data.get("functions", [])
    ]

    return GroundTruthDataset(
        dataset=data.get("dataset", p.stem),
        description=data.get("description", ""),
        source_path=data.get("source_path", ""),
        entries=entries,
        curation_status=data.get("curation_status", {}) or {},
    )
