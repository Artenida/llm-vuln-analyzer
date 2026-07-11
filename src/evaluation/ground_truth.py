"""
Ground truth dataset loading.
Mirrors the schema used by experiments/ground_truth/*.json (see docs/evaluation.md).
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

    @property
    def instance_id(self) -> str:
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
        )
        for e in data.get("functions", [])
    ]

    return GroundTruthDataset(
        dataset=data.get("dataset", p.stem),
        description=data.get("description", ""),
        source_path=data.get("source_path", ""),
        entries=entries,
    )
