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


# ─────────────────────────────────────────────────────────────────────────────
# Summary block
# ─────────────────────────────────────────────────────────────────────────────
#
# A ground truth file carries a hand-written `summary`. Nothing in `evaluate`
# reads it - metrics come from `functions[]` - but it is the block that gets
# quoted into a write-up, and it drifts: juice-shop's still read
# `vulnerable: 47` against 55 actual rows months after the verification pass
# added eight, and had no CWE-345 entry at all.
#
# These live here rather than in experiments/scripts so they are tracked, tested,
# and importable. `experiments/` is gitignored, so a test importing from there
# would pass locally and fail on a fresh clone.


def summary_vuln_id(entry: dict) -> str:
    """Mirrors GroundTruthEntry.vuln_id for a raw row dict."""
    if entry.get("duplicate_of"):
        return entry["duplicate_of"]
    lines = entry.get("source_lines") or []
    base = f"{entry.get('file')}::{entry.get('function_name')}"
    return f"{base}@{lines[0]}-{lines[-1]}" if lines else base


def compute_summary(functions: list) -> dict:
    """Every summary field derivable from the rows, whether or not a given
    dataset happens to use it."""
    from collections import Counter

    vuln = [e for e in functions if e.get("vulnerable")]
    clean = [e for e in functions if not e.get("vulnerable")]

    # A row counts as verified-clean if someone read it and recorded a clean
    # verdict. The ctf_integrity rows carry VERIFIED_CLEAN_OUT_OF_SCOPE_CTF -
    # read and verified, then scope-tagged - so a prefix match is the right
    # test; an exact one would report them as never read.
    verified_clean = [
        e for e in clean
        if str(e.get("verification_status") or "").startswith("VERIFIED_CLEAN")
    ]

    cwe_counts = dict(sorted(Counter(e.get("cwe_id") for e in vuln if e.get("cwe_id")).items()))
    sev_counts = Counter(e.get("severity") for e in vuln if e.get("severity"))

    return {
        "total_functions": len(functions),
        "total_functions_ground_truthed": len(functions),
        "vulnerable": len(vuln),
        "clean": len(clean),
        "vulnerable_in_scope": sum(1 for e in vuln if e.get("taxonomy_scope") == "in_scope"),
        "vulnerable_out_of_scope": sum(1 for e in vuln if e.get("taxonomy_scope") == "out_of_scope"),
        "clean_verified": len(verified_clean),
        "clean_or_not_applicable": len(clean),
        "unique_cwe_instances": len({summary_vuln_id(e) for e in vuln}),
        "duplicate_findings": sum(1 for e in vuln if e.get("duplicate_of")),
        "by_cwe": cwe_counts,
        "cwe_distribution": cwe_counts,
        "severity_distribution": {
            "high": sev_counts.get("high", 0),
            "medium": sev_counts.get("medium", 0),
            "low": sev_counts.get("low", 0),
        },
    }


def recompute_present_keys(stored: dict, functions: list) -> tuple:
    """Returns (updated summary, keys left untouched because they are not derivable).

    Only keys already in the file are recomputed. Datasets do not share a summary
    schema - juice-shop has `by_cwe`, auth-service has `cwe_distribution`, nodegoat
    has its own names again - so writing the full computed set would silently
    impose one dataset's schema on the others. Key order is preserved so applying
    the result produces a minimal diff.
    """
    computed = compute_summary(functions)
    updated: dict = {}
    unknown: list = []
    for key, value in stored.items():
        if key in computed:
            updated[key] = computed[key]
        else:
            updated[key] = value
            unknown.append(key)
    return updated, unknown
