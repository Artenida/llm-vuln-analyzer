"""
Incremental run persistence.

The analysis loop is sequential and, until this existed, nothing was written
until every function had been analysed. A run that died at function 300 of 379
— rate limit, network drop, closed laptop, Ctrl-C — lost all 300 results and
had to be paid for again from zero. On a small fixture app that is an
annoyance; on a few-hundred-function repository it is the difference between an
interrupted run costing nothing and costing the whole run.

This module appends one JSON line per completed function to a checkpoint file
next to the run's other artifacts, so an interrupted run can be resumed with
`analyze --resume` and only pays for what is actually left.

Resuming the *wrong* checkpoint would be worse than not resuming at all: it
would silently skip functions that were never analysed and report the result as
a complete run. So the file carries a header describing the run that wrote it,
and `load_completed()` refuses to resume when it does not match — including a
per-index check that the sample at position i is still the same function.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional

from src.llm.client import VulnerabilityReport
from src.llm.pricing import TokenUsage

logger = logging.getLogger(__name__)

CHECKPOINT_FILENAME = "checkpoint.jsonl"


class CheckpointMismatch(Exception):
    """The checkpoint on disk was written by a different run than the one
    asking to resume it."""


@dataclass(frozen=True)
class CheckpointHeader:
    """Identity of the run that wrote a checkpoint.

    Deliberately excludes run_id: a resumed run is a new invocation with a new
    run_id, so comparing it would make every resume look like a mismatch. What
    must match is the *work* — same code, same model, same mode, same number of
    functions in the same order.
    """
    model: str
    source_path: str
    analysis_mode: str
    total_samples: int

    def to_dict(self) -> dict:
        return {"kind": "header", **asdict(self)}

    @classmethod
    def from_dict(cls, d: dict) -> "CheckpointHeader":
        return cls(
            model=d.get("model", ""),
            source_path=d.get("source_path", ""),
            analysis_mode=d.get("analysis_mode", ""),
            total_samples=int(d.get("total_samples", 0)),
        )

    def describe_difference(self, other: "CheckpointHeader") -> str:
        diffs = [
            f"{field}: checkpoint has {getattr(self, field)!r}, this run has {getattr(other, field)!r}"
            for field in ("model", "source_path", "analysis_mode", "total_samples")
            if getattr(self, field) != getattr(other, field)
        ]
        return "; ".join(diffs)


def _report_to_dict(report: VulnerabilityReport) -> dict:
    d = asdict(report)          # recurses into the nested TokenUsage
    return d


def _report_from_dict(d: dict) -> VulnerabilityReport:
    d = dict(d)
    usage = d.pop("token_usage", None) or {}
    return VulnerabilityReport(**d, token_usage=TokenUsage(**usage))


class RunCheckpoint:
    """Append-only record of the functions a run has already analysed."""

    def __init__(self, folder: str | Path, filename: str = CHECKPOINT_FILENAME):
        self.path = Path(folder) / filename

    @property
    def exists(self) -> bool:
        return self.path.exists()

    # ── writing ──────────────────────────────────────────────────────────────

    def start(self, header: CheckpointHeader) -> None:
        """Create the file with its header, unless it already exists (in which
        case we are resuming and the existing header stands)."""
        if self.exists:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(json.dumps(header.to_dict()) + "\n")

    def append(self, index: int, report: VulnerabilityReport) -> None:
        """Record one completed function. Flushed immediately — a checkpoint
        still sitting in a buffer when the process dies protects nothing."""
        record = {
            "kind": "report",
            "index": index,
            "function_name": report.function_name,
            "file_path": report.file_path,
            "report": _report_to_dict(report),
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
            f.flush()

    def clear(self) -> None:
        if self.exists:
            self.path.unlink()

    # ── reading ──────────────────────────────────────────────────────────────

    def read_header(self) -> Optional[CheckpointHeader]:
        if not self.exists:
            return None
        with open(self.path, encoding="utf-8") as f:
            first = f.readline()
        if not first.strip():
            return None
        try:
            return CheckpointHeader.from_dict(json.loads(first))
        except (json.JSONDecodeError, ValueError):
            return None

    def load_completed(
        self,
        header: CheckpointHeader,
        samples: Optional[Iterable] = None,
    ) -> dict:
        """Returns {sample_index: VulnerabilityReport} for already-completed functions.

        Raises CheckpointMismatch if the checkpoint belongs to a different run,
        or if `samples` is given and a recorded function no longer sits at the
        index it was recorded at — a partially resumed run that skipped the
        wrong functions would report itself as complete.
        """
        on_disk = self.read_header()
        if on_disk is None:
            raise CheckpointMismatch(
                f"{self.path} has no readable header — it was not written by this tool, "
                "or was truncated. Delete it and start a fresh run."
            )
        if on_disk != header:
            raise CheckpointMismatch(
                f"{self.path} was written by a different run — {on_disk.describe_difference(header)}. "
                "Resuming it would skip functions that were never analysed. Delete it "
                "to start over, or point --run-name at the run it belongs to."
            )

        sample_list = list(samples) if samples is not None else None
        completed: dict = {}
        truncated = 0

        with open(self.path, encoding="utf-8") as f:
            next(f, None)  # header
            for line_no, line in enumerate(f, start=2):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    # A process killed mid-write leaves a half-line. It is
                    # always the last one, and the function it describes simply
                    # gets re-analysed — no reason to fail the whole resume.
                    truncated += 1
                    logger.warning(
                        "Ignoring incomplete checkpoint record at %s:%d "
                        "(process interrupted mid-write); that function will be re-analysed.",
                        self.path, line_no,
                    )
                    continue

                if rec.get("kind") != "report":
                    continue
                index = rec.get("index")
                if index is None:
                    continue

                if sample_list is not None:
                    if index >= len(sample_list):
                        raise CheckpointMismatch(
                            f"{self.path} records index {index} but this run only has "
                            f"{len(sample_list)} functions. The source has changed — "
                            "delete the checkpoint and start over."
                        )
                    sample = sample_list[index]
                    if (sample.function_name != rec.get("function_name")
                            or sample.file_path != rec.get("file_path")):
                        raise CheckpointMismatch(
                            f"{self.path} records {rec.get('function_name')!r} in "
                            f"{rec.get('file_path')!r} at index {index}, but that position now "
                            f"holds {sample.function_name!r} in {sample.file_path!r}. The source "
                            "changed since the checkpoint was written — delete it and start over."
                        )

                try:
                    completed[index] = _report_from_dict(rec["report"])
                except (TypeError, KeyError) as e:
                    truncated += 1
                    logger.warning(
                        "Skipping unreadable checkpoint record at %s:%d (%s); "
                        "that function will be re-analysed.", self.path, line_no, e,
                    )

        return completed
