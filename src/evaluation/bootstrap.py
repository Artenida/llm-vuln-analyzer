"""
Ground-truth scaffolding for a real repository.

Hand-writing a ground_truth.json is fine for a 25-function app. For a real
repo it is the bottleneck: the evaluator only counts a false positive when a
*clean* function has a row (findings with no row are excluded from the
confusion matrix entirely), so every function needs labelling — not just the
vulnerable ones. Precision is uncomputable otherwise.

This module emits the full skeleton: one row per extracted function, defaulted
to `vulnerable: false` and marked UNREVIEWED, so the remaining work is flipping
the known-vulnerable rows rather than transcribing hundreds of clean ones.

Given `--fix-commit`, it also pre-marks the functions a CVE's fixing commit
touched. Fix commits routinely bundle refactoring, tests and changelog edits,
so those rows are flagged for review rather than trusted — they are a starting
point for curation, never ground truth on their own.
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

UNREVIEWED = "UNREVIEWED — defaulted clean; confirm before using in evaluation"


def _rel_path(file_path: str, repo_root: Path) -> str:
    """Ground truth stores repo-relative paths; the evaluator matches a finding
    by checking its absolute file_path ends with this."""
    try:
        return Path(file_path).resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return Path(file_path).as_posix()


def changed_pre_image_ranges(repo_root: Path, commit: str) -> dict[str, list[tuple[int, int]]]:
    """Line ranges each file had *before* `commit` was applied, per file.

    The pre-image side is what matters: ground truth is built against the
    vulnerable checkout (the fix's parent), so the `-` side of each hunk is
    what maps onto the code actually being analysed.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_root), "show", "--unified=0", "--format=", commit],
            capture_output=True, text=True, check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.warning("Could not read commit %s from %s: %s", commit, repo_root, e)
        return {}

    ranges: dict[str, list[tuple[int, int]]] = {}
    current: Optional[str] = None

    for line in out.splitlines():
        if line.startswith("--- a/"):
            current = line[6:].strip()
        elif line.startswith("--- /dev/null"):
            current = None          # newly added file — nothing pre-existing to blame
        elif line.startswith("@@") and current:
            m = _HUNK_RE.match(line)
            if not m:
                continue
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            if count == 0:
                # pure insertion — no pre-image lines were modified
                continue
            ranges.setdefault(current, []).append((start, start + count - 1))

    return ranges


def _overlaps(a_start: int, a_end: int, ranges: list[tuple[int, int]]) -> bool:
    return any(not (a_end < r_start or a_start > r_end) for r_start, r_end in ranges)


def build_ground_truth(
    samples: list,
    skipped: list,
    repo_root: Path,
    dataset: str,
    source_path: str,
    fix_commits: Optional[list[str]] = None,
    description: str = "",
) -> dict:
    """Ground-truth skeleton covering every extracted function."""
    fix_commits = fix_commits or []

    # file -> changed pre-image ranges, unioned across every fix commit
    touched: dict[str, list[tuple[int, int]]] = {}
    commit_for_file: dict[str, list[str]] = {}
    for sha in fix_commits:
        for f, rs in changed_pre_image_ranges(repo_root, sha).items():
            touched.setdefault(f, []).extend(rs)
            commit_for_file.setdefault(f, []).append(sha[:10])

    functions = []
    flagged = 0

    for s in samples:
        rel = _rel_path(s.file_path, repo_root)
        is_touched = rel in touched and _overlaps(s.start_line, s.end_line, touched[rel])

        if is_touched:
            flagged += 1
            notes = (
                f"REVIEW REQUIRED — overlaps fix commit(s) "
                f"{', '.join(commit_for_file.get(rel, []))}. A fix commit also carries "
                f"refactoring/tests; confirm this function is the vulnerability before "
                f"trusting this row."
            )
        else:
            notes = UNREVIEWED

        functions.append({
            "function_name": s.function_name,
            "file": rel,
            "vulnerable": bool(is_touched),
            "cwe_id": None,          # must be filled in by hand — never inferred here
            "severity": None,
            "affected_lines": [],
            "notes": notes,
        })

    functions.sort(key=lambda e: (e["file"], e["function_name"]))

    total_seen = len(samples) + len(skipped)
    return {
        "schema_version": "1.0",
        "dataset": dataset,
        "description": description or f"Ground truth skeleton for {dataset} — REQUIRES CURATION.",
        "source_path": source_path,
        "curation_status": {
            "state": "skeleton",
            "reviewed": False,
            "fix_commits": fix_commits,
            "functions_prefilled_vulnerable": flagged,
            "functions_unreviewed": len(functions) - flagged,
            "instructions": (
                "Every row defaults to vulnerable=false. Confirm the REVIEW REQUIRED rows, "
                "set cwe_id/severity on each true vulnerability, then set reviewed=true. "
                "Rows left UNREVIEWED are treated as clean by `evaluate` and will be "
                "counted as false positives if the analyzer flags them."
            ),
        },
        "coverage": {
            "functions_extracted": len(samples),
            "functions_skipped_oversized": len(skipped),
            "coverage": round(len(samples) / total_seen, 4) if total_seen else 1.0,
            "note": (
                "Skipped functions have no ground truth row and are outside every "
                "metric. Report this coverage alongside any recall figure."
            ),
            "skipped_oversized": [
                {
                    "function_name": sk.name,
                    "file": _rel_path(sk.file_path, repo_root),
                    "line_count": sk.line_count,
                }
                for sk in skipped
            ],
        },
        "functions": functions,
        "summary": {
            "total_functions": len(functions),
            "vulnerable": flagged,
            "clean": len(functions) - flagged,
        },
    }


def save_ground_truth_skeleton(payload: dict, out_path: Path, force: bool = False) -> Path:
    """Writes the skeleton. Refuses to clobber an existing file unless `force`,
    because overwriting a curated ground truth destroys hand-labelling work
    that cannot be regenerated."""
    if out_path.exists() and not force:
        raise FileExistsError(
            f"{out_path} already exists — refusing to overwrite curated labels. "
            f"Pass --force only if you intend to discard them."
        )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return out_path
