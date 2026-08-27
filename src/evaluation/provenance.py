"""
Where a ground truth label came from.

`evaluate` treats all 55 juice-shop vulnerable rows alike, but they do not rest
on the same evidence. Eight were read and four of those confirmed by running an
exploit. The other 47 were taken from the application's own documentation of its
own flaws, which is a claim by someone else and therefore survives an objection
to this author's judgement. Reporting recall over the whole set hides that.

Rather than stamping the tiers by hand, they are derived from the checked-out
source, so the assignment is reproducible and can be re-run if the pin moves:

  PROJECT_DOCUMENTED_MARKER    a `vuln-code-snippet vuln-line` comment marks
                               these exact lines. The project asserts both the
                               vulnerability and its location. Strongest
                               external tier.
  PROJECT_DOCUMENTED_CHALLENGE the function references a `challenges.<key>`
                               defined in data/static/challenges.yml, so the
                               project documents the flaw; the attribution to
                               this function is this author's.
  AUTHOR_READ                  no project source. Established by reading alone.

Only rows with no `verification_status` are candidates. A row already stamped
VERIFIED_VULNERABLE was read, and in four cases exploited, which is a stronger
claim than either project tier and is never overwritten.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

MARKER_TIER = "PROJECT_DOCUMENTED_MARKER"
CHALLENGE_TIER = "PROJECT_DOCUMENTED_CHALLENGE"
AUTHOR_TIER = "AUTHOR_READ"

# `// vuln-code-snippet vuln-line <challengeKey> [<challengeKey>...]` — the
# project's own annotation of the exact vulnerable line. Deliberately excludes
# `neutral-line`, `hide-line` and the start/end range markers: those delimit the
# snippet shown to the player, and only `vuln-line` asserts a defect.
_VULN_LINE = re.compile(r"vuln-code-snippet\s+vuln-line\b")
_CHALLENGE_REF = re.compile(r"challenges\.([A-Za-z0-9_]+)")


def _read_lines(path: Path) -> Optional[list]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


def _span(entry) -> Optional[tuple]:
    """1-indexed [start, end] of the function, or None if the row has no range."""
    lines = getattr(entry, "source_lines", None) or []
    if len(lines) >= 2:
        return int(lines[0]), int(lines[-1])
    if len(lines) == 1:
        return int(lines[0]), int(lines[0])
    return None


def derive_tier(entry, source_root: str | Path, challenge_keys: Optional[set] = None) -> dict:
    """Classify one vulnerable ground truth row by the evidence behind its label.

    Returns the tier and the reason, so a stamped row can be checked without
    re-running this: the reason names the line the tier was read from.
    """
    root = Path(source_root)
    src = _read_lines(root / entry.file)
    if src is None:
        return {"tier": AUTHOR_TIER, "reason": f"source not found: {entry.file}"}

    span = _span(entry)
    if span is None:
        return {"tier": AUTHOR_TIER, "reason": "row carries no source_lines"}
    start, end = span
    # A vuln-line marker sits on the offending line itself, but Juice Shop also
    # puts one on the line that opens a multi-line statement. Widening by a line
    # on each side would start crediting neighbouring functions, so the span is
    # taken as-is and the marker must fall inside it.
    body = src[max(0, start - 1):end]

    for offset, line in enumerate(body):
        if _VULN_LINE.search(line):
            return {
                "tier": MARKER_TIER,
                "reason": f"{entry.file}:{start + offset} carries a vuln-code-snippet vuln-line marker",
            }

    for offset, line in enumerate(body):
        for key in _CHALLENGE_REF.findall(line):
            if challenge_keys is None or key in challenge_keys:
                return {
                    "tier": CHALLENGE_TIER,
                    "reason": f"{entry.file}:{start + offset} references challenges.{key}",
                }

    return {"tier": AUTHOR_TIER, "reason": "no marker or challenge reference in the function body"}


def load_challenge_keys(source_root: str | Path) -> set:
    """The `key:` values in data/static/challenges.yml.

    Parsed with a regex rather than a YAML dependency: one flat field is being
    read from a file the project controls, and adding PyYAML to the runtime for
    it would be the larger change.
    """
    path = Path(source_root) / "data" / "static" / "challenges.yml"
    lines = _read_lines(path)
    if lines is None:
        return set()
    keys = set()
    for line in lines:
        m = re.match(r"\s*key:\s*([A-Za-z0-9_]+)", line)
        if m:
            keys.add(m.group(1))
    return keys


def stamp_dataset(gt_path: str | Path, source_root: str | Path, apply: bool = False) -> dict:
    """Derive a tier for every unstamped vulnerable row.

    Defaults to a dry run. Only ever writes `verification_status` and
    `verification_reason`, and only onto rows where the first is absent —
    `vulnerable`, `cwe_id` and every other field are left untouched, because a
    provenance pass that could silently change a label would invalidate the
    answer key it is documenting.
    """
    import json

    gt_path = Path(gt_path)
    data = json.loads(gt_path.read_text(encoding="utf-8"))
    keys = load_challenge_keys(source_root)

    from src.evaluation.ground_truth import GroundTruthEntry

    changes = []
    for row in data.get("functions", []):
        if not row.get("vulnerable") or row.get("verification_status"):
            continue
        entry = GroundTruthEntry(
            function_name=row["function_name"],
            file=row["file"],
            vulnerable=True,
            source_lines=row.get("source_lines") or [],
        )
        verdict = derive_tier(entry, source_root, challenge_keys=keys)
        changes.append({
            "file": row["file"],
            "function_name": row["function_name"],
            **verdict,
        })
        if apply:
            row["verification_status"] = verdict["tier"]
            row["verification_reason"] = verdict["reason"]

    if apply and changes:
        gt_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

    counts: dict = {}
    for c in changes:
        counts[c["tier"]] = counts.get(c["tier"], 0) + 1
    return {"applied": apply, "rows": len(changes), "counts": counts, "changes": changes}
