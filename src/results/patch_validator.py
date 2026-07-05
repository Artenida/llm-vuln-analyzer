"""
Patch validation.
Applies a unified diff to an in-memory copy of the function's source only —
never touches the original file — then re-parses the result with tree-sitter
as a syntax check. Hunk context is matched with difflib to tolerate small
line-number drift from the LLM-generated diff.
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass
from typing import Optional

from src.ingestion.parser import TreeSitterParser

_FUZZY_MATCH_THRESHOLD = 0.85


class PatchApplyError(Exception):
    pass


@dataclass
class PatchValidationResult:
    valid: bool
    patched_code: Optional[str] = None
    error: Optional[str] = None


class PatchValidator:

    def __init__(self, parser: Optional[TreeSitterParser] = None):
        self.parser = parser or TreeSitterParser()

    def validate(self, original_code: str, unified_diff: str, language: str) -> PatchValidationResult:
        if not unified_diff or not unified_diff.strip():
            return PatchValidationResult(valid=False, error="empty_diff")

        try:
            patched_code = self._apply_patch(original_code, unified_diff)
        except PatchApplyError as e:
            return PatchValidationResult(valid=False, error=str(e))

        tree = self.parser.parse(patched_code, language)
        if tree is None:
            return PatchValidationResult(
                valid=False, patched_code=patched_code, error="unsupported_language_or_parse_failure"
            )
        if tree.root_node.has_error:
            return PatchValidationResult(
                valid=False, patched_code=patched_code, error="syntax_error_after_patch"
            )

        return PatchValidationResult(valid=True, patched_code=patched_code)

    # ── patch application ────────────────────────────────────────────────────

    def _apply_patch(self, original_code: str, unified_diff: str) -> str:
        hunks = self._parse_hunks(unified_diff)
        if not hunks:
            raise PatchApplyError("no_hunks_found")

        lines = original_code.splitlines(keepends=True)
        result = list(lines)
        search_start = 0

        for hunk in hunks:
            before, after = hunk["before"], hunk["after"]
            idx = self._locate(result, before, search_start)
            if idx is None:
                raise PatchApplyError("hunk_context_not_found")
            result[idx: idx + len(before)] = after
            search_start = idx + len(after)

        return "".join(result)

    def _parse_hunks(self, diff_text: str) -> list[dict]:
        hunks: list[dict] = []
        current: Optional[dict] = None

        for line in diff_text.splitlines():
            if line.startswith("@@"):
                if current is not None:
                    hunks.append(current)
                current = {"before": [], "after": []}
                continue
            if current is None:
                continue  # skip --- / +++ preamble before the first hunk
            if line.startswith("+++") or line.startswith("---") or line.startswith("\\"):
                continue
            if line.startswith("+"):
                current["after"].append(line[1:] + "\n")
            elif line.startswith("-"):
                current["before"].append(line[1:] + "\n")
            elif line.startswith(" "):
                text = line[1:] + "\n"
                current["before"].append(text)
                current["after"].append(text)
            elif line == "":
                current["before"].append("\n")
                current["after"].append("\n")

        if current is not None:
            hunks.append(current)
        return hunks

    def _locate(self, lines: list[str], target: list[str], search_start: int) -> Optional[int]:
        if not target:
            return search_start

        n, m = len(lines), len(target)
        if m > n:
            return None

        # exact match, scanning forward from where the previous hunk ended
        for i in range(search_start, n - m + 1):
            if lines[i:i + m] == target:
                return i

        # fallback: fuzzy match (tolerates whitespace drift in LLM-produced diffs)
        target_joined = "".join(t.strip() for t in target)
        best_ratio, best_idx = 0.0, None
        for i in range(0, n - m + 1):
            window_joined = "".join(l.strip() for l in lines[i:i + m])
            ratio = difflib.SequenceMatcher(None, target_joined, window_joined).ratio()
            if ratio > best_ratio:
                best_ratio, best_idx = ratio, i

        if best_idx is not None and best_ratio >= _FUZZY_MATCH_THRESHOLD:
            return best_idx
        return None
