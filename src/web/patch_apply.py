"""
Writing one validated patch into the analysed project, and taking it back out.

This is the only code in the web layer that modifies a file outside a result
directory, so every guard it needs lives here rather than in the router:

* **Opt-in, one finding at a time.** There is no "apply all". The user reviews a
  diff and applies that diff; nothing is written as a side effect of generating
  patches, opening a page, or running an analysis.
* **Only a patch that validated.** `patch_valid` is the tree-sitter parse check
  from `PatchValidator`; a diff that never parsed is not writable at all.
* **Only inside the analysed project.** The target must resolve within the run's
  own `source_path`. `file_path` arrives from the request, so without this the
  endpoint would be a write-anywhere oracle.
* **Only over code that still matches what was analysed.** The function is
  located by *content*, not by trusting the recorded line numbers — see
  `locate_block`. If the text has changed since extraction the write is refused,
  never guessed at.

Every applied patch is journalled to `applied_patches.json` in the result
directory, holding the exact bytes replaced. That is what makes the write
reversible, and it lives with the results rather than as a `.bak` littered
through the user's project.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from src.web import paths, results

# Deliberately not `applied_patches.json`: `results.patch_file()` finds a run's
# patch artifact with a `*_patches.json` glob and takes the newest match, so a
# journal named that way would be picked up as the patch document itself the
# moment the first patch was applied.
APPLIED_FILE = "patches_applied.json"


class ApplyError(Exception):
    """A patch could not be written, with a reason meant for the user."""


def _key(file_path: str, function_name: str) -> str:
    return f"{file_path.replace(chr(92), '/')}::{function_name}"


# ── the journal ───────────────────────────────────────────────────────────────


def applied_path(directory: Path) -> Path:
    return directory / APPLIED_FILE


def load_applied(directory: Path) -> list[dict]:
    """Patches currently written into the source tree, newest state per function.

    Reverted entries are kept with `"state": "reverted"` rather than deleted —
    "this was applied and undone" is a different fact from "never applied", and
    the user should be able to see it.
    """
    data = paths.read_json(applied_path(directory))
    return [e for e in data if isinstance(e, dict)] if isinstance(data, list) else []


def _find_entry(entries: list[dict], file_path: str, function_name: str) -> Optional[dict]:
    wanted = _key(file_path, function_name)
    for entry in entries:
        if _key(entry.get("file_path", ""), entry.get("function_name", "")) == wanted:
            return entry
    return None


def _save(directory: Path, entries: list[dict]) -> None:
    paths.write_json(applied_path(directory), entries)


# ── locating the function in the file as it is now ────────────────────────────


def locate_block(text: str, block: str, hint_line: Optional[int]) -> int:
    """Offset of `block` in `text`, or raise.

    Line numbers alone are not trustworthy here. Applying one patch shifts every
    function below it in the same file, so by the second apply the recorded
    range can point at unrelated code — and overwriting a line range without
    checking what is on those lines is how a "fix" silently deletes something
    else. So the recorded line is only a hint: the text must match there, and if
    it does not, the block has to be findable exactly once elsewhere.
    """
    lines = text.splitlines(keepends=True)
    if hint_line and 1 <= hint_line <= len(lines):
        line_start = sum(len(line) for line in lines[:hint_line - 1])
        # tree-sitter reports a node from its first *column*, so an indented
        # function's recorded source has no leading indent on line one while
        # the file does. Step over it rather than failing the comparison.
        indent = 0
        while line_start + indent < len(text) and text[line_start + indent] in " \t":
            indent += 1
        if text.startswith(block, line_start + indent):
            return line_start + indent

    occurrences = text.count(block)
    if occurrences == 1:
        return text.index(block)
    if occurrences == 0:
        raise ApplyError(
            "The function no longer matches what was analysed — the file has "
            "been edited since this run. Re-analyse before applying."
        )
    raise ApplyError(
        f"That function body appears {occurrences} times in the file, so there "
        "is no single place this patch belongs. Apply it by hand."
    )


def _match_line_endings(reference: str, block: str) -> str:
    """Give `block` the line endings `reference` uses.

    Applied to both sides of the splice, for two different reasons. The patched
    code comes back from the model as `\\n` text, and splicing that into a CRLF
    file leaves mixed endings — a whole-file diff in the user's editor that
    buries the one change actually made. The *original* needs it too: a file
    checked out again under a different `core.autocrlf`, or normalised by an
    editor, is byte-different from what was extracted while being the same code,
    and matching on raw bytes alone would refuse every patch in that project.
    """
    if "\r\n" in reference and "\r\n" not in block:
        return block.replace("\n", "\r\n")
    if "\r\n" not in reference and "\r\n" in block:
        return block.replace("\r\n", "\n")
    return block


def _read(target: Path) -> str:
    # newline="" so line endings survive the round trip. Path.read_text would
    # translate CRLF to LF on the way in and write LF back out, rewriting every
    # line of the file to change one function.
    try:
        with open(target, "r", encoding="utf-8", newline="") as handle:
            return handle.read()
    except UnicodeDecodeError as exc:
        raise ApplyError(f"{target.name} is not UTF-8, so it cannot be patched safely: {exc}")
    except OSError as exc:
        raise ApplyError(f"Could not read {target}: {exc}")


def _write(target: Path, text: str) -> None:
    try:
        with open(target, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
    except OSError as exc:
        raise ApplyError(f"Could not write {target}: {exc}")


def _splice(target: Path, old_block: str, new_block: str, hint_line: Optional[int]) -> dict:
    text = _read(target)
    # Both sides move to the file's own line endings before anything is searched
    # for or written, so the match and the splice share one convention.
    old_block = _match_line_endings(text, old_block)
    new_block = _match_line_endings(text, new_block)
    offset = locate_block(text, old_block, hint_line)
    _write(target, text[:offset] + new_block + text[offset + len(old_block):])
    return {
        "line": text.count("\n", 0, offset) + 1,
        "old_block": old_block,
        "new_block": new_block,
    }


# ── the guards ────────────────────────────────────────────────────────────────


def _source_root(directory: Path, patch_doc: dict) -> Path:
    raw = patch_doc.get("source_path") or results.summary(directory).get("source_path")
    if not raw:
        raise ApplyError(
            "This run does not record which project it analysed, so there is no "
            "safe way to tell which files it may write to."
        )
    root = paths.normalise(str(raw))
    if not root.exists():
        raise ApplyError(f"The analysed project is not at {root} any more.")
    return root


def _resolve_target(record: dict, root: Path) -> Path:
    raw = record.get("file_path")
    if not raw:
        raise ApplyError("That patch has no file path recorded.")
    target = paths.normalise(str(raw))
    if not paths.is_within(target, root):
        # The record is read from the run's own patch artifact rather than from
        # the request, so this should be unreachable — which is exactly why it
        # is worth failing loudly if it ever fires.
        raise ApplyError(f"{target} is outside the analysed project ({root}).")
    if not target.is_file():
        raise ApplyError(f"{target} no longer exists.")
    return target


def _record_for(patch_doc: dict, file_path: str, function_name: str) -> dict:
    wanted = _key(file_path, function_name)
    for record in patch_doc.get("patches") or []:
        if _key(record.get("file_path", ""), record.get("function_name", "")) == wanted:
            return record
    raise ApplyError(f"No generated patch for {function_name} in {file_path}.")


def _original_source(directory: Path, record: dict) -> str:
    """The function exactly as it was sent to the model.

    Read from `extraction.json`, not re-derived from the diff: it is the same
    text `PatchValidator` produced `patched_code` from, so a byte-for-byte match
    against the file proves the code on disk is what was actually analysed.
    """
    entry = results.function_source(
        directory, record.get("file_path") or "", record.get("function_name") or ""
    )
    code = (entry or {}).get("code")
    if not code:
        raise ApplyError(
            "The original source for this function is not in this run's "
            "extraction.json, so there is nothing to verify the file against."
        )
    return code


# ── the operations ────────────────────────────────────────────────────────────


def apply_patch(directory: Path, file_path: str, function_name: str) -> dict:
    patch_doc = results.patches(directory)
    if not patch_doc:
        raise ApplyError("No patches have been generated for this run.")

    record = _record_for(patch_doc, file_path, function_name)
    if record.get("patch_valid") is not True:
        raise ApplyError(
            "This patch did not pass the syntax check, so it will not be "
            "written. " + (record.get("patch_error") or "")
        )
    patched_code = record.get("patched_code")
    if not patched_code:
        raise ApplyError("This patch has no patched code to write.")

    entries = load_applied(directory)
    existing = _find_entry(entries, record["file_path"], function_name)
    if existing and existing.get("state") == "applied":
        raise ApplyError(f"{function_name} is already patched in the source file.")

    root = _source_root(directory, patch_doc)
    target = _resolve_target(record, root)
    original = _original_source(directory, record)

    spliced = _splice(target, original, patched_code, record.get("start_line"))

    entry = {
        "function_name": function_name,
        "file_path": str(target),
        "cwe_id": record.get("cwe_id"),
        "severity": record.get("severity"),
        "state": "applied",
        "applied_at": datetime.now().isoformat(timespec="seconds"),
        "reverted_at": None,
        "line": spliced["line"],
        # The bytes on both sides of the edit. This is what revert restores, and
        # what makes the write undoable without touching the user's project.
        "original_code": spliced["old_block"],
        "patched_code": spliced["new_block"],
    }
    if existing:
        entries[entries.index(existing)] = entry
    else:
        entries.append(entry)
    _save(directory, entries)
    return entry


def revert_patch(directory: Path, file_path: str, function_name: str) -> dict:
    entries = load_applied(directory)
    entry = _find_entry(entries, file_path, function_name)
    if entry is None or entry.get("state") != "applied":
        raise ApplyError(f"{function_name} is not currently patched.")

    target = paths.normalise(entry["file_path"])
    if not target.is_file():
        raise ApplyError(f"{target} no longer exists.")

    # Reverting looks for the patched text, not the original: the patched block
    # is what is in the file now. `line` is only a hint, for the same reason it
    # is only a hint on the way in.
    spliced = _splice(target, entry["patched_code"], entry["original_code"], entry.get("line"))

    reverted = {
        **entry,
        "state": "reverted",
        "reverted_at": datetime.now().isoformat(timespec="seconds"),
        "line": spliced["line"],
    }
    entries[entries.index(entry)] = reverted
    _save(directory, entries)
    return reverted


def status(directory: Path) -> dict[str, Any]:
    """Applied/reverted state for the whole run, for the patches table."""
    entries = load_applied(directory)
    return {
        "entries": entries,
        "applied_count": sum(1 for e in entries if e.get("state") == "applied"),
    }
