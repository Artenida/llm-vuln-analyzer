"""
Path resolution and safety.

Results no longer live in one fixed tree — the user chooses an output directory
per analysis — so containment is enforced against a *registry* of directories
the user has actually used, rather than a single hardcoded root. Every
filesystem path derived from a request goes through this module.

Two distinct rules, deliberately different:

* **Artifact reads** (`resolve_result_dir`, `resolve_artifact`) must land inside
  a registered result directory, and only on known artifact filenames. The API
  is not a general file-read oracle.
* **Directory browsing** (`is_listable_dir`) may list anywhere, because picking
  a folder to analyse is the whole point of the picker. It returns names and
  types only — never file contents.
"""
from __future__ import annotations

import json
import os
import string
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]

def ui_state_dir() -> Path:
    """Where the UI keeps its own state (settings, history, root registry).

    Separate from experiments/ so the thesis tree is untouched by using the UI.
    Overridable with VULN_ANALYZER_UI_STATE so tests never touch real state —
    deleting a user's run history to run a test is not an acceptable trade.
    """
    override = os.environ.get("VULN_ANALYZER_UI_STATE")
    return Path(override).resolve() if override else PROJECT_ROOT / ".vulnui"


# Kept as a module attribute for readability at call sites; resolved lazily
# everywhere it matters via ui_state_dir().
UI_STATE_DIR = ui_state_dir()

# Artifacts an analysis run writes. Reads are restricted to this set so a
# registered directory cannot be used to fish for unrelated files that happen
# to sit beside a result.
RUN_ARTIFACTS = {
    "analysis.json",
    "extraction.json",
    "call_graph.json",
    "call_graph.dot",
    "call_graph.html",
    "call_graph_annotated.html",
    "checkpoint.jsonl",
    "patches.json",
}

# A directory is recognisable as a result bundle if it holds any of these.
RESULT_MARKERS = ("analysis.json", "extraction.json", "call_graph.json")


class UnsafePathError(ValueError):
    """Raised when a request-derived path is refused."""


def experiments_root() -> Path:
    override = os.environ.get("VULN_ANALYZER_EXPERIMENTS")
    return Path(override).resolve() if override else PROJECT_ROOT / "experiments"


def cost_ledger_path() -> Path:
    return experiments_root() / "cost_ledger.db"


def env_file() -> Path:
    """The .env the CLI already loads — where a key set in the UI is written."""
    return PROJECT_ROOT / ".env"


def default_results_root() -> Path:
    return PROJECT_ROOT / "results"


# ── generic helpers ───────────────────────────────────────────────────────────


def normalise(raw: str) -> Path:
    """User-supplied path → absolute, resolved Path.

    Accepts either separator and expands `~`, because a path typed into the UI
    on Windows may arrive with forward slashes from the picker and backslashes
    from a paste.
    """
    if not raw or not raw.strip():
        raise UnsafePathError("Empty path")
    try:
        return Path(os.path.expanduser(raw.strip())).resolve()
    except (OSError, ValueError) as exc:
        raise UnsafePathError(f"Unusable path: {exc}") from exc


def is_within(child: Path, parent: Path) -> bool:
    try:
        child = child.resolve()
        parent = parent.resolve()
    except OSError:
        return False
    return child == parent or parent in child.parents


def safe_join(base: Path, name: str) -> Path:
    """Join one request-supplied filename onto `base`, refusing to escape it."""
    if not name or name in (".", "..") or "/" in name or "\\" in name or os.path.isabs(name):
        raise UnsafePathError(f"Illegal filename: {name!r}")
    candidate = (base / name).resolve()
    if not is_within(candidate, base):
        raise UnsafePathError("Path escapes its directory")
    return candidate


# ── result-directory registry ─────────────────────────────────────────────────
#
# Populated by the job runner (every analysis registers its output directory)
# and by history. Reads are confined to it.


def _registry_file() -> Path:
    return ui_state_dir() / "roots.json"


def registered_roots() -> list[Path]:
    roots = [default_results_root(), experiments_root()]
    data = read_json(_registry_file())
    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, str):
                try:
                    roots.append(Path(entry))
                except (OSError, ValueError):
                    continue
    return roots


def register_root(directory: Path) -> None:
    """Remember a directory the user wrote results into, so it can be read back.

    Registering the directory itself rather than its parent keeps the readable
    surface as small as possible: choosing `D:\\work\\scan1` as an output does
    not make the whole of `D:\\work` readable.
    """
    directory = directory.resolve()
    if any(is_within(directory, root) for root in (default_results_root(), experiments_root())):
        return  # already covered by a standing root

    ui_state_dir().mkdir(parents=True, exist_ok=True)
    existing = read_json(_registry_file())
    entries = [e for e in existing if isinstance(e, str)] if isinstance(existing, list) else []
    value = str(directory)
    if value not in entries:
        entries.append(value)
        write_json(_registry_file(), entries)


def resolve_result_dir(raw: str) -> Path:
    """Validate a result-directory path from a request."""
    directory = normalise(raw)
    if not directory.is_dir():
        raise UnsafePathError("No such directory")
    if not any(is_within(directory, root) for root in registered_roots()):
        raise UnsafePathError(
            "That directory is not a known result location. Results are readable "
            "only from directories this tool has written to."
        )
    return directory


def resolve_artifact(raw_dir: str, name: str) -> Path:
    """Validate `<result dir>/<artifact>` from a request."""
    if name not in RUN_ARTIFACTS:
        raise UnsafePathError(f"Not a run artifact: {name!r}")
    return safe_join(resolve_result_dir(raw_dir), name)


def looks_like_result_dir(directory: Path) -> bool:
    return any((directory / marker).is_file() for marker in RESULT_MARKERS)


# ── directory browsing ────────────────────────────────────────────────────────


def is_listable_dir(directory: Path) -> bool:
    return directory.is_dir()


def filesystem_roots() -> list[dict[str, str]]:
    """Starting points for the folder picker."""
    roots: list[dict[str, str]] = [
        {"label": "Project", "path": str(PROJECT_ROOT)},
        {"label": "Home", "path": str(Path.home())},
    ]
    if os.name == "nt":
        for letter in string.ascii_uppercase:
            drive = Path(f"{letter}:\\")
            if drive.exists():
                roots.append({"label": f"{letter}:\\", "path": str(drive)})
    else:
        roots.append({"label": "/", "path": "/"})
    return roots


# ── json helpers ──────────────────────────────────────────────────────────────


def read_json(path: Path) -> Optional[Any]:
    """Load JSON, or None if absent or unreadable.

    A missing artifact is normal (a dry run has no analysis.json), so absence is
    not an error. A malformed one degrades the same way rather than failing a
    page that renders a dozen other things.
    """
    if not path.is_file():
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
    tmp.replace(path)  # atomic — a crash mid-write must not truncate the file


def read_jsonl(path: Path) -> list[Any]:
    """Load JSON lines, skipping bad ones.

    A checkpoint is appended to while a run is in flight, so its last line can
    legitimately be a partial write.
    """
    if not path.is_file():
        return []
    records: list[Any] = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except (OSError, UnicodeDecodeError):
        pass
    return records


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)
