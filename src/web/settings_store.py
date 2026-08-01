"""
UI settings, and the OpenAI API key.

**The key lives in the user's workspace, not in the repository.** This is a page
other people are meant to use, and someone who has never seen the source should
not have to know that a `.env` exists in a checkout somewhere. So the key is
written to a `.key` file inside the workspace folder they picked — the same
folder their results go to — and the whole workspace is portable: move it, and
the key and the results move with it.

Resolution order, most specific first:

1. ``<workspace>/.openai.key``            (or ``.openai.<alias>.key``)
2. ``OPENAI_API_KEY`` in the environment  (or ``OPENAI_API_KEY_<ALIAS>``)

The environment is kept as a *read-only fallback* so an existing CLI setup keeps
working, and so a deployment can inject a key without a file. Nothing here ever
writes to `.env`.

The key value is never returned to the browser: `api_key_status()` reports only
whether one is configured, where it came from, and a masked preview.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from src.web import paths

logger = logging.getLogger(__name__)

def settings_file() -> Path:
    return paths.ui_state_dir() / "settings.json"

DEFAULT_ALIAS = "default"

_ALIAS_RE = re.compile(r"^[A-Za-z0-9_]{1,32}$")

# What the workspace .gitignore gets, so a key can never be committed by someone
# who keeps their workspace inside a repository.
_GITIGNORE_LINES = (
    "# Written by llm-vuln-analyzer — these hold API keys in plain text.",
    ".openai.key",
    ".openai.*.key",
)


def _validate_alias(alias: Optional[str]) -> str:
    if not alias or alias == DEFAULT_ALIAS:
        return DEFAULT_ALIAS
    if not _ALIAS_RE.match(alias):
        raise ValueError(
            "An API key name may only contain letters, digits and underscores."
        )
    return alias


def env_var_for_alias(alias: Optional[str] = None) -> str:
    """The environment variable an alias falls back to, matching `AppConfig`."""
    alias = _validate_alias(alias)
    return "OPENAI_API_KEY" if alias == DEFAULT_ALIAS else f"OPENAI_API_KEY_{alias.upper()}"


# ── settings ──────────────────────────────────────────────────────────────────


@dataclass
class UISettings:
    """Defaults the Analyze form is pre-filled from.

    `results_root` is the **workspace**: results and the API key both live there.
    """

    model: str = "o4-mini"
    react: bool = True
    max_steps: int = 5
    max_function_lines: int = 200
    visualize: bool = True
    budget_usd: Optional[float] = 5.0
    api_key_alias: str = DEFAULT_ALIAS
    results_root: str = ""
    skip_dirs: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.results_root:
            self.results_root = str(paths.default_results_root())


def load_settings() -> UISettings:
    data = paths.read_json(settings_file())
    if not isinstance(data, dict):
        return UISettings()
    known = set(UISettings.__dataclass_fields__)
    # Unknown keys are dropped rather than raising: a settings file written by a
    # newer build must not brick an older one.
    return UISettings(**{k: v for k, v in data.items() if k in known})


def save_settings(settings: UISettings) -> UISettings:
    paths.write_json(settings_file(), asdict(settings))
    return settings


def workspace_dir() -> Path:
    """The folder holding results and the API key."""
    return Path(load_settings().results_root)


# ── key files ─────────────────────────────────────────────────────────────────


def key_file(alias: Optional[str] = None, workspace: Optional[Path] = None) -> Path:
    alias = _validate_alias(alias)
    root = workspace or workspace_dir()
    name = ".openai.key" if alias == DEFAULT_ALIAS else f".openai.{alias}.key"
    return root / name


def _read_key_file(alias: Optional[str] = None) -> Optional[str]:
    path = key_file(alias)
    if not path.is_file():
        return None
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        logger.warning("Could not read %s: %s", path, exc)
        return None
    return value or None


def resolve_key(alias: Optional[str] = None) -> tuple[Optional[str], str]:
    """Returns ``(key, source)`` where source is ``workspace``/``environment``/``none``."""
    from_file = _read_key_file(alias)
    if from_file:
        return from_file, "workspace"
    from_env = os.environ.get(env_var_for_alias(alias))
    if from_env:
        return from_env, "environment"
    return None, "none"


def _mask(value: str) -> str:
    """`sk-proj…wxyz` — enough to tell which key, not enough to use it."""
    if len(value) <= 12:
        return "•" * len(value)
    return f"{value[:7]}…{value[-4:]}"


def api_key_status(alias: Optional[str] = None) -> dict:
    alias = _validate_alias(alias)
    value, source = resolve_key(alias)
    return {
        "alias": alias,
        "configured": bool(value),
        "masked": _mask(value) if value else None,
        "source": source,
        "key_file": str(key_file(alias)),
        "env_var": env_var_for_alias(alias),
    }


def list_key_aliases() -> list[dict]:
    """Every key visible to this install, from the workspace and the environment."""
    aliases: set[str] = {DEFAULT_ALIAS}

    workspace = workspace_dir()
    if workspace.is_dir():
        try:
            for path in workspace.glob(".openai.*.key"):
                name = path.name[len(".openai."): -len(".key")]
                if _ALIAS_RE.match(name):
                    aliases.add(name)
        except OSError:
            pass

    for var in os.environ:
        if var.startswith("OPENAI_API_KEY_"):
            suffix = var[len("OPENAI_API_KEY_"):]
            if suffix and _ALIAS_RE.match(suffix):
                aliases.add(suffix.lower())

    return [api_key_status(alias) for alias in sorted(aliases)]


def set_api_key(value: str, alias: Optional[str] = None) -> dict:
    """Write a key into the workspace.

    Also updates this process's environment so a key just saved works
    immediately, and protects the workspace with a `.gitignore` — a plaintext
    secret inside a folder someone might later `git init` is a real way to leak
    a key.
    """
    alias = _validate_alias(alias)
    value = value.strip()
    if not value:
        raise ValueError("The API key is empty.")
    if "\n" in value or "\r" in value:
        raise ValueError("The API key contains a line break.")

    workspace = workspace_dir()
    try:
        workspace.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ValueError(f"Could not create the workspace folder {workspace}: {exc}") from exc

    path = key_file(alias, workspace)
    try:
        path.write_text(value + "\n", encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Could not write {path}: {exc}") from exc

    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError:
            pass

    _protect_workspace(workspace)
    os.environ[env_var_for_alias(alias)] = value
    return api_key_status(alias)


def clear_api_key(alias: Optional[str] = None) -> dict:
    alias = _validate_alias(alias)
    path = key_file(alias)
    try:
        if path.is_file():
            path.unlink()
    except OSError as exc:
        raise ValueError(f"Could not remove {path}: {exc}") from exc
    os.environ.pop(env_var_for_alias(alias), None)
    return api_key_status(alias)


def _protect_workspace(workspace: Path) -> None:
    """Append key patterns to the workspace `.gitignore` if not already there."""
    gitignore = workspace / ".gitignore"
    try:
        existing = gitignore.read_text(encoding="utf-8") if gitignore.is_file() else ""
        missing = [line for line in _GITIGNORE_LINES if line not in existing]
        if missing:
            prefix = "" if not existing or existing.endswith("\n") else "\n"
            gitignore.write_text(existing + prefix + "\n".join(missing) + "\n", encoding="utf-8")
    except OSError as exc:
        # Never fail saving a key over bookkeeping.
        logger.warning("Could not update %s: %s", gitignore, exc)


# ── environment report ────────────────────────────────────────────────────────


def environment_report() -> dict:
    import sys

    workspace = workspace_dir()
    return {
        "workspace": str(workspace),
        "workspace_exists": workspace.is_dir(),
        "key_file": str(key_file()),
        "project_root": str(paths.PROJECT_ROOT),
        "python": sys.version.split()[0],
        "python_executable": sys.executable,
        "ledger_path": str(paths.cost_ledger_path()),
        "ledger_exists": paths.cost_ledger_path().is_file(),
    }
