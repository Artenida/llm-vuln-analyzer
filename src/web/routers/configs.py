"""
The analysis configs the UI can run under.

A config file decides which functions a run sees — `ingestion.skip_dirs` is the
only thing standing between "the Express app" and "the Express app plus its
2,108-function Angular client". That decision has to be made *before* the scan,
because the scan's function count is what the cost estimate and the confirm
dialog are built from, and a count taken under one scope next to a run executed
under another is the one bug this screen must not have.

So the picker lists the same YAML files `python -m src.cli analyze --config`
takes, and the chosen one is threaded through both `/fs/inspect` and
`/jobs/analyze`. Scanned scope and analysed scope are then the same object.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from src.config import load_config
from src.web import paths

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/configs", tags=["configs"])

# The config `load_config()` falls back to, and the one a run gets when the
# request names none. Listed like any other so the UI never has to special-case
# "no choice made" — there is always a named scope on screen.
DEFAULT_CONFIG_NAME = "default.yaml"


class AnalysisConfig(BaseModel):
    name: str                    # file stem, e.g. "juice_shop"
    filename: str                # "juice_shop.yaml"
    path: str                    # absolute, what the API wants back
    display_path: str            # project-relative, what a person reads
    description: str
    model: str
    react: bool
    max_function_lines: int
    chunk_oversized: bool
    skip_dirs: list[str]
    is_default: bool


def configs_dir() -> Path:
    return paths.experiments_root() / "configs"


def _describe(path: Path) -> Optional[AnalysisConfig]:
    try:
        config = load_config(str(path))
    except Exception as exc:  # a malformed YAML must not empty the whole list
        logger.warning("Skipping unreadable config %s: %s", path, exc)
        return None
    return AnalysisConfig(
        name=path.stem,
        filename=path.name,
        path=str(path.resolve()),
        display_path=paths.display_path(path),
        description=config.description,
        model=config.llm.model,
        react=config.agent.react_mode,
        max_function_lines=config.ingestion.max_function_lines,
        chunk_oversized=config.ingestion.chunk_oversized,
        skip_dirs=sorted(config.ingestion.skip_dirs),
        is_default=path.name == DEFAULT_CONFIG_NAME,
    )


def resolve(raw: Optional[str]) -> Path:
    """The config file a request means, or the default when it names none.

    Confined to the configs directory: this path reaches a subprocess argv, and
    "run the analyzer with that YAML over there" is not a capability the browser
    needs. Refusing it here also keeps `/fs/inspect` and `/jobs/analyze` unable
    to disagree about what a given request resolved to.
    """
    directory = configs_dir()
    if not raw:
        return directory / DEFAULT_CONFIG_NAME

    candidate = Path(raw)
    # A bare name ("juice_shop", "juice_shop.yaml") is as valid as a full path;
    # the UI round-trips absolute paths, but a hand-written request should work.
    if not candidate.is_absolute() and candidate.parent == Path("."):
        candidate = directory / (raw if raw.endswith((".yaml", ".yml")) else f"{raw}.yaml")

    resolved = candidate.expanduser().resolve()
    if not paths.is_within(resolved, directory.resolve()):
        raise paths.UnsafePathError(
            f"Config files must live in {paths.display_path(directory)}."
        )
    if not resolved.is_file():
        raise paths.UnsafePathError(f"No config file at {paths.display_path(resolved)}.")
    return resolved


@router.get("", response_model=list[AnalysisConfig])
def list_configs() -> list[AnalysisConfig]:
    directory = configs_dir()
    if not directory.is_dir():
        return []
    found = [
        described
        for path in sorted(directory.iterdir())
        if path.suffix in (".yaml", ".yml") and path.is_file()
        for described in [_describe(path)]
        if described is not None
    ]
    # Default first; it is the scope a run falls back to, so it should be the
    # one the picker opens on rather than whatever sorts first alphabetically.
    return sorted(found, key=lambda c: (not c.is_default, c.name))


@router.get("/resolve", response_model=AnalysisConfig)
def resolve_config(path: Optional[str] = None) -> AnalysisConfig:
    try:
        described = _describe(resolve(path))
    except paths.UnsafePathError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if described is None:
        raise HTTPException(status_code=400, detail="That config file could not be read.")
    return described
