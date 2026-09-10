"""
Filesystem browsing for the folder picker.

A web page cannot obtain an absolute path from a native file dialog — an
`<input webkitdirectory>` yields relative names only. Since the backend is
local, listing directories server-side is the only way "select the folder" can
actually work.

This router may list any directory, which is the deliberate exception to the
containment rule in `paths.py`: browsing to a folder is the point. It returns
names and types only, never file contents.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from src.models import EXTENSION_MAP
from src.web import paths
from src.web.routers import configs as configs_router

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/fs", tags=["filesystem"])

SOURCE_EXTENSIONS = set(EXTENSION_MAP)

# Deep-scanning a huge tree means parsing every file with tree-sitter. Past this
# many source files the inspect step reports counts only and says it skipped the
# function count, rather than making the picker feel broken. Applied to the
# files the chosen config actually keeps: a scoped config is precisely how a
# tree too big to parse whole becomes one that can be.
DEEP_SCAN_FILE_LIMIT = 1500


def _matched_skip(path: Path, skips: set[str]) -> Optional[str]:
    """The skip entry that excludes `path`, or None.

    Mirrors `CodeExtractor`'s rule — any path part equal to a skip entry
    excludes the file, which is why a bare filename (`Gruntfile.js`) works as a
    skip entry too. Parts are checked outermost-first so an excluded file is
    attributed to the top of the subtree that excluded it, not to some nested
    directory that happens to share a name.
    """
    for part in path.parts:
        if part in skips:
            return part
    return None


class DirEntry(BaseModel):
    name: str
    path: str
    is_dir: bool
    is_result_dir: bool = False


class ListResponse(BaseModel):
    path: str
    parent: Optional[str] = None
    entries: list[DirEntry]
    # Whether the listed directory is itself a result bundle. The entries carry
    # the same flag for their own sake, but a picker that must land *on* a
    # results folder needs to know about the one it is standing in.
    is_result_dir: bool = False


class InspectRequest(BaseModel):
    path: str
    # The scope to count under. Omitted means the default config, which is what
    # a run with no `--config` uses — the two defaults have to be the same one.
    config_path: Optional[str] = None
    # Whether an oversized function is counted as its chunks or dropped. None
    # leaves the config's setting alone, matching `--chunk-oversized`'s default.
    chunk_oversized: Optional[bool] = None


class InspectResponse(BaseModel):
    path: str
    exists: bool
    is_dir: bool
    source_files: int = 0
    languages: dict[str, int] = {}
    functions: Optional[int] = None
    functions_skipped: Optional[int] = None
    scanned: bool = False
    # Echoed back so the panel can name the scope its numbers were taken under,
    # and so a stored scan carries the config it belongs to rather than being a
    # bare count that could be read against any scope.
    config_path: Optional[str] = None
    config_name: Optional[str] = None
    config_description: Optional[str] = None
    # Echoed for the same reason as the config: the count means one thing when
    # an oversized function contributes three chunks and another when it
    # contributes nothing, so the setting travels with the number.
    chunk_oversized: bool = True
    # Whole functions, before oversized ones are split. `functions` counts the
    # units that get analysed and billed; this counts the units the ground truth
    # has rows for. They differ by exactly the extra chunks.
    whole_functions: Optional[int] = None
    # Source files this config's `skip_dirs` put out of scope, beyond the
    # build/dependency folders no scope ever includes. Reported because the gap
    # between 382 and 2,696 is a decision, and a decision that size should be
    # visible on the screen that spends money on it.
    source_files_excluded: int = 0
    excluded: dict[str, int] = {}
    note: Optional[str] = None


class MkdirRequest(BaseModel):
    path: str


@router.get("/roots")
def roots() -> list[dict]:
    return paths.filesystem_roots()


@router.get("/list", response_model=ListResponse)
def list_directory(
    path: str = Query(..., description="Directory to list."),
    show_hidden: bool = Query(False),
) -> ListResponse:
    try:
        directory = paths.normalise(path)
    except paths.UnsafePathError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if not directory.is_dir():
        raise HTTPException(status_code=404, detail=f"No such directory: {directory}")

    entries: list[DirEntry] = []
    try:
        for child in sorted(directory.iterdir(), key=lambda c: c.name.lower()):
            try:
                is_dir = child.is_dir()
            except OSError:
                continue  # a permission-denied entry should not break the listing
            if not is_dir:
                continue
            if not show_hidden and child.name.startswith("."):
                continue
            entries.append(
                DirEntry(
                    name=child.name,
                    path=str(child),
                    is_dir=True,
                    is_result_dir=paths.looks_like_result_dir(child),
                )
            )
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied for that directory.")
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"Could not read that directory: {exc}")

    parent = str(directory.parent) if directory.parent != directory else None
    return ListResponse(
        path=str(directory),
        parent=parent,
        entries=entries,
        is_result_dir=paths.looks_like_result_dir(directory),
    )


@router.post("/inspect", response_model=InspectResponse)
def inspect(request: InspectRequest) -> InspectResponse:
    """What is in this folder, before committing to analyse it.

    Counted under the config the run will use, so every number on the screen —
    files, functions, projected cost — describes the same set of functions the
    analyser will open. A count taken under one scope and a run executed under
    another is how you end up authorising $22 of Angular components on the
    strength of a figure that meant something else.
    """
    from src.config import load_config
    from src.ingestion.extractor import SKIP_DIRS as BASE_SKIP_DIRS

    try:
        target = paths.normalise(request.path)
    except paths.UnsafePathError as exc:
        return InspectResponse(path=request.path, exists=False, is_dir=False, note=str(exc))

    try:
        config_file = configs_router.resolve(request.config_path)
    except paths.UnsafePathError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    config = load_config(str(config_file))
    if request.chunk_oversized is not None:
        config.ingestion.chunk_oversized = request.chunk_oversized
    scope = dict(
        config_path=str(config_file),
        config_name=config_file.stem,
        config_description=config.description or None,
        chunk_oversized=config.ingestion.chunk_oversized,
    )

    if not target.exists():
        return InspectResponse(path=str(target), exists=False, is_dir=False,
                               note="That path does not exist.", **scope)

    skips = set(config.ingestion.skip_dirs)
    # Build and dependency folders are walked past silently: no scope includes
    # them, so reporting them as this config's doing would be a lie, and
    # descending into node_modules to count what we then discard is minutes of
    # walking for a number nobody wants.
    unreportable = set(BASE_SKIP_DIRS)

    languages: dict[str, int] = {}
    source_files = 0
    excluded: dict[str, int] = {}

    if target.is_file():
        language = EXTENSION_MAP.get(target.suffix.lower())
        if language:
            source_files = 1
            languages[language.value] = 1
    else:
        for root, dirnames, filenames in os.walk(target):
            dirnames[:] = [
                d for d in dirnames if d not in unreportable and not d.startswith(".")
            ]
            for filename in filenames:
                language = EXTENSION_MAP.get(Path(filename).suffix.lower())
                if not language:
                    continue
                skipped_by = _matched_skip(Path(root, filename), skips)
                if skipped_by:
                    excluded[skipped_by] = excluded.get(skipped_by, 0) + 1
                    continue
                source_files += 1
                languages[language.value] = languages.get(language.value, 0) + 1

    scope["source_files_excluded"] = sum(excluded.values())
    # Largest first: the picker's job is to make the one costly exclusion
    # obvious, not to list twelve directories alphabetically.
    scope["excluded"] = dict(sorted(excluded.items(), key=lambda kv: -kv[1]))

    if source_files == 0:
        return InspectResponse(
            path=str(target), exists=True, is_dir=target.is_dir(),
            source_files=0, languages={},
            note=(
                f"Every source file here is excluded by {config_file.name}."
                if excluded else
                "No files in a supported language (Python, JavaScript, TypeScript, C, C++)."
            ),
            **scope,
        )

    if source_files > DEEP_SCAN_FILE_LIMIT:
        return InspectResponse(
            path=str(target), exists=True, is_dir=target.is_dir(),
            source_files=source_files, languages=languages, scanned=False,
            note=f"{source_files} source files in scope — too many to count functions "
                 "quickly. The cost estimate will be based on file count instead. "
                 "A narrower config would make this countable.",
            **scope,
        )

    try:
        from src.ingestion.extractor import CodeExtractor

        extractor = CodeExtractor(
            max_function_lines=config.ingestion.max_function_lines,
            skip_dirs=config.ingestion.skip_dirs,
            chunk_oversized=config.ingestion.chunk_oversized,
        )
        samples = extractor.from_path(str(target))
        # A chunked function contributes its chunks *instead of* itself: it is
        # recorded as skipped, and its slices are the samples. So the chunks are
        # the whole of the difference between the two counts.
        extra_chunks = sum(
            sk.chunk_count or 0
            for sk in extractor.skipped_functions
            if getattr(sk, "chunked", False)
        )
        notes = []
        if extractor.skipped_functions:
            notes.append(
                f"{len(extractor.skipped_functions)} function(s) exceed "
                f"{config.ingestion.max_function_lines} lines"
                + (
                    " and are analysed in chunks."
                    if config.ingestion.chunk_oversized
                    else " and will not be analysed."
                )
            )
        if scope["source_files_excluded"]:
            notes.append(
                f"{scope['source_files_excluded']} source file(s) are out of scope "
                f"under {config_file.name}."
            )
        return InspectResponse(
            path=str(target), exists=True, is_dir=target.is_dir(),
            source_files=source_files, languages=languages,
            functions=len(samples),
            whole_functions=len(samples) - extra_chunks,
            functions_skipped=len(extractor.skipped_functions),
            scanned=True,
            note=" ".join(notes) or None,
            **scope,
        )
    except Exception as exc:
        logger.warning("Deep scan of %s failed: %s", target, exc)
        return InspectResponse(
            path=str(target), exists=True, is_dir=target.is_dir(),
            source_files=source_files, languages=languages, scanned=False,
            note=f"Could not count functions: {exc}",
            **scope,
        )


@router.post("/mkdir")
def make_directory(request: MkdirRequest) -> dict:
    try:
        target = paths.normalise(request.path)
    except paths.UnsafePathError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"Could not create that folder: {exc}")
    return {"path": str(target), "created": True}
