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

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/fs", tags=["filesystem"])

SOURCE_EXTENSIONS = set(EXTENSION_MAP)

# Deep-scanning a huge tree means parsing every file with tree-sitter. Past this
# many source files the inspect step reports counts only and says it skipped the
# function count, rather than making the picker feel broken.
DEEP_SCAN_FILE_LIMIT = 1500


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


class InspectResponse(BaseModel):
    path: str
    exists: bool
    is_dir: bool
    source_files: int = 0
    languages: dict[str, int] = {}
    functions: Optional[int] = None
    functions_skipped: Optional[int] = None
    scanned: bool = False
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

    The function count comes from the same extractor `analyze` uses, so the
    number shown in the cost estimate is the number that will actually be
    analysed — not a guess from file sizes.
    """
    try:
        target = paths.normalise(request.path)
    except paths.UnsafePathError as exc:
        return InspectResponse(path=request.path, exists=False, is_dir=False, note=str(exc))

    if not target.exists():
        return InspectResponse(path=str(target), exists=False, is_dir=False,
                               note="That path does not exist.")

    languages: dict[str, int] = {}
    source_files = 0
    if target.is_file():
        language = EXTENSION_MAP.get(target.suffix.lower())
        if language:
            source_files = 1
            languages[language.value] = 1
    else:
        from src.ingestion.extractor import SKIP_DIRS

        for root, dirnames, filenames in os.walk(target):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
            for filename in filenames:
                language = EXTENSION_MAP.get(Path(filename).suffix.lower())
                if language:
                    source_files += 1
                    languages[language.value] = languages.get(language.value, 0) + 1

    if source_files == 0:
        return InspectResponse(
            path=str(target), exists=True, is_dir=target.is_dir(),
            source_files=0, languages={},
            note="No files in a supported language (Python, JavaScript, TypeScript, C, C++).",
        )

    if source_files > DEEP_SCAN_FILE_LIMIT:
        return InspectResponse(
            path=str(target), exists=True, is_dir=target.is_dir(),
            source_files=source_files, languages=languages, scanned=False,
            note=f"{source_files} source files — too many to count functions quickly. "
                 "The cost estimate will be based on file count instead.",
        )

    try:
        from src.config import load_config
        from src.ingestion.extractor import CodeExtractor

        config = load_config()
        extractor = CodeExtractor(
            max_function_lines=config.ingestion.max_function_lines,
            skip_dirs=config.ingestion.skip_dirs,
        )
        samples = extractor.from_path(str(target))
        return InspectResponse(
            path=str(target), exists=True, is_dir=target.is_dir(),
            source_files=source_files, languages=languages,
            functions=len(samples),
            functions_skipped=len(extractor.skipped_functions),
            scanned=True,
            note=(
                f"{len(extractor.skipped_functions)} function(s) exceed "
                f"{config.ingestion.max_function_lines} lines and will not be analysed."
                if extractor.skipped_functions else None
            ),
        )
    except Exception as exc:
        logger.warning("Deep scan of %s failed: %s", target, exc)
        return InspectResponse(
            path=str(target), exists=True, is_dir=target.is_dir(),
            source_files=source_files, languages=languages, scanned=False,
            note=f"Could not count functions: {exc}",
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
