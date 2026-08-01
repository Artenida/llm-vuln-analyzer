"""
Reading a result bundle.

Every endpoint takes `?path=` — the output directory of a run — because results
live wherever the user chose to put them. The path is validated against the
registry of directories this tool has written to; see `paths.resolve_result_dir`.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse

from src.web import paths, results

router = APIRouter(prefix="/results", tags=["results"])


def _directory(path: str):
    try:
        return paths.resolve_result_dir(path)
    except paths.UnsafePathError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("")
def get_summary(path: str = Query(..., description="Run output directory.")) -> dict:
    directory = _directory(path)
    if not results.summary(directory)["artifacts"]:
        raise HTTPException(status_code=404, detail="That directory is empty.")
    return results.summary(directory)


@router.get("/findings")
def get_findings(path: str = Query(...)) -> list[dict]:
    return results.findings(_directory(path))


@router.get("/extraction")
def get_extraction(path: str = Query(...)) -> dict:
    return results.extraction(_directory(path))


@router.get("/graph")
def get_graph(path: str = Query(...)) -> dict:
    return results.graph(_directory(path))


@router.get("/checkpoint")
def get_checkpoint(path: str = Query(...)) -> list[dict]:
    return results.checkpoint(_directory(path))


@router.get("/patches")
def get_patches(path: str = Query(...)) -> Optional[dict]:
    return results.patches(_directory(path))


@router.get("/source")
def get_source(
    path: str = Query(...),
    file: str = Query("", description="File path as recorded on the finding."),
    function: str = Query(..., description="Function name."),
) -> dict:
    """The function's source as extracted — what was actually sent to the model.

    Read from extraction.json rather than the analysed project, so it is correct
    even if the project has since changed or is no longer on this machine.
    """
    entry = results.function_source(_directory(path), file, function)
    if entry is None:
        raise HTTPException(
            status_code=404,
            detail=f"{function} is not in this run's extraction.json.",
        )
    return entry


# pyvis emits a page that expects to be opened from the project root with a
# working internet connection: vis-network comes from a CDN, `lib/` is a
# relative path, and `../node_modules/vis/...` is dead in every case. None of
# that survives being served from an API URL — the relative paths resolve
# against /api/results/ and fall through to the SPA catch-all, so the browser
# gets HTML where it expected JavaScript ("Unexpected token '<'").
#
# Every asset it actually needs is already vendored in the repo's lib/, which is
# mounted at /vendor. Rewriting the references there makes the graph render
# inside the iframe and work with no internet at all.
_ASSET_REWRITES = (
    ("https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.2/dist/dist/vis-network.min.css",
     "/vendor/vis-9.1.2/vis-network.css"),
    ("https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.2/dist/vis-network.min.js",
     "/vendor/vis-9.1.2/vis-network.min.js"),
    ('src="lib/', 'src="/vendor/'),
    ('href="lib/', 'href="/vendor/'),
)

# Tags pointing at a node_modules tree that does not exist in this project.
_DEAD_ASSETS = re.compile(
    r"""<(?:script|link)\b[^>]*(?:src|href)\s*=\s*["'][^"']*node_modules/vis[^"']*["'][^>]*>"""
    r"""(?:\s*</script>)?""",
    re.IGNORECASE,
)

# The CDN tags carry a Subresource Integrity hash of the *CDN* file. Once the URL
# points at the vendored copy the hash no longer matches and the browser blocks
# the script outright ("vis is not defined", blank graph). Scoped to the tags
# actually rewritten, so any remaining CDN asset keeps its SRI check.
_VENDOR_TAG = re.compile(r"<(?:script|link)\b[^>]*/vendor/[^>]*>", re.IGNORECASE)
_SRI_ATTRS = re.compile(
    r"""\s+(?:integrity|crossorigin)\s*=\s*(?:"[^"]*"|'[^']*'|\S+)""", re.IGNORECASE
)


@router.get("/graph.html", response_class=HTMLResponse)
def get_graph_html(
    path: str = Query(...),
    annotated: bool = Query(True, description="Prefer the findings-annotated graph."),
) -> HTMLResponse:
    """The interactive call graph, rewritten for embedding in an iframe.

    The graph itself is still the one `export_graph.py` produced — only its
    asset URLs are adjusted. Re-implementing an interactive graph in React would
    be days of work for no gain over what the CLI already emits.
    """
    directory = _directory(path)
    order = ["call_graph_annotated.html", "call_graph.html"]
    if not annotated:
        order.reverse()

    for name in order:
        candidate = directory / name
        if not candidate.is_file():
            continue
        html = candidate.read_text(encoding="utf-8", errors="replace")
        for old, new in _ASSET_REWRITES:
            html = html.replace(old, new)
        html = _DEAD_ASSETS.sub("", html)
        html = _VENDOR_TAG.sub(lambda m: _SRI_ATTRS.sub("", m.group(0)), html)
        return HTMLResponse(html)

    raise HTTPException(
        status_code=404,
        detail="No call graph HTML in this run — re-run with visualisation enabled.",
    )


@router.get("/artifacts")
def get_artifacts(path: str = Query(...)) -> list[dict]:
    return results.artifacts(_directory(path))


@router.get("/artifacts/{name}")
def get_artifact(name: str, path: str = Query(...)) -> Any:
    """Raw passthrough of one artifact — the guarantee that no field is unreachable."""
    directory = _directory(path)
    if name.endswith("_patches.json"):
        target = directory / name
        if not target.is_file():
            raise HTTPException(status_code=404, detail=f"No {name} in this run.")
    else:
        try:
            target = paths.resolve_artifact(path, name)
        except paths.UnsafePathError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if not target.is_file():
            raise HTTPException(status_code=404, detail=f"No {name} in this run.")

    if target.suffix == ".jsonl":
        return paths.read_jsonl(target)
    if target.suffix == ".json":
        data = paths.read_json(target)
        if data is None:
            raise HTTPException(status_code=422, detail=f"{name} could not be parsed as JSON.")
        return data
    return PlainTextResponse(target.read_text(encoding="utf-8", errors="replace"))
