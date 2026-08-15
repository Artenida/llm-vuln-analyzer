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
from pydantic import BaseModel, Field

from src.web import patch_apply, paths, results

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


class OpenRequest(BaseModel):
    path: str = Field(..., description="A folder holding a previous run's artifacts.")


@router.post("/open")
def post_open(request: OpenRequest) -> dict:
    """Authorise reading a result folder this installation did not write.

    Reads are confined to the registry of directories the tool has written to
    (`paths.register_root`), which is what makes a run from another machine, a
    run whose registry entry was lost, or a plain CLI run unreadable from here.
    This is the only way to widen that set from the browser, so it is
    deliberately narrow: the folder must *already* look like a result bundle.
    A directory of arbitrary files cannot be registered and then read out of —
    and even once registered, reads stay restricted to `paths.RUN_ARTIFACTS`.

    Deliberately not a list of past runs: the flow is one codebase, one
    analysis, that run's results. See docs/frontend-plan.md §10.
    """
    try:
        directory = paths.normalise(request.path)
    except paths.UnsafePathError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if not directory.is_dir():
        raise HTTPException(status_code=404, detail=f"No such folder: {directory}")

    if not paths.looks_like_result_dir(directory):
        raise HTTPException(
            status_code=400,
            detail=(
                "That folder holds no analysis results. A results folder contains "
                + ", ".join(paths.RESULT_MARKERS)
                + "."
            ),
        )

    paths.register_root(directory)
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


# ── applying a patch to the analysed project ──────────────────────────────────
#
# The only write this API makes outside a result directory. It is a POST per
# finding, never a bulk operation, and it carries no "apply all" convenience —
# the user reads one diff and chooses to take that one change. `patch --apply`
# on the CLI remains the way to write a whole run at once.
#
# All the safety work is in `patch_apply`; this layer only turns its refusals
# into status codes.


class PatchTarget(BaseModel):
    path: str = Field(..., description="Run output directory.")
    file_path: str = Field(..., description="File path as recorded on the patch.")
    function_name: str = Field(..., description="Function the patch rewrites.")


@router.get("/patches/applied")
def get_applied(path: str = Query(...)) -> dict:
    return patch_apply.status(_directory(path))


@router.post("/patches/apply")
def post_apply(target: PatchTarget) -> dict:
    try:
        return patch_apply.apply_patch(
            _directory(target.path), target.file_path, target.function_name
        )
    except patch_apply.ApplyError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except paths.UnsafePathError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/patches/revert")
def post_revert(target: PatchTarget) -> dict:
    try:
        return patch_apply.revert_patch(
            _directory(target.path), target.file_path, target.function_name
        )
    except patch_apply.ApplyError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except paths.UnsafePathError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


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

# pyvis sizes the canvas in fixed pixels on an unstyled white body, which inside
# a shorter iframe shows as a white band above a clipped, separately-scrolling
# graph. Sizing to the viewport makes the embed and the full-screen view fill
# whatever they are given.
_FIT_VIEWPORT = """
<style>
  html, body { margin: 0; padding: 0; height: 100%; background: #1a1a2e; overflow: hidden; }
  body > .card { height: 100%; margin: 0; border: 0; border-radius: 0; }
  #mynetwork { height: 100vh !important; border: 0 !important; float: none !important; }
</style>
</head>"""

# Sizing the canvas to its frame is only half the job. vis-network measures the
# container once, when the network is constructed, and computes the initial view
# from that — but a viewport-relative height is not final until the embedding
# frame has settled, which can happen after this document has already run
# drawGraph(). The result is a graph fitted to a box that no longer exists, with
# the nodes drawn outside the visible area: the legend renders, the canvas looks
# empty, and there is nothing under the cursor to scroll-zoom. Refitting on every
# size change costs nothing and removes the race entirely.
_REFIT = """
<script>
  (function () {
    var box = document.getElementById('mynetwork');
    if (!box || typeof network === 'undefined' || !network) return;
    var lastWidth = 0, lastHeight = 0;
    var fit = function () {
      try { network.fit({ animation: false }); } catch (err) { /* stabilising */ }
    };
    // Only when the box actually changed: setSize rebuilds the navigation
    // overlay, and calling it on every tick leaves stale buttons behind.
    var resize = function () {
      var width = box.clientWidth, height = box.clientHeight;
      if (!width || !height || (width === lastWidth && height === lastHeight)) return;
      lastWidth = width; lastHeight = height;
      try {
        // setSize, not redraw: redraw repaints at the size vis-network already
        // believes in. It measures the container once, at construction, and
        // only re-measures when told — which is the whole bug.
        network.setSize(width + "px", height + "px");
        network.redraw();
      } catch (err) { /* stabilising */ }
      fit();
    };
    // Fires once on observe with the current size, so this covers first paint
    // as well as any later resize of the frame or the window.
    if (window.ResizeObserver) new ResizeObserver(resize).observe(box);
    window.addEventListener("resize", resize);
    // Physics keeps moving nodes after the first paint; fit again once settled.
    try { network.on("stabilizationIterationsDone", fit); } catch (err) {}
    requestAnimationFrame(resize);
    setTimeout(resize, 400);
  })();
</script>
</body>"""


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
    candidate = results.graph_html_file(directory, annotated=annotated)
    if candidate is None:
        raise HTTPException(
            status_code=404,
            detail="No call graph HTML in this run — re-run with visualisation enabled.",
        )

    html = candidate.read_text(encoding="utf-8", errors="replace")
    for old, new in _ASSET_REWRITES:
        html = html.replace(old, new)
    html = _DEAD_ASSETS.sub("", html)
    html = _VENDOR_TAG.sub(lambda m: _SRI_ATTRS.sub("", m.group(0)), html)
    html = html.replace("</head>", _FIT_VIEWPORT, 1)
    # Appended rather than replaced when the document has no </body>, so a
    # differently-shaped export still gets the refit.
    html = html.replace("</body>", _REFIT, 1) if "</body>" in html else html + _REFIT
    # No validator and no expiry on this response, so a browser is free to cache
    # it heuristically — which pins whatever it saw first, including a copy
    # fetched before the asset rewriting above existed (blank graph, no nodes,
    # fixed only by a hard refresh). The bytes are also rebuilt on every re-run
    # of the same output directory, so they must never be served from cache.
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})


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
