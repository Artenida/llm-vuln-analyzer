"""
FastAPI application factory.

Serves the API under /api and, when built, the compiled SPA from frontend/dist.
In development the SPA is served by Vite on :5173, which proxies /api here.
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from src.web import paths, settings_store
from src.web.paths import UnsafePathError
from src.web.routers import configs, cost, evaluations, fs, jobs, results, settings

logger = logging.getLogger(__name__)

FRONTEND_DIST = paths.PROJECT_ROOT / "frontend" / "dist"

# The Vite dev server. The app binds to localhost and is unauthenticated by
# design — a single-user local instrument, not a deployed service.
DEV_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]


def create_app() -> FastAPI:
    app = FastAPI(
        title="LLM-Vuln-Analyzer",
        description="Point it at a folder, analyse it, read the results.",
        version="0.2.0",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=DEV_ORIGINS,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )

    @app.exception_handler(UnsafePathError)
    async def _unsafe_path(_: Request, exc: UnsafePathError) -> JSONResponse:
        logger.warning("Refused path: %s", exc)
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.get("/api/health", tags=["overview"])
    def health() -> dict:
        return {
            "status": "ok",
            **settings_store.environment_report(),
            "api_key": settings_store.api_key_status(),
        }

    for module in (settings, configs, fs, jobs, results, cost, evaluations):
        app.include_router(module.router, prefix="/api")

    # vis-network and pyvis's helpers, vendored in the repo. The call-graph HTML
    # is rewritten to load them from here so it renders inside the iframe and
    # needs no internet — see routers/results.py.
    vendor = paths.PROJECT_ROOT / "lib"
    if vendor.is_dir():
        app.mount("/vendor", StaticFiles(directory=vendor), name="vendor")
    else:
        logger.warning(
            "lib/ not found — the embedded call graph will fall back to CDN assets."
        )

    _mount_frontend(app)
    return app


def _mount_frontend(app: FastAPI) -> None:
    """Serve the built SPA, if it exists.

    Without a build this is skipped rather than mounting an empty directory —
    `ui --dev` points the browser at Vite instead, and a silently-empty mount
    would look like a broken app.
    """
    if not FRONTEND_DIST.is_dir():
        logger.info("frontend/dist not found — API only.")

        @app.get("/", include_in_schema=False)
        def _no_build() -> JSONResponse:
            return JSONResponse({
                "detail": "Frontend not built.",
                "api": "/api/docs",
                "hint": "cd frontend && npm install && npm run build",
            })

        return

    assets = FRONTEND_DIST / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    index = FRONTEND_DIST / "index.html"

    @app.get("/{full_path:path}", include_in_schema=False)
    def _spa(full_path: str) -> FileResponse:
        """Client-side routing catch-all.

        A real file under dist/ is served directly; anything else falls through
        to index.html so a deep link survives a hard refresh. /api/* never
        reaches here — those routes are registered first.
        """
        if full_path:
            try:
                candidate = FRONTEND_DIST
                for segment in full_path.split("/"):
                    candidate = paths.safe_join(candidate, segment)
            except UnsafePathError:
                raise HTTPException(status_code=400, detail="Invalid path")
            if candidate.is_file():
                return FileResponse(candidate)
        return FileResponse(index)


app = create_app()
