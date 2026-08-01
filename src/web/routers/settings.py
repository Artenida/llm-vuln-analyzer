"""Settings: analysis defaults, and the OpenAI API key."""
from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)

from src.web import settings_store
from src.web.settings_store import UISettings

router = APIRouter(prefix="/settings", tags=["settings"])


class SettingsPayload(BaseModel):
    model: str = "o4-mini"
    react: bool = True
    max_steps: int = 5
    max_function_lines: int = 200
    visualize: bool = True
    budget_usd: Optional[float] = None
    api_key_alias: str = "default"
    results_root: str = ""
    skip_dirs: list[str] = []


class SettingsResponse(BaseModel):
    settings: dict
    api_keys: list[dict]
    environment: dict


class ApiKeyPayload(BaseModel):
    value: str
    alias: Optional[str] = None


def _response() -> SettingsResponse:
    return SettingsResponse(
        settings=asdict(settings_store.load_settings()),
        api_keys=settings_store.list_key_aliases(),
        environment=settings_store.environment_report(),
    )


@router.get("", response_model=SettingsResponse)
def get_settings() -> SettingsResponse:
    """Analysis defaults plus key *status*.

    The key value itself is never in this response — only whether one is
    configured and a masked preview.
    """
    return _response()


@router.put("", response_model=SettingsResponse)
def put_settings(payload: SettingsPayload) -> SettingsResponse:
    if payload.max_steps < 1:
        raise HTTPException(status_code=400, detail="Max ReAct steps must be at least 1.")
    if payload.max_function_lines < 10:
        raise HTTPException(status_code=400, detail="Max function lines must be at least 10.")
    if payload.budget_usd is not None and payload.budget_usd <= 0:
        raise HTTPException(status_code=400, detail="The budget must be greater than zero.")

    settings_store.save_settings(UISettings(**payload.model_dump()))
    return _response()


@router.put("/api-key", response_model=SettingsResponse)
def put_api_key(payload: ApiKeyPayload) -> SettingsResponse:
    try:
        settings_store.set_api_key(payload.value, payload.alias)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _response()


@router.delete("/api-key", response_model=SettingsResponse)
def delete_api_key(alias: Optional[str] = None) -> SettingsResponse:
    try:
        settings_store.clear_api_key(alias)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _response()


@router.post("/api-key/test")
def test_api_key(alias: Optional[str] = None) -> dict:
    """Verify a key by listing models — the cheapest call that proves it works."""
    key, source = settings_store.resolve_key(alias)
    if not key:
        return {
            "ok": False,
            "detail": "No key saved yet. Paste one above and press Save key.",
        }
    logger.debug("Testing the %s key from %s", alias or "default", source)

    try:
        from openai import OpenAI

        client = OpenAI(api_key=key)
        models = client.models.list()
        names = sorted(m.id for m in models.data)[:5]
        return {"ok": True, "detail": f"Key works — {len(models.data)} models available.",
                "sample_models": names}
    except Exception as exc:
        # Surface the provider's message, but never echo the key back even if
        # the SDK included it in the error string.
        message = str(exc).replace(key, "***") if key else str(exc)
        return {"ok": False, "detail": message[:400]}
