"""
LLM-based call graph edge resolver.

Wraps OpenAIResolver with a persistent cache so each unique
(caller, raw_call, candidates) combination is only sent to the
LLM once across runs.

Cache is stored under experiments/results/context/edge_cache.json
(not in the project root).
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from src.context.edge_cache import EdgeCache
from src.llm.openai_client import OpenAIResolver

logger = logging.getLogger(__name__)

# Put cache inside experiments folder, not project root
_DEFAULT_CACHE_PATH = os.path.join(
    Path(__file__).parent.parent.parent,
    "experiments", "results", "context", "edge_cache.json",
)


class LLMEdgeResolver:

    def __init__(self, api_key: str, cache_path: str = None):
        self.client = OpenAIResolver(api_key)
        self.cache = EdgeCache(
            cache_path or _DEFAULT_CACHE_PATH
        )

    def resolve(
        self,
        caller: str,
        raw_call: str,
        caller_code: str,
        candidates: list,
    ) -> dict:
        """
        Resolves a call graph edge using the LLM.

        Returns a dict with keys:
            target       - function name from candidates, or None
            confidence   - float 0.0–1.0
            resolved_by  - "cache" | "llm" | "static"
            reasoning    - short explanation string
        """
        # ── fast path: single candidate, no LLM needed ────────────────────────
        if len(candidates) == 1:
            return {
                "target": candidates[0],
                "confidence": 1.0,
                "resolved_by": "static",
                "reasoning": "Only one candidate.",
            }

        # ── filter candidates: skip obviously external calls ──────────────────
        # Member expressions like res.json, jwt.sign are external — don't waste
        # tokens asking the LLM about them.
        simple = raw_call.split(".")[-1] if "." in raw_call else raw_call
        obj = raw_call.split(".")[0] if "." in raw_call else ""

        _EXTERNAL_OBJECTS = {
            "res", "req", "console", "fs", "jwt", "bcrypt",
            "process", "Math", "JSON", "Date", "Object", "Array",
        }
        if obj in _EXTERNAL_OBJECTS:
            return {
                "target": None,
                "confidence": 1.0,
                "resolved_by": "static",
                "reasoning": f"{obj} is an external/runtime object.",
            }

        # ── cache lookup ──────────────────────────────────────────────────────
        # Sort candidates so key is stable regardless of insertion order
        cache_key = json.dumps(
            {
                "caller": caller,
                "raw_call": raw_call,
                "candidates": sorted(candidates),
            },
            sort_keys=True,
        )

        cached = self.cache.get(cache_key)
        if cached:
            # Normalise old cache entries that used different key names
            cached = self._normalise(cached, candidates)
            if cached.get("target") is not None:
                cached["resolved_by"] = "cache"
                return cached

        # ── LLM call ──────────────────────────────────────────────────────────
        payload = {
            "caller": caller,
            "raw_call": raw_call,
            "caller_code": caller_code,
            "candidates": candidates,
        }

        result = self.client.resolve_edge(payload)
        result["resolved_by"] = "llm"

        if result.get("target"):
            logger.debug(
                "LLM resolved %r -> %r (conf %.2f) for caller %s",
                raw_call,
                result["target"],
                result.get("confidence", 0.0),
                caller,
            )

        # cache even None results to avoid re-querying the same dead ends
        self.cache.set(cache_key, result)

        return result

    # ── helpers ───────────────────────────────────────────────────────────────

    def _normalise(self, entry: dict, candidates: list) -> dict:
        """
        Migrate old cache entries that used inconsistent key names
        (resolved_callee, callee, call, resolved_call, etc.) to the
        canonical "target" key.
        """
        if "target" in entry:
            return entry

        for alt in (
            "resolved_callee", "callee", "resolved_call",
            "resolved_to", "call",
        ):
            val = entry.get(alt)
            if isinstance(val, str) and val in candidates:
                entry["target"] = val
                return entry

        # check nested structures like {"resolved_edges": [{"callee": ...}]}
        for nested_key in ("resolved_edges", "edges", "call_edges"):
            nested = entry.get(nested_key)
            if isinstance(nested, list) and nested:
                first = nested[0]
                if isinstance(first, dict):
                    for alt in ("callee", "target", "resolved_callee"):
                        val = first.get(alt)
                        if isinstance(val, str) and val in candidates:
                            entry["target"] = val
                            return entry

        entry["target"] = None
        return entry