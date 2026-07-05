"""
Graph persistence utilities.
Handles serialisation and deserialisation of call graphs.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def load_call_graph(path: str | Path) -> dict:
    """
    Loads a previously saved call graph JSON back into a plain dict.
    Returns the graph dict keyed by node_id, or empty dict on failure.
    """
    p = Path(path)
    if not p.exists():
        logger.error("Call graph file not found: %s", p)
        return {}

    try:
        with open(p, encoding="utf-8") as f:
            payload = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Could not load call graph from %s: %s", p, e)
        return {}

    return payload.get("graph", {})
