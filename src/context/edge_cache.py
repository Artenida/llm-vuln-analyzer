"""
Persistent key-value cache for resolved call graph edges.
Stored as a JSON file. Path is configurable — defaults to
experiments/results/context/edge_cache.json.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class EdgeCache:

    def __init__(self, cache_file: str = "experiments/results/context/edge_cache.json"):
        self.cache_file = Path(cache_file)

        # auto-create parent directories
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)

        if self.cache_file.exists():
            try:
                self.cache: dict = json.loads(self.cache_file.read_text(encoding="utf-8"))
                logger.debug(
                    "Loaded edge cache: %d entries from %s",
                    len(self.cache),
                    self.cache_file,
                )
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Edge cache corrupt or unreadable (%s) — starting fresh.", e)
                self.cache = {}
        else:
            self.cache = {}

    def get(self, key: str) -> dict | None:
        return self.cache.get(key)

    def set(self, key: str, value: dict) -> None:
        self.cache[key] = value
        try:
            self.cache_file.write_text(
                json.dumps(self.cache, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as e:
            logger.warning("Could not write edge cache: %s", e)

    def delete(self, key: str) -> None:
        if key in self.cache:
            del self.cache[key]
            self.cache_file.write_text(
                json.dumps(self.cache, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

    def clear(self) -> None:
        """Wipe all cached entries. Useful between analysis runs."""
        self.cache = {}
        self.cache_file.write_text("{}", encoding="utf-8")
        logger.info("Edge cache cleared: %s", self.cache_file)

    def stats(self) -> dict:
        resolved = sum(
            1 for v in self.cache.values()
            if isinstance(v, dict) and v.get("target") is not None
        )
        return {
            "total_entries": len(self.cache),
            "resolved": resolved,
            "unresolved": len(self.cache) - resolved,
            "cache_file": str(self.cache_file),
        }