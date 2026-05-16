from __future__ import annotations

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ToolSet:

    def __init__(self, graph: dict, name_index: dict = None):
        self.graph = graph
        self.name_index = name_index or {}

    # ── node lookup ───────────────────────────────────────────────────────────

    def _resolve_node_id(
        self,
        function_name: str,
        file_path: Optional[str] = None,
    ) -> Optional[str]:
        """
        Find the node_id in the graph for a given function.
        Prefers the exact file_path::function_name key when file_path is given.
        Falls back to name_index for name-only lookups.
        """
        if file_path:
            exact = f"{file_path}::{function_name}"
            if exact in self.graph:
                return exact

        # name_index maps function_name -> list of node_ids
        candidates = self.name_index.get(function_name, [])
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            logger.debug(
                "Ambiguous function name %r — %d candidates, using first",
                function_name,
                len(candidates),
            )
            return candidates[0]

        return None

    # ── public tools ──────────────────────────────────────────────────────────

    def get_callees(
        self, function_name: str, file_path: Optional[str] = None
    ) -> List[str]:
        node_id = self._resolve_node_id(function_name, file_path)
        if not node_id:
            return []
        node = self.graph.get(node_id)
        return list(node.callees) if node else []

    def get_callers(
        self, function_name: str, file_path: Optional[str] = None
    ) -> List[str]:
        node_id = self._resolve_node_id(function_name, file_path)
        if not node_id:
            return []
        node = self.graph.get(node_id)
        return list(node.callers) if node else []

    def is_entry_point(
        self, function_name: str, file_path: Optional[str] = None
    ) -> bool:
        node_id = self._resolve_node_id(function_name, file_path)
        if not node_id:
            return False
        node = self.graph.get(node_id)
        return node.is_entry_point if node else False

    def trace_one_hop(
        self, function_name: str, file_path: Optional[str] = None
    ) -> Dict[str, List[str]]:
        """
        Returns callers and callees for a function.
        Used by ReActAgent to build the analysis prompt.
        """
        return {
            "callers": self.get_callers(function_name, file_path),
            "callees": self.get_callees(function_name, file_path),
        }

    def get_node_info(
        self, function_name: str, file_path: Optional[str] = None
    ) -> Optional[dict]:
        """Returns full node metadata for a function."""
        node_id = self._resolve_node_id(function_name, file_path)
        if not node_id:
            return None
        node = self.graph.get(node_id)
        if not node:
            return None
        return {
            "id": node_id,
            "function_name": node.function_name,
            "file_path": node.file_path,
            "callers": list(node.callers),
            "callees": list(node.callees),
            "is_entry_point": node.is_entry_point,
            "is_external": node.is_external,
        }