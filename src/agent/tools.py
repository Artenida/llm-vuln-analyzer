from __future__ import annotations

import logging
from collections import deque
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

    def _node_callees(self, node_id: str) -> List[str]:
        node = self.graph.get(node_id)
        if node is None:
            return []
        if hasattr(node, "callees"):
            return list(node.callees)
        return list(node.get("callees", []))

    def _node_attr(self, node_id: str, attr: str, default=False):
        node = self.graph.get(node_id)
        if node is None:
            return default
        if hasattr(node, attr):
            return getattr(node, attr)
        return node.get(attr, default)

    # ── BFS helpers ───────────────────────────────────────────────────────────

    def _bfs_path(self, start: str, end: str, max_depth: int = 8) -> Optional[List[str]]:
        """Returns the shortest call-edge path from start to end, or None."""
        if start == end:
            return [start]
        visited = {start}
        queue: deque[List[str]] = deque([[start]])
        while queue:
            path = queue.popleft()
            if len(path) > max_depth:
                continue
            for callee_id in self._node_callees(path[-1]):
                if callee_id in visited:
                    continue
                new_path = path + [callee_id]
                if callee_id == end:
                    return new_path
                visited.add(callee_id)
                queue.append(new_path)
        return None

    # ── public tools ──────────────────────────────────────────────────────────

    def get_callees(
        self, function_name: str, file_path: Optional[str] = None
    ) -> List[str]:
        node_id = self._resolve_node_id(function_name, file_path)
        if not node_id:
            return []
        return self._node_callees(node_id)

    def get_callers(
        self, function_name: str, file_path: Optional[str] = None
    ) -> List[str]:
        node_id = self._resolve_node_id(function_name, file_path)
        if not node_id:
            return []
        node = self.graph.get(node_id)
        if node is None:
            return []
        if hasattr(node, "callers"):
            return list(node.callers)
        return list(node.get("callers", []))

    def is_entry_point(
        self, function_name: str, file_path: Optional[str] = None
    ) -> bool:
        node_id = self._resolve_node_id(function_name, file_path)
        return bool(self._node_attr(node_id, "is_entry_point")) if node_id else False

    def trace_one_hop(
        self, function_name: str, file_path: Optional[str] = None
    ) -> Dict[str, List[str]]:
        """Returns callers and callees for a function."""
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
            "id":               node_id,
            "function_name":    self._node_attr(node_id, "function_name") or function_name,
            "file_path":        self._node_attr(node_id, "file_path") or "",
            "callers":          self.get_callers(function_name, file_path),
            "callees":          self._node_callees(node_id),
            "is_entry_point":   self._node_attr(node_id, "is_entry_point"),
            "is_taint_source":  self._node_attr(node_id, "is_taint_source"),
            "is_taint_sink":    self._node_attr(node_id, "is_taint_sink"),
            "is_external":      self._node_attr(node_id, "is_external"),
        }

    def get_taint_path(
        self, function_name: str, file_path: Optional[str] = None
    ) -> List[str]:
        """
        Finds taint paths that pass through (or originate from / lead to) this function.

        Returns a list of human-readable path strings:
          "source_fn → ... → target_fn → ... → sink_fn"

        Up to 3 paths are returned. Each path shows the function names only (not node_ids).
        An empty list means the function is not on any known taint path.
        """
        node_id = self._resolve_node_id(function_name, file_path)
        if not node_id:
            return []

        # collect all source and sink node_ids in the graph
        sources = [
            nid for nid in self.graph
            if not nid.startswith("external::")
            and self._node_attr(nid, "is_taint_source")
        ]
        sinks = [
            nid for nid in self.graph
            if not nid.startswith("external::")
            and self._node_attr(nid, "is_taint_sink")
        ]

        results: List[str] = []

        for src_id in sources:
            if len(results) >= 3:
                break

            # path from source to this function
            prefix = self._bfs_path(src_id, node_id)
            if prefix is None:
                continue

            # try to extend to a sink
            suffix: Optional[List[str]] = None
            for sink_id in sinks:
                if sink_id == node_id:
                    suffix = [node_id]
                    break
                s = self._bfs_path(node_id, sink_id)
                if s is not None:
                    suffix = s
                    break

            if suffix:
                full_path = prefix + suffix[1:]
            else:
                full_path = prefix

            # convert node_ids to readable function names
            names = [nid.split("::")[-1] for nid in full_path]
            results.append(" -> ".join(names))

        return results

    def get_graph_summary(self) -> dict:
        """Returns summary statistics for the loaded graph."""
        total = len(self.graph)
        entry_points    = sum(1 for nid in self.graph if self._node_attr(nid, "is_entry_point"))
        taint_sources   = sum(1 for nid in self.graph if self._node_attr(nid, "is_taint_source"))
        taint_sinks     = sum(1 for nid in self.graph if self._node_attr(nid, "is_taint_sink"))
        infrastructure  = sum(1 for nid in self.graph if self._node_attr(nid, "is_infrastructure"))
        external        = sum(1 for nid in self.graph if self._node_attr(nid, "is_external"))
        edge_count      = sum(len(self._node_callees(nid)) for nid in self.graph)
        return {
            "total_nodes":   total,
            "entry_points":  entry_points,
            "taint_sources": taint_sources,
            "taint_sinks":   taint_sinks,
            "infrastructure": infrastructure,
            "external_nodes": external,
            "total_edges":   edge_count,
        }
