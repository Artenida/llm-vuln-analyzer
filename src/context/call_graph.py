import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from src.models import CodeSample
from src.context.symbol_resolver import SymbolResolver
from src.ingestion.parser import TreeSitterParser

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# NODE
# ─────────────────────────────────────────────

@dataclass
class CallGraphNode:
    id: str
    function_name: str
    file_path: str

    callers: Set[str] = field(default_factory=set)
    callees: Set[str] = field(default_factory=set)

    is_entry_point: bool = False
    is_infrastructure: bool = False
    is_external: bool = False


ENTRY_POINT_PATTERNS = ["handler", "route", "endpoint", "controller", "main"]


class CallGraphBuilder:

    def __init__(self):
        self.parser = TreeSitterParser()
        self.symbol_resolver = SymbolResolver()

    def _make_id(self, file_path: str, function_name: str) -> str:
        return f"{file_path}::{function_name}"

    def _is_entry_point(self, name: str) -> bool:
        return any(p in name.lower() for p in ENTRY_POINT_PATTERNS)

    def build(self, samples: List[CodeSample]) -> Tuple[Dict[str, CallGraphNode], Dict[str, Set[str]]]:

        graph: Dict[str, CallGraphNode] = {}
        name_index: Dict[str, Set[str]] = {}

        known: Set[str] = set()

        # ─────────────────────────────────────────────
        # 1. NODE CREATION
        # ─────────────────────────────────────────────
        for s in samples:
            if not s.function_name:
                continue

            node_id = self._make_id(s.file_path or "", s.function_name)
            known.add(s.function_name)

            graph[node_id] = CallGraphNode(
                id=node_id,
                function_name=s.function_name,
                file_path=s.file_path or "",
                is_entry_point=self._is_entry_point(s.function_name),
                is_infrastructure=(s.function_name == "execute"),
                is_external=False,
            )

            name_index.setdefault(s.function_name, set()).add(node_id)

        # ─────────────────────────────────────────────
        # 2. EDGE CREATION
        # ─────────────────────────────────────────────
        for s in samples:
            if not s.function_name or not s.ast_node:
                continue

            src_id = self._make_id(s.file_path or "", s.function_name)
            src_node = graph.get(src_id)
            if not src_node:
                continue

            src_bytes = (s.raw_content or s.code).encode("utf-8")

            calls = self.parser.extract_call_names(
                s.ast_node,
                s.language.value,
                src_bytes,
            )

            for c in calls:
                target = self.symbol_resolver.resolve(c)

                # ─────────────────────────────────────
                # external function
                # ─────────────────────────────────────
                if target not in known:
                    ext_id = f"external::{target}"

                    if ext_id not in graph:
                        graph[ext_id] = CallGraphNode(
                            id=ext_id,
                            function_name=target,
                            file_path="external",
                            is_external=True,
                        )

                    src_node.callees.add(ext_id)
                    graph[ext_id].callers.add(src_id)
                    continue

                # ─────────────────────────────────────
                # internal function (multi-target safe)
                # ─────────────────────────────────────
                targets = name_index.get(target, set())

                for tgt_id in targets:
                    src_node.callees.add(tgt_id)
                    graph[tgt_id].callers.add(src_id)

        # convert sets → lists for JSON serialization
        for node in graph.values():
            node.callers = list(node.callers)
            node.callees = list(node.callees)

        name_index_final = {k: list(v) for k, v in name_index.items()}

        return graph, name_index_final