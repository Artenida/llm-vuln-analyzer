import logging
from collections import defaultdict

from src.models import CodeSample
from src.context.symbol_resolver import SymbolResolver
from src.ingestion.parser import TreeSitterParser
from dataclasses import dataclass, field


logger = logging.getLogger(__name__)


@dataclass
class CallGraphNode:
    function_name: str
    file_path: str

    callers: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)

    is_entry_point: bool = False


ENTRY_POINT_PATTERNS = ["handler", "route", "endpoint", "controller", "main"]


class CallGraphBuilder:
    def __init__(self):
        self.parser = TreeSitterParser()
        self.symbol_resolver = SymbolResolver()

    def build(self, samples: list[CodeSample]) -> dict[str, CallGraphNode]:
        graph: dict[str, CallGraphNode] = {}

        known = {s.function_name for s in samples if s.function_name}

        # nodes
        for s in samples:
            if not s.function_name:
                continue

            graph[s.function_name] = CallGraphNode(
                function_name=s.function_name,
                file_path=s.file_path or "",
                is_entry_point=self._is_entry_point(s.function_name),
            )

        # edges
        for s in samples:
            if not s.function_name or not s.ast_node:
                continue

            src_bytes = (s.raw_content or s.code).encode("utf-8")

            calls = self.parser.extract_call_names(
                s.ast_node,
                s.language.value,
                src_bytes,
            )

            resolved = []
            for c in calls:
                r = self.symbol_resolver.resolve(c)
                if r in known:
                    resolved.append(r)

            node = graph[s.function_name]
            node.callees = sorted(set(resolved))

            for callee in node.callees:
                graph[callee].callers.append(s.function_name)

        return graph

    def _is_entry_point(self, name: str) -> bool:
        return any(p in name.lower() for p in ENTRY_POINT_PATTERNS)