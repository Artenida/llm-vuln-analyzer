"""
Call graph builder.
"""

import logging

from src.models import CodeSample
from src.context.models import CallGraphNode
from src.context.symbol_resolver import SymbolResolver
from src.ingestion.parser import TreeSitterParser

logger = logging.getLogger(__name__)


ENTRY_POINT_PATTERNS = [
    "handler",
    "route",
    "endpoint",
    "controller",
    "view",
    "main",
]


class CallGraphBuilder:

    def __init__(self):

        self.parser = TreeSitterParser()

        self.symbol_resolver = SymbolResolver()

    def build(self,
              samples: list[CodeSample]) -> dict[str, CallGraphNode]:

        graph: dict[str, CallGraphNode] = {}

        known_functions = {
            sample.function_name
            for sample in samples
            if sample.function_name
        }

        # Create nodes first
        for sample in samples:

            if not sample.function_name:
                continue

            graph[sample.function_name] = CallGraphNode(
                function_name=sample.function_name,
                file_path=sample.file_path or "",

                is_entry_point=self._is_entry_point(
                    sample.function_name
                ),
            )

        # Build edges
        for sample in samples:

            if not sample.function_name:
                continue

            if sample.ast_node is None:
                continue

            source_bytes = (
                sample.raw_content or sample.code
            ).encode("utf-8")

            raw_calls = self.parser.extract_call_names(
                sample.ast_node,
                sample.language.value,
                source_bytes,
            )

            resolved_calls = []

            for raw in raw_calls:

                resolved = self.symbol_resolver.resolve(raw)

                if resolved in known_functions:
                    resolved_calls.append(resolved)

            node = graph[sample.function_name]

            node.callees = sorted(set(resolved_calls))

            for callee in node.callees:

                if callee in graph:
                    graph[callee].callers.append(
                        sample.function_name
                    )

        return graph

    def _is_entry_point(self,
                        function_name: str) -> bool:

        lowered = function_name.lower()

        return any(
            pattern in lowered
            for pattern in ENTRY_POINT_PATTERNS
        )

    def debug_print(self,
                    graph: dict[str, CallGraphNode]):

        for name, node in graph.items():

            logger.info(
                "%s -> callees=%s callers=%s",
                name,
                node.callees,
                node.callers,
            )