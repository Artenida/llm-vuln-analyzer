import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from src.models import CodeSample
from src.context.symbol_resolver import SymbolResolver
from src.context.llm_edge_resolver import LLMEdgeResolver
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

INFRASTRUCTURE_PATTERNS = ["execute", "query", "connect", "disconnect"]


class CallGraphBuilder:

    def __init__(self, api_key: str = None, model: str = "o4-mini"):
        self.parser = TreeSitterParser()
        self.symbol_resolver = SymbolResolver()
        self.llm_resolver = LLMEdgeResolver(api_key, model=model) if api_key else None

    def _make_id(self, file_path: str, function_name: str) -> str:
        return f"{file_path}::{function_name}"

    def _is_entry_point(
        self,
        function_name: str,
        file_path: str,
    ) -> bool:

        path = file_path.lower()

        if any(
            x in path
            for x in [
                "controller",
                "route",
                "middleware",
                "api",
            ]
        ):
            return True

        return any(p in function_name.lower() for p in ENTRY_POINT_PATTERNS)

    def build(
        self, samples: List[CodeSample]
    ) -> Tuple[Dict[str, CallGraphNode], Dict[str, Set[str]]]:

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
                is_entry_point=self._is_entry_point(
                    s.function_name,
                    s.file_path or "",
                ),
                is_infrastructure=any(
                    p in s.function_name.lower() for p in INFRASTRUCTURE_PATTERNS
                ),
                is_external=False,
            )

            name_index.setdefault(s.function_name, set()).add(node_id)

        # ─────────────────────────────────────────────
        # 2. EDGE CREATION
        # ─────────────────────────────────────────────
        for s in samples:

            if not s.function_name or not s.ast_node:
                if s.function_name:
                    logger.debug(
                        "Skipping edge extraction for %s — no AST node",
                        s.function_name,
                    )
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

                # ─────────────────────────────────────
                # Static resolution
                # authService.registerUser -> registerUser
                # fakeDb.execute -> execute
                # ─────────────────────────────────────
                simple_target = c.split(".")[-1] if "." in c else c
                target = c

                resolved_name = None

                if target in known:
                    resolved_name = target

                elif simple_target in known:
                    resolved_name = simple_target

                # ─────────────────────────────────────
                # HYBRID: AI fallback when static fails
                # ─────────────────────────────────────
                if resolved_name is None and self.llm_resolver and known:
                    try:
                        result = self.llm_resolver.resolve(
                            caller=src_id,
                            raw_call=c,
                            caller_code=s.code,
                            candidates=list(known),
                        )
                        ai_target = result.get("target")
                        if ai_target and ai_target in known:
                            resolved_name = ai_target
                            logger.debug(
                                "AI resolved %r -> %r (caller: %s)",
                                c,
                                ai_target,
                                src_id,
                            )
                    except Exception as e:
                        logger.debug("AI edge resolution failed for %r: %s", c, e)

                # ─────────────────────────────────────
                # External node — truly unresolved
                # ─────────────────────────────────────
                if resolved_name is None:

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
                # Internal function — wire the edge
                # ─────────────────────────────────────
                targets = name_index.get(resolved_name, set())

                for tgt_id in targets:

                    if tgt_id == src_id:
                        continue

                    src_node.callees.add(tgt_id)
                    graph[tgt_id].callers.add(src_id)

        # ─────────────────────────────────────────────
        # 3. JSON SERIALIZATION FIX
        # ─────────────────────────────────────────────
        for node in graph.values():

            node.callers = sorted(list(node.callers))
            node.callees = sorted(list(node.callees))

        name_index_final = {k: sorted(list(v)) for k, v in name_index.items()}

        return graph, name_index_final