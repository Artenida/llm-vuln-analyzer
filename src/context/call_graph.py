import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

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
    is_taint_source: bool = False   # receives untrusted user input (e.g. HTTP handlers)
    is_taint_sink: bool = False     # passes data to dangerous operations


ENTRY_POINT_PATTERNS = ["handler", "route", "endpoint", "controller", "main"]

INFRASTRUCTURE_PATTERNS = ["execute", "query", "connect", "disconnect"]

# External calls that mark a node as a taint sink
_SINK_EXTERNAL_PATTERNS = [
    "execute", "query", "eval", "exec", "system", "popen",
    "spawn", "shell", "run_command", "subprocess",
    "write_file", "write", "send_response",
]

# Function-name patterns that are always sinks regardless of callees
_SINK_NAME_PATTERNS = [
    "execute", "exec_query", "run_query", "run_command",
    "eval", "shell_exec",
]


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

    def _apply_route_entry_points(
        self,
        graph: Dict[str, "CallGraphNode"],
        route_defs: List,
    ) -> None:
        name_to_nodes: Dict[str, List[str]] = {}
        for node_id, node in graph.items():
            if node.is_external:
                continue
            name_to_nodes.setdefault(node.function_name, []).append(node_id)

        for route in route_defs:
            for h in route.handlers:
                name = h.strip()
                if not name:
                    continue
                # handlers referenced as `object.method` (e.g. billingController.payInvoice)
                # never carry the object prefix on the extracted function itself
                lookup_name = name.split(".")[-1] if "." in name else name
                candidates = name_to_nodes.get(lookup_name, [])

                if len(candidates) == 1:
                    graph[candidates[0]].is_entry_point = True
                elif len(candidates) > 1:
                    preferred = [
                        nid for nid in candidates
                        if any(
                            x in graph[nid].file_path.lower()
                            for x in ("controller", "route", "middleware", "api")
                        )
                    ]
                    if len(preferred) == 1:
                        graph[preferred[0]].is_entry_point = True
                    # else: ambiguous with no clear winner — leave as-is rather
                    # than risk flagging the wrong (e.g. service-layer) function

    def build(
        self,
        samples: List[CodeSample],
        routes: Optional[List] = None,
    ) -> Tuple[Dict[str, "CallGraphNode"], Dict[str, Set[str]]]:
        """
        routes: project-wide RouteDefinition list (e.g. CodeExtractor.all_routes).
        Route files (Express `router.get(...)` wiring) typically have no function
        bodies of their own, so this can't be recovered from `sample.routes` alone
        — falls back to scanning samples for callers that don't pass it explicitly.
        """

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

        # Function names directly registered as Express route handlers — a more
        # precise entry-point signal than name/path guessing, applied once nodes
        # (and therefore name collisions across files) are known. A route name
        # that matches more than one function (e.g. a controller and the service
        # it delegates to sharing a name) is only resolved if exactly one
        # candidate also matches the existing path heuristic — otherwise it's
        # left alone rather than risk marking the wrong one.
        route_defs = routes if routes is not None else [
            r for s in samples for r in s.routes
        ]
        self._apply_route_entry_points(graph, route_defs)

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
                # Import-aware resolution via SymbolResolver
                # Handles: authService.registerUser when imports exist
                # ─────────────────────────────────────
                if resolved_name is None and "." in c and s.imports:
                    sr_candidates = self.symbol_resolver.resolve_candidates(
                        s, c, samples
                    )
                    for tgt_id in sr_candidates:
                        if tgt_id in graph:
                            src_node.callees.add(tgt_id)
                            graph[tgt_id].callers.add(src_id)
                    if sr_candidates:
                        continue  # wired directly; skip LLM fallback

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
        # 3. TAINT PROPAGATION
        # ─────────────────────────────────────────────
        for node_id, node in graph.items():
            if node.is_external:
                continue

            # entry points receive user-controlled data → taint sources
            if node.is_entry_point:
                node.is_taint_source = True

            # function-name based sink detection
            if any(p in node.function_name.lower() for p in _SINK_NAME_PATTERNS):
                node.is_taint_sink = True

            # sink detection via external callees: e.g. fakeDb.execute(...)
            for callee_id in node.callees:
                if callee_id.startswith("external::"):
                    raw_name = callee_id.replace("external::", "")
                    leaf = raw_name.split(".")[-1].lower()
                    if any(p in leaf for p in _SINK_EXTERNAL_PATTERNS):
                        node.is_taint_sink = True
                        break

        # ─────────────────────────────────────────────
        # 4. JSON SERIALIZATION FIX
        # ─────────────────────────────────────────────
        for node in graph.values():

            node.callers = sorted(list(node.callers))
            node.callees = sorted(list(node.callees))

        name_index_final = {k: sorted(list(v)) for k, v in name_index.items()}

        return graph, name_index_final


def nodes_to_dict(graph: Dict[str, "CallGraphNode"]) -> Dict[str, dict]:
    """
    Converts the Dict[str, CallGraphNode] returned by CallGraphBuilder.build()
    into the plain Dict[str, dict] format consumed by export_dot / export_html.
    """
    result = {}
    for node_id, node in graph.items():
        result[node_id] = {
            "function_name":     node.function_name,
            "file_path":         node.file_path,
            "callers":           list(node.callers),
            "callees":           list(node.callees),
            "is_entry_point":    node.is_entry_point,
            "is_infrastructure": node.is_infrastructure,
            "is_external":       node.is_external,
            "is_taint_source":   node.is_taint_source,
            "is_taint_sink":     node.is_taint_sink,
        }
    return result
